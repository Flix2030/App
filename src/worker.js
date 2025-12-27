// src/worker.js

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64urlEncode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecodeToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacSign(secret, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", key, dataBytes);
}

async function hmacVerify(secret, dataBytes, sigBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify("HMAC", key, sigBytes, dataBytes);
}

function parseCookies(req) {
  const h = req.headers.get("Cookie") || "";
  const out = {};
  h.split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function json(res, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(res), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

// Passwort: PBKDF2 (Worker-seitig), gespeichert als: pbkdf2$iter$saltB64$hashB64
async function pbkdf2Hash(password, saltBytes, iterations = 150000) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

function timingSafeEq(a, b) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}

async function makePassRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;
  const hash = await pbkdf2Hash(password, salt, iterations);
  // Format: pbkdf2$ITER$SALT$HASH
  return `pbkdf2$${iterations}$${b64urlEncode(salt)}$${b64urlEncode(hash)}`;
}

async function verifyPass(password, record) {
  const parts = record.split("$");
  // erwartet: ["pbkdf2", "100000", "<salt>", "<hash>"]
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

  const iter = parseInt(parts[1], 10);
  if (!Number.isFinite(iter) || iter < 1 || iter > 100000) return false;

  const salt = b64urlDecodeToBytes(parts[2]);
  const expected = b64urlDecodeToBytes(parts[3]);

  const got = await pbkdf2Hash(password, salt, iter);
  return timingSafeEq(got, expected);
}

// Cookie Token: header.payload.sig (HMAC SHA-256)
async function makeToken(env, userId) {
  if (!env.AUTH_SECRET) throw new Error("AUTH_SECRET not set");
  const header = b64urlEncode(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30; // 30 Tage
  const payload = b64urlEncode(encoder.encode(JSON.stringify({ u: userId, exp })));
  const data = `${header}.${payload}`;
  const sig = b64urlEncode(await hmacSign(env.AUTH_SECRET, encoder.encode(data)));
  return `${data}.${sig}`;
}

async function readToken(env, req) {
  if (!env.AUTH_SECRET) return null;
  const cookies = parseCookies(req);
  const t = cookies["session"];
  if (!t) return null;
  const parts = t.split(".");
  if (parts.length !== 3) return null;

  const data = `${parts[0]}.${parts[1]}`;
  const sig = b64urlDecodeToBytes(parts[2]);

  const ok = await hmacVerify(env.AUTH_SECRET, encoder.encode(data), sig);
  if (!ok) return null;

  const payload = JSON.parse(decoder.decode(b64urlDecodeToBytes(parts[1])));
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload.u;
}

async function handleApi(req, env) {
  // WICHTIG: Alles im Try/Catch, damit du NIE wieder HTML-Fehler bekommst, sondern JSON
  try {
    const url = new URL(req.url);
    const path = url.pathname;

    // /home und /packliste ohne .html auf die echte Datei mappen
    if (path === "/home") {
      return Response.redirect(new URL("/home.html", url.origin).toString(), 302);
    }
    if (path === "/packliste") {
      return Response.redirect(new URL("/packliste.html", url.origin).toString(), 302);
    }
    if (path === "/vokabeln") {
      return Response.redirect(new URL("/vokabeln.html", url.origin).toString(), 302);
    }

    // Health / Debug
    if (path === "/api/health" && req.method === "GET") {
      return json({
        ok: true,
        hasAuthSecret: !!env.AUTH_SECRET,
        hasDB: !!env.DB,
        time: new Date().toISOString(),
      });
    }

    // 1) Einmaliger Register-Endpoint: nur wenn noch KEIN User existiert
    if (path === "/api/register" && req.method === "POST") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const body = await req.json().catch(() => null);
      if (!body?.username || !body?.password) return json({ error: "missing" }, 400);

      const exists = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
      if ((exists?.c || 0) > 0) return json({ error: "disabled" }, 403);

      const pass = await makePassRecord(body.password);

      await env.DB.prepare(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)"
      )
        .bind(body.username, pass, new Date().toISOString())
        .run();

      return json({ ok: true });
    }

    // 2) Login
    if (path === "/api/login" && req.method === "POST") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);
      if (!env.AUTH_SECRET) return json({ error: "AUTH_SECRET not set" }, 500);

      const body = await req.json().catch(() => null);
      if (!body?.username || !body?.password) return json({ error: "missing" }, 400);

      const user = await env.DB.prepare(
        "SELECT id, password_hash FROM users WHERE username = ?"
      )
        .bind(body.username)
        .first();

      if (!user) return json({ error: "invalid" }, 401);

      const ok = await verifyPass(body.password, user.password_hash);
      if (!ok) return json({ error: "invalid" }, 401);

      const token = await makeToken(env, user.id);

      return json(
        { ok: true },
        200,
        {
          "Set-Cookie": `session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${
            60 * 60 * 24 * 30
          }`,
        }
      );
    }

    // 3) Logout
    if (path === "/api/logout" && req.method === "POST") {
      return json(
        { ok: true },
        200,
        { "Set-Cookie": "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" }
      );
    }

    // 4) Me
    if (path === "/api/me" && req.method === "GET") {
      const uid = await readToken(env, req);
      if (!uid) return json({ loggedIn: false }, 401);
      return json({ loggedIn: true, userId: uid });
    }

    // 5) Daten GET/PUT (gesamter App-State als JSON)
    
    // 4b) Profile API (pro Profil getrennt, aber unter demselben Login-Account)
    if (path === "/api/profiles") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);

      if (req.method === "GET") {
        const rows = await env.DB
          .prepare("SELECT profile_id, name, updated_at FROM profiles WHERE owner_id = ? ORDER BY updated_at DESC")
          .bind(uid)
          .all();

        return json({
          ok: true,
          profiles: (rows?.results || []).map(r => ({
            id: r.profile_id,
            name: r.name,
            updatedAt: r.updated_at
          }))
        });
      }

      if (req.method === "POST") {
        const body = await req.json().catch(() => null);
        const name = String(body?.name || "").trim();
        if (!name) return json({ error: "missing_name" }, 400);

        const profileId = "p_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
        const now = new Date().toISOString();

        await env.DB.prepare(
          "INSERT INTO profiles (owner_id, profile_id, name, updated_at) VALUES (?, ?, ?, ?)"
        ).bind(uid, profileId, name, now).run();

        const seed = { id: profileId, name, lists: [] };
        await env.DB.prepare(
          "INSERT INTO profile_data (owner_id, profile_id, json, updated_at) VALUES (?, ?, ?, ?)"
        ).bind(uid, profileId, JSON.stringify(seed), now).run();

        return json({ ok: true, id: profileId });
      }

      return json({ error: "method" }, 405);
    }

    if (path.startsWith("/api/profiles/")) {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);

      const profileId = decodeURIComponent(path.slice("/api/profiles/".length) || "").trim();
      if (!profileId) return json({ error: "missing_id" }, 400);

      if (req.method === "GET") {
        const row = await env.DB
          .prepare("SELECT json FROM profile_data WHERE owner_id = ? AND profile_id = ?")
          .bind(uid, profileId)
          .first();

        return json({ ok: true, data: row?.json ? JSON.parse(row.json) : null });
      }

      if (req.method === "PUT") {
        const body = await req.json().catch(() => null);
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

        const now = new Date().toISOString();

        await env.DB.prepare(
          "INSERT INTO profile_data (owner_id, profile_id, json, updated_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(owner_id, profile_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, profileId, JSON.stringify(body), now).run();

        const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : null;
        if (name) {
          await env.DB.prepare(
            "UPDATE profiles SET name = ?, updated_at = ? WHERE owner_id = ? AND profile_id = ?"
          ).bind(name, now, uid, profileId).run();
        } else {
          await env.DB.prepare(
            "UPDATE profiles SET updated_at = ? WHERE owner_id = ? AND profile_id = ?"
          ).bind(now, uid, profileId).run();
        }

        return json({ ok: true });
      }

      if (req.method === "DELETE") {
        await env.DB.prepare("DELETE FROM profile_data WHERE owner_id = ? AND profile_id = ?")
          .bind(uid, profileId)
          .run();
        await env.DB.prepare("DELETE FROM profiles WHERE owner_id = ? AND profile_id = ?")
          .bind(uid, profileId)
          .run();

        return json({ ok: true });
      }

      return json({ error: "method" }, 405);
    }

if (path === "/api/data") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);

      if (req.method === "GET") {
        const row = await env.DB.prepare("SELECT json FROM user_data WHERE user_id = ?")
          .bind(uid)
          .first();
        return json({ ok: true, data: row?.json ? JSON.parse(row.json) : null });
      }

      if (req.method === "PUT") {
        const body = await req.json().catch(() => null);
        if (!body) return json({ error: "bad_json" }, 400);

        const now = new Date().toISOString();
        await env.DB.prepare(
          "INSERT INTO user_data (user_id, json, updated_at) VALUES (?, ?, ?) " +
            "ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        )
          .bind(uid, JSON.stringify(body), now)
          .run();

        return json({ ok: true });
      }

      return json({ error: "method" }, 405);
    }

    return json({ error: "not_found", path }, 404);
  } catch (e) {
    // Hier kommt bei CRASH immer JSON raus:
    return json(
      {
        error: "worker_crash",
        message: String(e?.message || e),
        stack: String(e?.stack || ""),
      },
      500
    );
  }
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;

    // 0) Pretty-URLs auf echte Dateien mappen (optional, aber praktisch)
    if (path === "/home") return Response.redirect(new URL("/home.html", url.origin).toString(), 302);
    if (path === "/packliste") return Response.redirect(new URL("/packliste.html", url.origin).toString(), 302);
    if (path === "/vokabeln") return Response.redirect(new URL("/vokabeln.html", url.origin).toString(), 302);
    if (path === "/settings") return Response.redirect(new URL("/settings.html", url.origin).toString(), 302);

    // 1) API darf NIE umgeleitet werden (sonst kaputt)
    if (path.startsWith("/api/")) {
      return handleApi(req, env);
    }

    // 2) Login ist die EINZIGE öffentliche Seite
    if (path === "/login") {
      return env.ASSETS.fetch(new Request(url.origin + "/login.html", req));
    }

    // 3) ✅ DAS ist das "Gate": alles andere nur, wenn eingeloggt
    const uid = await readToken(env, req);
    if (!uid) {
      const loginUrl = new URL("/login", url.origin);
      loginUrl.searchParams.set("returnTo", path + url.search);
      return Response.redirect(loginUrl.toString(), 302);
    }

    // 4) Eingeloggt → normale Dateien ausliefern (egal welche Seite)
    
    // Client-side Routing: /packliste/<profil>/<liste> soll trotzdem packliste.html laden
    if (path.startsWith("/packliste/")) {
      const newUrl = new URL("/packliste.html", url.origin);
      const req2 = new Request(newUrl.toString(), req);
      return env.ASSETS.fetch(req2);
    }

return env.ASSETS.fetch(req);
  },
};
