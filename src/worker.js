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
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return b64urlEncode(new Uint8Array(sig));
}

async function hmacVerify(secret, data, signatureB64Url) {
  const expected = await hmacSign(secret, data);
  return expected === signatureB64Url;
}

// session token: base64url(payload).base64url(sig)
// payload: JSON {"uid":"...","exp":...}
async function makeToken(env, uid, maxAgeSeconds = 60 * 60 * 24 * 30) {
  const exp = Math.floor(Date.now() / 1000) + maxAgeSeconds;
  const payload = JSON.stringify({ uid, exp });
  const payloadB64 = b64urlEncode(encoder.encode(payload));
  const sig = await hmacSign(env.AUTH_SECRET, payloadB64);
  return `${payloadB64}.${sig}`;
}

async function readToken(env, req) {
  if (!env.AUTH_SECRET) return null;
  const cookie = req.headers.get("Cookie") || "";
  const m = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (!m) return null;
  const token = m[1];

  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;

  const ok = await hmacVerify(env.AUTH_SECRET, payloadB64, sigB64);
  if (!ok) return null;

  let payload;
  try {
    payload = JSON.parse(decoder.decode(b64urlDecodeToBytes(payloadB64)));
  } catch {
    return null;
  }
  if (!payload?.uid || !payload?.exp) return null;
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload.uid;
}

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
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
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function verifyPassword(stored, password) {
  // stored: pbkdf2$iter$saltB64$hashB64
  try {
    const [scheme, iterStr, saltB64, hashB64] = stored.split("$");
    if (scheme !== "pbkdf2") return false;
    const iterations = parseInt(iterStr, 10);
    if (!iterations) return false;

    const salt = b64urlDecodeToBytes(saltB64);
    const hash = b64urlDecodeToBytes(hashB64);

    const got = await pbkdf2Hash(password, salt, iterations);
    if (got.length !== hash.length) return false;

    // constant-time compare
    let diff = 0;
    for (let i = 0; i < got.length; i++) diff |= got[i] ^ hash[i];
    return diff === 0;
  } catch {
    return false;
  }
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
    if (path === "/settings") {
      return Response.redirect(new URL("/settings.html", url.origin).toString(), 302);
    }

    // 1) Who am I
    if (path === "/api/me" && req.method === "GET") {
      const uid = await readToken(env, req);
      return json({ loggedIn: !!uid, uid: uid || null });
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

      if (!user) return json({ error: "bad_credentials" }, 401);

      const ok = await verifyPassword(user.password_hash, body.password);
      if (!ok) return json({ error: "bad_credentials" }, 401);

      const token = await makeToken(env, String(user.id));
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

    // 4b) Profile API (pro Profil getrennt, aber unter demselben Login-Account)
    // GET  /api/profiles              -> Liste {profiles:[{id,name,updatedAt}]}
    // POST /api/profiles {name}       -> erstellt Profil, legt Seed-Daten an
    // GET  /api/profiles/:id          -> Profil-Daten
    // PUT  /api/profiles/:id          -> Profil-Daten speichern
    // DELETE /api/profiles/:id        -> Profil + Daten löschen

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
            updatedAt: r.updated_at,
          })),
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
        const row = await env.DB.prepare(
          "SELECT json FROM profile_data WHERE owner_id = ? AND profile_id = ?"
        ).bind(uid, profileId).first();

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
          .bind(uid, profileId).run();
        await env.DB.prepare("DELETE FROM profiles WHERE owner_id = ? AND profile_id = ?")
          .bind(uid, profileId).run();
        return json({ ok: true });
      }

      return json({ error: "method" }, 405);
    }

    // 4) Daten holen/speichern (Legacy: ein JSON pro Login) – bleibt drin, falls du es noch nutzt
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

    // 2) Login-Seite darf jeder sehen
    if (path === "/login" || path === "/login.html") {
      return env.ASSETS.fetch(req);
    }

    // 3) ✅ DAS ist das "Gate": alles andere nur, wenn eingeloggt
    const uid = await readToken(env, req);
    if (!uid) {
      const loginUrl = new URL("/login", url.origin);
      loginUrl.searchParams.set("returnTo", path + url.search);
      return Response.redirect(loginUrl.toString(), 302);
    }

    // 4) Eingeloggt → Client-side Routing unterstützen:
    // /packliste/<profilId> und /packliste/<profilId>/<listId> sollen packliste.html laden
    if (path.startsWith("/packliste/")) {
      const newUrl = new URL("/packliste.html", url.origin);
      const req2 = new Request(newUrl.toString(), req);
      return env.ASSETS.fetch(req2);
    }

    // 4) Eingeloggt → normale Dateien ausliefern (egal welche Seite)
    return env.ASSETS.fetch(req);
  },
};
