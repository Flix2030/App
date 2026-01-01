// src/worker.js

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function makeId(prefix="id") {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  const s = Array.from(bytes).map(b => b.toString(16).padStart(2,"0")).join("");
  return `${prefix}_${s.slice(0,16)}`;
}


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

async function sha256B64Url(inputStr) {
  const buf = await crypto.subtle.digest("SHA-256", encoder.encode(inputStr));
  return b64urlEncode(new Uint8Array(buf));
}

// Confirm-Token: HMAC über JSON-Payload (kurzlebig) – verhindert "aus Versehen" destruktive Saves
async function makeConfirmToken(env, payloadObj) {
  if (!env.AUTH_SECRET) throw new Error("AUTH_SECRET not set");
  const payloadStr = JSON.stringify(payloadObj);
  const sig = b64urlEncode(await hmacSign(env.AUTH_SECRET, encoder.encode(payloadStr)));
  return `${b64urlEncode(encoder.encode(payloadStr))}.${sig}`;
}

async function readConfirmToken(env, token) {
  if (!env.AUTH_SECRET) return null;
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const payloadStr = decoder.decode(b64urlDecodeToBytes(parts[0]));
  const sigBytes = b64urlDecodeToBytes(parts[1]);
  const ok = await hmacVerify(env.AUTH_SECRET, encoder.encode(payloadStr), sigBytes);
  if (!ok) return null;
  const obj = JSON.parse(payloadStr);
  if (!obj?.exp || obj.exp < Math.floor(Date.now() / 1000)) return null;
  return obj;
}

function countItems(profileJson) {
  const lists = Array.isArray(profileJson?.lists) ? profileJson.lists : [];
  let items = 0;
  for (const l of lists) {
    const its = Array.isArray(l?.items) ? l.items : [];
    items += its.length;
  }
  return { lists: lists.length, items };
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
    if (path === "/einkaufsliste") {
      return env.ASSETS.fetch(new Request(url.origin + "/einkaufsliste.html", req));
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
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

        const name = String(body?.name || "").trim() || "Benutzer";
        const now = new Date().toISOString();
        const nowSec = Math.floor(Date.now() / 1000);

        // Alte Version laden (für Safety-Checks)
        const existingRow = await env.DB.prepare(
          "SELECT json FROM profile_data WHERE owner_id = ? AND profile_id = ?"
        ).bind(uid, profileId).first();

        const oldData = existingRow?.json ? JSON.parse(existingRow.json) : null;

        // Destruktive Änderungen erkennen (Listen/Items plötzlich weniger)
        const oldCounts = countItems(oldData);
        const newCounts = countItems(body);

        const listsDeleted = Math.max(0, (oldCounts.lists || 0) - (newCounts.lists || 0));
        const itemsDeleted = Math.max(0, (oldCounts.items || 0) - (newCounts.items || 0));

        const destructive =
          (listsDeleted >= 1) ||
          (itemsDeleted >= 20);

        // Force/Confirm prüfen
        const force = body?._force === true;
        const confirmToken = body?._confirm;

        // Body ohne Force-Felder hashen, damit Token an GENAU dieses Update gebunden ist
        const bodyForHash = { ...body };
        delete bodyForHash._force;
        delete bodyForHash._confirm;
        const bodyHash = await sha256B64Url(JSON.stringify(bodyForHash));

        if (destructive && !force) {
          const reasons = [];
          if (listsDeleted >= 1) reasons.push(`${listsDeleted} Liste(n) würden gelöscht/verschwinden`);
          if (itemsDeleted >= 20) reasons.push(`${itemsDeleted} Item(s) würden gelöscht/verschwinden`);
          const reason = reasons.join(" · ") || "Große Löschung erkannt";

          const token = await makeConfirmToken(env, {
            uid,
            profileId,
            bodyHash,
            exp: nowSec + 60, // 60 Sekunden gültig
          });

          return json(
            {
              ok: false,
              needsConfirm: true,
              reason,
              listsDeleted,
              itemsDeleted,
              confirmToken: token,
            },
            409
          );
        }

        if (destructive && force) {
          const tok = await readConfirmToken(env, confirmToken);
          if (!tok || tok.uid !== uid || tok.profileId !== profileId || tok.bodyHash !== bodyHash) {
            return json(
              {
                ok: false,
                error: "confirm_failed",
                message: "Bestätigung ungültig oder abgelaufen.",
              },
              409
            );
          }
        }

        // ensure meta exists + update name
        await env.DB.prepare(
          "INSERT INTO profiles (owner_id, profile_id, name, updated_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(owner_id, profile_id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at"
        ).bind(uid, profileId, name, now).run();

        await env.DB.prepare(
          "INSERT INTO profile_data (owner_id, profile_id, json, updated_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(owner_id, profile_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, profileId, JSON.stringify(bodyForHash), now).run();

        return json({ ok: true });
      }

      if (req.method === "DELETE") {
        // Safety: Profil-Löschung immer bestätigen lassen (damit nichts "aus Versehen" weg ist)
        const url = new URL(req.url);
        const force = url.searchParams.get("force") === "1";
        const confirm = url.searchParams.get("confirm") || "";
        const nowSec = Math.floor(Date.now() / 1000);

        if (!force) {
          const token = await makeConfirmToken(env, {
            uid,
            profileId,
            bodyHash: "DELETE",
            exp: nowSec + 60,
          });
          return json(
            {
              ok: false,
              needsConfirm: true,
              reason: "Dieses Profil würde gelöscht werden.",
              confirmToken: token,
            },
            409
          );
        } else {
          const tok = await readConfirmToken(env, confirm);
          if (!tok || tok.uid !== uid || tok.profileId !== profileId || tok.bodyHash !== "DELETE") {
            return json(
              {
                ok: false,
                error: "confirm_failed",
                message: "Bestätigung ungültig oder abgelaufen.",
              },
              409
            );
          }
        }

        await env.DB.prepare("DELETE FROM profile_data WHERE owner_id = ? AND profile_id = ?").bind(uid, profileId).run();
        await env.DB.prepare("DELETE FROM profiles WHERE owner_id = ? AND profile_id = ?").bind(uid, profileId).run();
        return json({ ok: true });
      }

      return json({ error: "method" }, 405);
    }
    // ===== /Profiles API =====

    // 6) AI (Gemini) – Key bleibt im Worker (Secret: GEMINI_API_KEY)
if (path === "/api/ai" && req.method === "POST") {
  const uid = await readToken(env, req);
  if (!uid) return json({ error: "unauthorized" }, 401);

  if (!env.GEMINI_API_KEY) return json({ error: "GEMINI_API_KEY_missing" }, 500);

  const body = await req.json().catch(() => null);
  const prompt = String(body?.prompt || "").trim();
  if (!prompt) return json({ error: "prompt_required" }, 400);

  const url =
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" +
    encodeURIComponent(env.GEMINI_API_KEY);

  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
    }),
  });

  const j = await r.json().catch(() => null);
  if (!r.ok) return json({ error: "gemini_error", status: r.status, details: j }, 502);

  const text =
    j?.candidates?.[0]?.content?.parts?.map((p) => p?.text).filter(Boolean).join("\n") || "";

  return json({ ok: true, text });
}
// ===== Einkaufsliste API =====
if (path.startsWith("/api/einkauf/")) {
  if (!env.DB) return json({ error: "DB not bound" }, 500);

  const uid = await readToken(env, req);
  if (!uid) return json({ error: "unauthorized" }, 401);

  // GET /api/einkauf/data  -> komplette Einkaufsliste als JSON (nur Cloudflare)
  if (path === "/api/einkauf/data" && req.method === "GET") {
    const row = await env.DB.prepare(
      "SELECT json FROM einkauf_data WHERE user_id = ?"
    ).bind(uid).first();

    return json({ ok: true, data: row?.json ? JSON.parse(row.json) : { lists: [] } });
  }

  // PUT /api/einkauf/data -> komplette Einkaufsliste speichern
  if (path === "/api/einkauf/data" && req.method === "PUT") {
    const body = await req.json().catch(() => null);
    if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

    const now = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO einkauf_data (user_id, json, updated_at) VALUES (?, ?, ?) " +
      "ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
    ).bind(uid, JSON.stringify(body), now).run();

    return json({ ok: true });
  }

  return json({ error: "not_found", path }, 404);
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
    try {
      const url = new URL(req.url);
      const path = url.pathname;

      // 0) Pretty-URLs auf echte Dateien mappen
      if (path === "/home") return Response.redirect(new URL("/home.html", url.origin).toString(), 302);
      if (path === "/packliste") return env.ASSETS.fetch(new Request(url.origin + "/packliste.html", req));
      if (path === "/vokabeln") return Response.redirect(new URL("/vokabeln.html", url.origin).toString(), 302);
      if (path === "/settings") return Response.redirect(new URL("/settings.html", url.origin).toString(), 302);

      // SPA-Routen: /packliste/<user>/<liste> soll trotzdem packliste.html liefern (URL bleibt stehen)
      if (path.startsWith("/packliste/")) {
        return env.ASSETS.fetch(new Request(url.origin + "/packliste.html", req));
      }
      if (path.startsWith("/einkaufsliste/")) {
        return env.ASSETS.fetch(new Request(url.origin + "/einkaufsliste.html", req));
      }

      // 1) API darf NIE umgeleitet werden (sonst kaputt)
      if (path.startsWith("/api/")) {
        return handleApi(req, env);
      }

      // 2) Login ist die EINZIGE öffentliche Seite
      if (path === "/login") {
        return env.ASSETS.fetch(new Request(url.origin + "/login.html", req));
      }

      // 3) Gate: alles andere nur, wenn eingeloggt
      const uid = await readToken(env, req);
      if (!uid) {
        const loginUrl = new URL("/login", url.origin);
        loginUrl.searchParams.set("returnTo", path + url.search);
        return Response.redirect(loginUrl.toString(), 302);
      }

      // 4) Eingeloggt → normale Dateien ausliefern (404 -> zurück zu Home mit Meldung)
      const res = await env.ASSETS.fetch(req);
      if (res.status === 404) {
        const target = new URL("/home", url.origin);
        target.searchParams.set("msg", "loadfail");
        return Response.redirect(target.toString(), 302);
      }
      return res;

    } catch (err) {
      // ✅ NIE 1101-Screen: immer kontrollierte Antwort
      const url = new URL(req.url);
      const path = url.pathname;

      // API: JSON-Fehler statt Redirect
      if (path.startsWith("/api/")) {
        return new Response(JSON.stringify({
          ok: false,
          error: "worker_exception",
          message: String(err && err.message ? err.message : err),
        }), {
          status: 500,
          headers: { "content-type": "application/json; charset=utf-8" }
        });
      }

      // HTML/Seitenaufruf: zurück zu Home + Flag für Meldung
      // Loop verhindern
      if (path === "/home" || path === "/" || path === "/home.html") {
        return new Response("Fehler im Worker. Bitte Workers Logs prüfen.", { status: 500 });
      }

      const target = new URL("/home.html", url.origin);
      target.searchParams.set("msg", "loadfail");
      return Response.redirect(target.toString(), 302);
    }
  },
};
