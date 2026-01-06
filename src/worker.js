// worker.js (vollständig) — FIXED (Groq Debug + besseres Error-Logging + profileId fix)

import { buildPushHTTPRequest } from "@pushforge/builder";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const BUILD_ID = "FIXED2_20260106160916";

import { handleWebcamLive, LOBBY as LOBBY_DO, STREAM as STREAM_DO } from "./webcam.js";

function withNoStore(resp) {
  try {
    const h = new Headers(resp.headers);
    h.set("cache-control", "no-store");
    h.set("pragma", "no-cache");
    h.set("expires", "0");
    h.set("x-build-id", BUILD_ID);
    return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
  } catch (e) {
    return resp;
  }
}

// wrangler will die Klassen im entrypoint sehen:

export class SIGNAL {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  async fetch() {
    // Legacy Durable Object (wird aktuell nicht genutzt)
    return new Response("SIGNAL: not implemented", { status: 404 });
  }
}

export class LOBBY extends LOBBY_DO {}
export class STREAM extends STREAM_DO {}

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


function extractLatLngFromString(s) {
  const text = String(s || "");

  // @lat,lng (Google Maps)
  let m = text.match(/@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)/);
  if (m) return { lat: +m[1], lng: +m[2] };

  // q=lat,lng or ll=lat,lng or query=lat,lng
  m = text.match(/[?&](?:q|query|ll)=(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)/);
  if (m) return { lat: +m[1], lng: +m[2] };

  // !3dLAT!4dLNG (pb= links)
  m = text.match(/!3d(-?\d+(?:\.\d+)?)!4d(-?\d+(?:\.\d+)?)/);
  if (m) return { lat: +m[1], lng: +m[2] };

  // plain "lat,lng" somewhere
  m = text.match(/(-?\d{1,2}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)/);
  if (m) return { lat: +m[1], lng: +m[2] };

  return null;
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
  return `pbkdf2$${iterations}$${b64urlEncode(salt)}$${b64urlEncode(hash)}`;
}

async function verifyPass(password, record) {
  const parts = record.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

  const iter = parseInt(parts[1], 10);
  if (!Number.isFinite(iter) || iter < 1 || iter > 200000) return false;

  const salt = b64urlDecodeToBytes(parts[2]);
  const expected = b64urlDecodeToBytes(parts[3]);

  const got = await pbkdf2Hash(password, salt, iter);
  return timingSafeEq(got, expected);
}

async function makeToken(env, userId) {
  if (!env.AUTH_SECRET) throw new Error("AUTH_SECRET not set");
  const header = b64urlEncode(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30;
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

async function safeReadJson(req) {
  try { return await req.json(); } catch { return null; }
}

function pickProfileId(url, body) {
  // minimal-fix: profileId aus Query oder Body
  return (
    url.searchParams.get("profileId") ||
    url.searchParams.get("p") ||
    (body && (body.profileId || body.profile_id)) ||
    null
  );
}


// --------------------
// Web Push (Cloudflare Workers) via @pushforge/builder
// Env:
// - VAPID_PRIVATE_KEY: JSON string of a JWK (private)
// - VAPID_SUBJECT: e.g. "mailto:you@example.com" or "https://your-domain"
// D1 table: push_subscriptions(id TEXT PRIMARY KEY, json TEXT NOT NULL, updated_at TEXT NOT NULL)
// We store ONLY one subscription with id="primary" (your phone PWA).
// --------------------
function requireEnv(env, key){
  const v = env[key];
  return (typeof v === "string" && v.trim()) ? v.trim() : null;
}

async function d1GetPrimarySubscription(env){
  if (!env.DB) return null;
  const row = await env.DB.prepare(
    "SELECT json FROM push_subscriptions WHERE id = 'primary' LIMIT 1"
  ).first();
  if (!row?.json) return null;
  try { return JSON.parse(row.json); } catch { return null; }
}

async function d1UpsertPrimarySubscription(env, subscription){
  if (!env.DB) throw new Error("DB not bound");
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO push_subscriptions (id, json, updated_at) VALUES ('primary', ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
  ).bind(JSON.stringify(subscription), now).run();
}

async function d1DeletePrimarySubscription(env){
  if (!env.DB) return;
  await env.DB.prepare("DELETE FROM push_subscriptions WHERE id='primary'").run();
}

async function sendWebPush(env, subscription, todoName){
  const vapidPrivate = requireEnv(env, "VAPID_PRIVATE_KEY");
  const vapidSubject = requireEnv(env, "VAPID_SUBJECT");
  if (!vapidPrivate || !vapidSubject) throw new Error("missing_vapid_env");

  // VAPID_PRIVATE_KEY is expected to be a JSON-encoded JWK (private key)
  const privateJWK = JSON.parse(vapidPrivate);

  const payload = JSON.stringify({
    title: "Erinnerung",
    body: String(todoName || "").trim() || "To-Do",
    url: "/todo"
  });

  const { endpoint, headers, body } = await buildPushHTTPRequest(
    privateJWK,
    {
      payload,
      ttl: 60 * 60 * 24, // 24h
      urgency: "normal",
    },
    subscription,
    vapidSubject
  );

  const res = await fetch(endpoint, { method: "POST", headers, body });

  // Expired / gone subscription -> delete so you can re-register on the phone
  if (res.status === 404 || res.status === 410) {
    await d1DeletePrimarySubscription(env);
  }

  if (!res.ok) {
    const t = await res.text().catch(()=> "");
    throw new Error("push_failed_" + res.status + "_" + t.slice(0,200));
  }

  return true;
}

async function handleApi(req, env) {
  try {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/home") return Response.redirect(new URL("/home.html", url.origin).toString(), 302);
    if (path === "/packliste") return Response.redirect(new URL("/packliste.html", url.origin).toString(), 302);
    if (path === "/vokabeln") return Response.redirect(new URL("/vokabeln.html", url.origin).toString(), 302);
    if (path === "/einkaufsliste") return env.ASSETS.fetch(new Request(url.origin + "/einkaufsliste.html", req));

    if (path === "/api/health" && req.method === "GET") {
      return json({
        ok: true,
        hasAuthSecret: !!env.AUTH_SECRET,
        hasDB: !!env.DB,
        time: new Date().toISOString(),
      });
    }

    // --- PUSH: register subscription (run ONLY on your phone PWA) ---
    if (path === "/api/push/register" && req.method === "POST") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const body = await safeReadJson(req);
      const sub = body?.subscription;

      if (!sub || typeof sub !== "object") return json({ error: "subscription_required" }, 400);
      if (!sub.endpoint || !sub.keys?.p256dh || !sub.keys?.auth) return json({ error: "bad_subscription" }, 400);

      await d1UpsertPrimarySubscription(env, sub);
      return json({ ok: true });
    }

    // --- PUSH: send a push to your stored phone subscription ---
    if (path === "/api/push/send" && req.method === "POST") {
      const body = await safeReadJson(req);
      const todoName = String(body?.name || body?.todoName || "").trim();
      if (!todoName) return json({ error: "name_required" }, 400);

      const sub = await d1GetPrimarySubscription(env);
      if (!sub) return json({ error: "no_subscription_registered" }, 400);

      try {
        await sendWebPush(env, sub, todoName);
        return json({ ok: true });
      } catch (e) {
        console.log("PUSH_SEND_ERROR", String(e?.message || e));
        return json({ ok: false, error: "push_send_failed", message: String(e?.message || e) }, 500);
      }
    }

    if (path === "/api/register" && req.method === "POST") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const body = await safeReadJson(req);
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

    if (path === "/api/login" && req.method === "POST") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);
      if (!env.AUTH_SECRET) return json({ error: "AUTH_SECRET not set" }, 500);

      const body = await safeReadJson(req);
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

    if (path === "/api/logout" && req.method === "POST") {
      return json(
        { ok: true },
        200,
        { "Set-Cookie": "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" }
      );
    }

    if (path === "/api/me" && req.method === "GET") {
      const uid = await readToken(env, req);
      if (!uid) return json({ loggedIn: false }, 401);
      return json({ loggedIn: true, userId: uid });
    }


    // Resolve Google Maps short links (maps.app.goo.gl) -> coordinates
    if (path === "/api/resolve-maps" && req.method === "GET") {

      const target = url.searchParams.get("url") || "";
      if (!target) return json({ ok: false, error: "missing_url" }, 400);

      let u;
      try { u = new URL(target); } catch { return json({ ok: false, error: "bad_url" }, 400); }

      const host = (u.hostname || "").toLowerCase();
      const allowed = ["maps.app.goo.gl", "goo.gl", "maps.google.com", "www.google.com"];
      const okHost = allowed.some(a => host === a || host.endsWith("." + a));
      if (!okHost) return json({ ok: false, error: "domain_not_allowed" }, 400);

      // Follow redirects so the final URL contains coordinates
      let finalUrl = target;
      try {
        const r = await fetch(target, { redirect: "follow" });
        finalUrl = r.url || finalUrl;
      } catch {}

      const coords = extractLatLngFromString(finalUrl) || extractLatLngFromString(target);
      if (!coords) return json({ ok: false, finalUrl, error: "no_coords" }, 200);

      return json({ ok: true, finalUrl, lat: coords.lat, lng: coords.lng }, 200, { "Cache-Control": "no-store" });
    }

    // 5) Daten GET/PUT/DELETE (minimal-fix: profileId definieren, statt ReferenceError)
    if (path === "/api/data") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);

      // GET: erlaubt auch ohne profileId (alte Logik)
      if (req.method === "GET") {
        const row = await env.DB.prepare("SELECT json FROM user_data WHERE user_id = ?")
          .bind(uid)
          .first();
        return json({ ok: true, data: row?.json ? JSON.parse(row.json) : null });
      }

      const body = await safeReadJson(req);

      // ✅ FALL 1: Globales Packliste-Dokument (dein { users:[...] } von /api/data)
      // -> in user_data speichern (damit alle Geräte syncen, ohne profileId)
      if (req.method === "PUT") {
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

        const looksGlobal = Array.isArray(body.users) || ("users" in body) || body.__test === "hello";

        if (looksGlobal) {
          const now = new Date().toISOString();
          await env.DB.prepare(
            "INSERT INTO user_data (user_id, json, updated_at) VALUES (?, ?, ?) " +
            "ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
          ).bind(uid, JSON.stringify(body), now).run();

          return json({ ok: true }, 200, { "Cache-Control": "no-store" });
        }
      }

      // ✅ FALL 2: Profil-basiert (dein bestehendes profiles/profile_data System)
      // -> profileId ist Pflicht
      const profileId = pickProfileId(new URL(req.url), body);
      if (!profileId) return json({ error: "profileId_required" }, 400);

      // ===== ab hier bleibt DEIN Code wie er ist =====
      if (req.method === "PUT") {
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

        const name = String(body?.name || "").trim() || "Benutzer";
        const now = new Date().toISOString();
        const nowSec = Math.floor(Date.now() / 1000);

        const existingRow = await env.DB.prepare(
          "SELECT json FROM profile_data WHERE owner_id = ? AND profile_id = ?"
        ).bind(uid, profileId).first();

        const oldData = existingRow?.json ? JSON.parse(existingRow.json) : null;

        const oldCounts = countItems(oldData);
        const newCounts = countItems(body);

        const listsDeleted = Math.max(0, (oldCounts.lists || 0) - (newCounts.lists || 0));
        const itemsDeleted = Math.max(0, (oldCounts.items || 0) - (newCounts.items || 0));

        const destructive = (listsDeleted >= 1) || (itemsDeleted >= 20);

        const force = body?._force === true;
        const confirmToken = body?._confirm;

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
            exp: nowSec + 60,
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

        await env.DB.prepare(
          "INSERT INTO profiles (owner_id, profile_id, name, updated_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(owner_id, profile_id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at"
        ).bind(uid, profileId, name, now).run();

        await env.DB.prepare(
          "INSERT INTO profile_data (owner_id, profile_id, json, updated_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(owner_id, profile_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, profileId, JSON.stringify(bodyForHash), now).run();

        return json({ ok: true }, 200, { "Cache-Control": "no-store" });
      }

      if (req.method === "DELETE") {
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

    // 6) AI (Groq) — FIX: text() lesen + parse + loggen
    if (path === "/api/ai" && req.method === "POST") {
      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);

      if (!env.Groq_API) return json({ error: "Groq_API_missing" }, 500);

      const body = await safeReadJson(req);
      const prompt = String(body?.prompt || "").trim();
      if (!prompt) return json({ error: "prompt_required" }, 400);

      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.Groq_API}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "moonshotai/kimi-k2-instruct",
          messages: [{ role: "user", content: prompt }],
          temperature: 0.7,
        }),
      });

      const raw = await r.text();
      let parsed = null;
      try { parsed = JSON.parse(raw); } catch {}

      if (!r.ok) {
        console.log("GROQ_ERROR", r.status, raw.slice(0, 800));
        return json(
          { error: "groq_error", status: r.status, details: parsed ?? raw.slice(0, 800) },
          502
        );
      }

      const text = parsed?.choices?.[0]?.message?.content || "";
      return json({ ok: true, text });
    }

    // Debug: prüfen ob Secret ankommt
    if (path === "/api/debug-groq" && req.method === "GET") {
      return json({ ok: true, service: "app", hasGroq: !!env.Groq_API });
    }

    // Debug: Groq-Key/Endpoint testen (damit du 401/403/429 direkt siehst)
    if (path === "/api/ai-debug" && req.method === "GET") {
      const r = await fetch("https://api.groq.com/openai/v1/models", {
        headers: { Authorization: `Bearer ${env.Groq_API}` }
      });
      const t = await r.text();
      console.log("GROQ_MODELS_STATUS", r.status, t.slice(0, 400));
      return json({ ok: r.ok, status: r.status, body: t.slice(0, 800) }, 200, { "Cache-Control": "no-store" });
    }

    
    // ===== Lernen API (Profile + Whiteboards + Chat-Settings) =====
    if (path.startsWith("/api/learn/")) {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);
      try {

      if (path === "/api/learn/data" && req.method === "GET") {
        const row = await env.DB.prepare(
          "SELECT json FROM learn_data WHERE user_id = ?"
        ).bind(uid).first();

        let data;
        if (row?.json) {
          data = JSON.parse(row.json);
        } else {
          // Erstes Mal: stabiler Default (damit Frontend nie crasht)
          data = {
            profiles: [
              {
                id: "p_default",
                name: "Benutzer",
                // optional: Vokabel-Ordner/Lernsets (später)
                vocabFolders: [],
                boards: [
                  {
                    id: "b_default",
                    name: "Whiteboard 1",
                    blocks: [],
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString()
                  }
                ]
              }
            ]
          };
        }
        return json({ ok: true, data }, 200, { "Cache-Control": "no-store" });
      }

      if (path === "/api/learn/data" && req.method === "PUT") {
        const body = await safeReadJson(req);
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

        const now = new Date().toISOString();
        await env.DB.prepare(
          "INSERT INTO learn_data (user_id, json, updated_at) VALUES (?, ?, ?) " +
          "ON CONFLICT(user_id) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at"
        ).bind(uid, JSON.stringify(body), now).run();

        return json({ ok: true }, 200, { "Cache-Control": "no-store" });
      }

      return json({ error: "not_found", path }, 404);
      } catch (e) {
        console.log("LEARN_API_ERROR", e && (e.stack || e.message || String(e)));
        const msg = e?.message ? String(e.message) : String(e);
        if (msg.includes("no such table") && msg.includes("learn_data")) {
          return json({ error: "learn_table_missing", message: msg }, 500);
        }
        return json({ error: "learn_api_error", message: msg }, 500);
      }

    }

// ===== Einkaufsliste API =====
    if (path.startsWith("/api/einkauf/")) {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);

      if (path === "/api/einkauf/data" && req.method === "GET") {
        const row = await env.DB.prepare(
          "SELECT json FROM einkauf_data WHERE user_id = ?"
        ).bind(uid).first();

        return json(
          { ok: true, data: row?.json ? JSON.parse(row.json) : { lists: [] } },
          200,
          { "Cache-Control": "no-store" }
        );
      }

      if (path === "/api/einkauf/data" && req.method === "PUT") {
        const body = await safeReadJson(req);
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

        const now = new Date().toISOString();
        await env.DB.prepare(
          "INSERT INTO einkauf_data (user_id, json, updated_at) VALUES (?, ?, ?) " +
          "ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, JSON.stringify(body), now).run();

        return json({ ok: true }, 200, { "Cache-Control": "no-store" });
      }

      return json({ error: "not_found", path }, 404);
    }
    // ===== To-Do API =====
    if (path.startsWith("/api/todo/")) {
      if (!env.DB) return json({ error: "DB not bound" }, 500);

      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);

      if (path === "/api/todo/data" && req.method === "GET") {
        const row = await env.DB.prepare(
          "SELECT json FROM todo_data WHERE user_id = ?"
        ).bind(uid).first();

        let parsed = null;
        if (row && row.json) {
          try { parsed = JSON.parse(row.json); } catch {}
        }

        return json(
          { ok: true, data: parsed || { tasks: [], settings: { doneBottom: false, checkbox: false } } },
          200,
          { "Cache-Control": "no-store" }
        );
      }

      if (path === "/api/todo/data" && req.method === "PUT") {
        const body = await safeReadJson(req);
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);

        const now = new Date().toISOString();
        await env.DB.prepare(
          "INSERT INTO todo_data (user_id, json, updated_at) VALUES (?, ?, ?) " +
          "ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, JSON.stringify(body), now).run();

        return json({ ok: true }, 200, { "Cache-Control": "no-store" });
      }

      return json({ error: "not_found", path }, 404);
    }


    return json({ error: "not_found", path }, 404);

  } catch (e) {
    console.log("WORKER_CRASH", String(e?.message || e));
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

      // ✅ WEBCAM LIVE (stabil + Gruppen) – MUSS VOR LOGIN-GATE!
// Unterstütze sowohl /webcam-live/* als auch kurze Aliases (/room, /ws, /groups),
// damit du Links wie /room?room=... verwenden kannst ohne dass eine alte Version geladen wird.
if (
  path === "/webcam-live" ||
  path === "/webcam-live/" ||
  path === "/webcam-live/room" ||
  path === "/webcam-live/groups" ||
  path === "/webcam-live/ws" ||
  path === "/room" ||
  path === "/groups" ||
  path === "/ws"
) {
  const resp = await handleWebcamLive(req, env);
        return withNoStore(resp);
      }

let assetPath = path;

      if (path === "/home") assetPath = "/home.html";
      if (path === "/packliste") assetPath = "/packliste.html";
      if (path === "/vokabeln") assetPath = "/vokabeln.html";
      if (path === "/settings") assetPath = "/settings.html";
      if (path === "/einkaufsliste") assetPath = "/einkaufsliste.html";
      if (path === "/todo") assetPath = "/todo.html";
      if (path === "/lernen") assetPath = "/lernen.html";
      if (path === "/lernen/") assetPath = "/lernen.html";
      if (path === "/lernen/ki") assetPath = "/lernen-ki.html";
      if (path === "/lernen/whiteboard") assetPath = "/whiteboard.html";
      if (path.startsWith("/lernen/whiteboard/")) assetPath = "/whiteboard.html";


      if (path.startsWith("/packliste/")) assetPath = "/packliste.html";
      if (path.startsWith("/einkaufsliste/")) assetPath = "/einkaufsliste.html";
      if (path.startsWith("/todo/")) assetPath = "/todo.html";

      if (path.startsWith("/api/")) {
        return handleApi(req, env);
      }

      if (path === "/login") {
        return env.ASSETS.fetch(new Request(url.origin + "/login.html", req));
      }

      // ✅ Service Worker & PWA assets must be reachable WITHOUT login redirect
      if (path === "/sw.js") {
        return env.ASSETS.fetch(new Request(url.origin + "/sw.js", req));
      }
      if (path === "/manifest.webmanifest") {
        return env.ASSETS.fetch(new Request(url.origin + "/manifest.webmanifest", req));
      }
      if (path === "/icon-192.png" || path === "/icon-512.png") {
        return env.ASSETS.fetch(new Request(url.origin + path, req));
      }


      const uid = await readToken(env, req);
      if (!uid) {
        const loginUrl = new URL("/login", url.origin);
        loginUrl.searchParams.set("returnTo", path + url.search);
        return Response.redirect(loginUrl.toString(), 302);
      }

      const res = await env.ASSETS.fetch(new Request(url.origin + assetPath, req));
      if (res.status === 404) {
        const target = new URL("/home", url.origin);
        target.searchParams.set("msg", "loadfail");
        return Response.redirect(target.toString(), 302);
      }
      return res;

    } catch (err) {
      const url = new URL(req.url);
      const path = url.pathname;

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

      if (path === "/home" || path === "/" || path === "/home.html") {
        return new Response("Fehler im Worker. Bitte Workers Logs prüfen.", { status: 500 });
      }

      const target = new URL("/home.html", url.origin);
      target.searchParams.set("msg", "loadfail");
      return Response.redirect(target.toString(), 302);
    }
  },
};