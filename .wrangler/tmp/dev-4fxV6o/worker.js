var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/worker.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
function makeId(prefix = "id") {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  const s = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}_${s.slice(0, 16)}`;
}
__name(makeId, "makeId");
function b64urlEncode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(b64urlEncode, "b64urlEncode");
function b64urlDecodeToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
__name(b64urlDecodeToBytes, "b64urlDecodeToBytes");
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
__name(hmacSign, "hmacSign");
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
__name(hmacVerify, "hmacVerify");
function parseCookies(req) {
  const h = req.headers.get("Cookie") || "";
  const out = {};
  h.split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
__name(parseCookies, "parseCookies");
function json(res, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(res), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}
__name(json, "json");
async function pbkdf2Hash(password, saltBytes, iterations = 15e4) {
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
__name(pbkdf2Hash, "pbkdf2Hash");
function timingSafeEq(a, b) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}
__name(timingSafeEq, "timingSafeEq");
async function makePassRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 1e5;
  const hash = await pbkdf2Hash(password, salt, iterations);
  return `pbkdf2$${iterations}$${b64urlEncode(salt)}$${b64urlEncode(hash)}`;
}
__name(makePassRecord, "makePassRecord");
async function verifyPass(password, record) {
  const parts = record.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iter = parseInt(parts[1], 10);
  if (!Number.isFinite(iter) || iter < 1 || iter > 1e5) return false;
  const salt = b64urlDecodeToBytes(parts[2]);
  const expected = b64urlDecodeToBytes(parts[3]);
  const got = await pbkdf2Hash(password, salt, iter);
  return timingSafeEq(got, expected);
}
__name(verifyPass, "verifyPass");
async function makeToken(env, userId) {
  if (!env.AUTH_SECRET) throw new Error("AUTH_SECRET not set");
  const header = b64urlEncode(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const exp = Math.floor(Date.now() / 1e3) + 60 * 60 * 24 * 30;
  const payload = b64urlEncode(encoder.encode(JSON.stringify({ u: userId, exp })));
  const data = `${header}.${payload}`;
  const sig = b64urlEncode(await hmacSign(env.AUTH_SECRET, encoder.encode(data)));
  return `${data}.${sig}`;
}
__name(makeToken, "makeToken");
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
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1e3)) return null;
  return payload.u;
}
__name(readToken, "readToken");
async function handleApi(req, env) {
  try {
    const url = new URL(req.url);
    const path = url.pathname;
    if (path === "/home") {
      return Response.redirect(new URL("/home.html", url.origin).toString(), 302);
    }
    if (path === "/packliste") {
      return Response.redirect(new URL("/packliste.html", url.origin).toString(), 302);
    }
    if (path === "/vokabeln") {
      return Response.redirect(new URL("/vokabeln.html", url.origin).toString(), 302);
    }
    if (path === "/api/health" && req.method === "GET") {
      return json({
        ok: true,
        hasAuthSecret: !!env.AUTH_SECRET,
        hasDB: !!env.DB,
        time: (/* @__PURE__ */ new Date()).toISOString()
      });
    }
    if (path === "/api/register" && req.method === "POST") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);
      const body = await req.json().catch(() => null);
      if (!body?.username || !body?.password) return json({ error: "missing" }, 400);
      const exists = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
      if ((exists?.c || 0) > 0) return json({ error: "disabled" }, 403);
      const pass = await makePassRecord(body.password);
      await env.DB.prepare(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)"
      ).bind(body.username, pass, (/* @__PURE__ */ new Date()).toISOString()).run();
      return json({ ok: true });
    }
    if (path === "/api/login" && req.method === "POST") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);
      if (!env.AUTH_SECRET) return json({ error: "AUTH_SECRET not set" }, 500);
      const body = await req.json().catch(() => null);
      if (!body?.username || !body?.password) return json({ error: "missing" }, 400);
      const user = await env.DB.prepare(
        "SELECT id, password_hash FROM users WHERE username = ?"
      ).bind(body.username).first();
      if (!user) return json({ error: "invalid" }, 401);
      const ok = await verifyPass(body.password, user.password_hash);
      if (!ok) return json({ error: "invalid" }, 401);
      const token = await makeToken(env, user.id);
      return json(
        { ok: true },
        200,
        {
          "Set-Cookie": `session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${60 * 60 * 24 * 30}`
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
    if (path === "/api/data") {
      if (!env.DB) return json({ error: "DB not bound" }, 500);
      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);
      if (req.method === "GET") {
        const row = await env.DB.prepare("SELECT json FROM user_data WHERE user_id = ?").bind(uid).first();
        return json({ ok: true, data: row?.json ? JSON.parse(row.json) : null });
      }
      if (req.method === "PUT") {
        const body = await req.json().catch(() => null);
        if (!body) return json({ error: "bad_json" }, 400);
        const now = (/* @__PURE__ */ new Date()).toISOString();
        await env.DB.prepare(
          "INSERT INTO user_data (user_id, json, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, JSON.stringify(body), now).run();
        return json({ ok: true });
      }
      return json({ error: "method" }, 405);
    }
    if (path === "/api/profiles") {
      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauth" }, 401);
      if (req.method === "GET") {
        const rows = await env.DB.prepare(
          "SELECT profile_id AS id, name, updated_at FROM profiles WHERE owner_id = ? ORDER BY updated_at DESC"
        ).bind(uid).all();
        return json({ ok: true, profiles: rows?.results || [] });
      }
      if (req.method === "POST") {
        const body = await req.json().catch(() => null);
        const name = String(body?.name || "").trim();
        if (!name) return json({ error: "name_required" }, 400);
        const id = makeId("p");
        const now = (/* @__PURE__ */ new Date()).toISOString();
        await env.DB.prepare(
          "INSERT INTO profiles (owner_id, profile_id, name, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(owner_id, profile_id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at"
        ).bind(uid, id, name, now).run();
        const initial = { id, name, lists: [] };
        await env.DB.prepare(
          "INSERT INTO profile_data (owner_id, profile_id, json, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(owner_id, profile_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, id, JSON.stringify(initial), now).run();
        return json({ ok: true, id });
      }
      return json({ error: "method" }, 405);
    }
    if (path.startsWith("/api/profiles/")) {
      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauth" }, 401);
      const profileId = decodeURIComponent(path.split("/").slice(3).join("/") || "");
      if (!profileId) return json({ error: "bad_profile_id" }, 400);
      if (req.method === "GET") {
        const row = await env.DB.prepare(
          "SELECT json FROM profile_data WHERE owner_id = ? AND profile_id = ?"
        ).bind(uid, profileId).first();
        return json({ ok: true, data: row?.json ? JSON.parse(row.json) : null });
      }
      if (req.method === "PUT") {
        const body = await req.json().catch(() => null);
        if (!body || typeof body !== "object") return json({ error: "bad_json" }, 400);
        const name = String(body?.name || "").trim() || "Benutzer";
        const now = (/* @__PURE__ */ new Date()).toISOString();
        await env.DB.prepare(
          "INSERT INTO profiles (owner_id, profile_id, name, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(owner_id, profile_id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at"
        ).bind(uid, profileId, name, now).run();
        await env.DB.prepare(
          "INSERT INTO profile_data (owner_id, profile_id, json, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(owner_id, profile_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"
        ).bind(uid, profileId, JSON.stringify(body), now).run();
        return json({ ok: true });
      }
      if (req.method === "DELETE") {
        await env.DB.prepare("DELETE FROM profile_data WHERE owner_id = ? AND profile_id = ?").bind(uid, profileId).run();
        await env.DB.prepare("DELETE FROM profiles WHERE owner_id = ? AND profile_id = ?").bind(uid, profileId).run();
        return json({ ok: true });
      }
      return json({ error: "method" }, 405);
    }
    if (path === "/api/ai" && req.method === "POST") {
      const uid = await readToken(env, req);
      if (!uid) return json({ error: "unauthorized" }, 401);
      if (!env.GEMINI_API_KEY) return json({ error: "GEMINI_API_KEY_missing" }, 500);
      const body = await req.json().catch(() => null);
      const prompt = String(body?.prompt || "").trim();
      if (!prompt) return json({ error: "prompt_required" }, 400);
      const url2 = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + encodeURIComponent(env.GEMINI_API_KEY);
      const r = await fetch(url2, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ role: "user", parts: [{ text: prompt }] }]
        })
      });
      const j = await r.json().catch(() => null);
      if (!r.ok) return json({ error: "gemini_error", status: r.status, details: j }, 502);
      const text = j?.candidates?.[0]?.content?.parts?.map((p) => p?.text).filter(Boolean).join("\n") || "";
      return json({ ok: true, text });
    }
    return json({ error: "not_found", path }, 404);
  } catch (e) {
    return json(
      {
        error: "worker_crash",
        message: String(e?.message || e),
        stack: String(e?.stack || "")
      },
      500
    );
  }
}
__name(handleApi, "handleApi");
var worker_default = {
  async fetch(req, env, ctx) {
    try {
      const url = new URL(req.url);
      const path = url.pathname;
      if (path === "/home") return Response.redirect(new URL("/home.html", url.origin).toString(), 302);
      if (path === "/packliste") return env.ASSETS.fetch(new Request(url.origin + "/packliste.html", req));
      if (path === "/vokabeln") return Response.redirect(new URL("/vokabeln.html", url.origin).toString(), 302);
      if (path === "/settings") return Response.redirect(new URL("/settings.html", url.origin).toString(), 302);
      if (path.startsWith("/packliste/")) {
        return env.ASSETS.fetch(new Request(url.origin + "/packliste.html", req));
      }
      if (path.startsWith("/api/")) {
        return handleApi(req, env);
      }
      if (path === "/login") {
        return env.ASSETS.fetch(new Request(url.origin + "/login.html", req));
      }
      const uid = await readToken(env, req);
      if (!uid) {
        const loginUrl = new URL("/login", url.origin);
        loginUrl.searchParams.set("returnTo", path + url.search);
        return Response.redirect(loginUrl.toString(), 302);
      }
      const res = await env.ASSETS.fetch(req);
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
          message: String(err && err.message ? err.message : err)
        }), {
          status: 500,
          headers: { "content-type": "application/json; charset=utf-8" }
        });
      }
      if (path === "/home" || path === "/" || path === "/home.html") {
        return new Response("Fehler im Worker. Bitte Workers Logs pr\xFCfen.", { status: 500 });
      }
      const target = new URL("/home.html", url.origin);
      target.searchParams.set("msg", "loadfail");
      return Response.redirect(target.toString(), 302);
    }
  }
};

// ../../usr/local/share/nvm/versions/node/v24.11.1/lib/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../usr/local/share/nvm/versions/node/v24.11.1/lib/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-BH551I/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// ../../usr/local/share/nvm/versions/node/v24.11.1/lib/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-BH551I/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker.js.map
