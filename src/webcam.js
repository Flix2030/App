// src/webcam.js
// ✅ Kostenlos + stabil über verschiedene Netze (auch Mobile Daten) – ohne WebRTC
// Prinzip: Sender streamt JPEG-Frames -> WebSocket -> Durable Object (STREAM) -> Zuschauer bekommen Frames.
// Zusätzlich: Lobby-Liste aktiver Gruppen (LOBBY DO) für "LIVE"-Übersicht.
//
// Routen (im Worker vor dem Login-Gate):
// - GET  /webcam-live                 -> Lobby UI (aktive Gruppen + neue Gruppe)
// - GET  /webcam-live/room            -> Room UI (send/watch)
// - GET  /webcam-live/groups          -> JSON Liste aktiver Gruppen
// - WS   /webcam-live/ws?room=NAME    -> STREAM WebSocket (Frames + Control)
//
// Bindings (wrangler.jsonc):
// durable_objects.bindings: [{name:"LOBBY", class_name:"LOBBY"}, {name:"STREAM", class_name:"STREAM"}]
// migrations (Free plan): new_sqlite_classes für beide Klassen

// ---------------------------
// Durable Object: LOBBY (global)
// ---------------------------
export class LOBBY {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    const key = "rooms";

    const loadRooms = async () => {
      const rooms = (await this.state.storage.get(key)) || {};
      const now = Date.now();
      let changed = false;
      for (const [name, info] of Object.entries(rooms)) {
        if (!info || typeof info !== "object") { delete rooms[name]; changed = true; continue; }
        if (!info.senderOnline) continue;
        if ((now - (info.lastSeen || 0)) > 120000) { // 2 min stale -> mark offline
          info.senderOnline = false;
          info.viewers = info.viewers || 0;
          changed = true;
        }
      }
      if (changed) await this.state.storage.put(key, rooms);
      return rooms;
    };

    if (path.endsWith("/groups") && request.method === "GET") {
      const rooms = await loadRooms();
      const list = Object.entries(rooms)
        .filter(([_, r]) => r?.senderOnline)
        .map(([name, r]) => ({
          room: name,
          viewers: r.viewers || 0,
          lastSeen: r.lastSeen || 0,
        }))
        .sort((a, b) => (b.lastSeen - a.lastSeen));

      return new Response(JSON.stringify({ ok: true, rooms: list }), {
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
      });
    }

    if (path.endsWith("/touch") && request.method === "POST") {
      let body = null;
      try { body = await request.json(); } catch {}
      const room = String(body?.room || "").trim().slice(0, 64);
      if (!room) return new Response("bad room", { status: 400 });

      const rooms = (await this.state.storage.get(key)) || {};
      const prev = rooms[room] || {};
      rooms[room] = {
        room,
        senderOnline: body?.senderOnline === true,
        viewers: Number.isFinite(body?.viewers) ? Math.max(0, body.viewers) : (prev.viewers || 0),
        lastSeen: Date.now(),
      };
      await this.state.storage.put(key, rooms);
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    }

    return new Response("Not found", { status: 404 });
  }
}

// ---------------------------
// Durable Object: STREAM (per room)
// ---------------------------
export class STREAM {
  constructor(state, env) {
    this.state = state;
    this.env = env;

    this.senderId = null;
    this.clients = new Map(); // id -> { ws, role }
    this.lastFrame = null; // ArrayBuffer
    this.lastFrameAt = 0;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const client = pair[1];
    const server = pair[0];

    const id = crypto.randomUUID();
    server.accept();

    this.clients.set(id, { ws: server, role: "watch" });

    const sendText = (ws, obj) => { try { ws.send(JSON.stringify(obj)); } catch {} };
    const sendBin = (ws, buf) => { try { ws.send(buf); } catch {} };

    const roomName = String(url.searchParams.get("room") || "default").slice(0, 64);

    const touchLobby = async () => {
      try {
        if (!this.env.LOBBY) return;
        const lobbyId = this.env.LOBBY.idFromName("global");
        const lobby = this.env.LOBBY.get(lobbyId);
        const viewers = [...this.clients.values()].filter(c => c.role === "watch").length;
        const senderOnline = !!this.senderId && this.clients.has(this.senderId);
        await lobby.fetch("https://internal/webcam-live/touch", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ room: roomName, senderOnline, viewers }),
        });
      } catch {}
    };

    sendText(server, { type: "hello", id });

    const pingTimer = setInterval(() => {
      if (server.readyState !== 1) return;
      sendText(server, { type: "ping" });
    }, 20000);

    const closeIt = async () => {
      clearInterval(pingTimer);
      this.clients.delete(id);
      if (this.senderId === id) this.senderId = null;
      await touchLobby();
    };

    server.addEventListener("close", () => { closeIt(); });
    server.addEventListener("error", () => { closeIt(); });

    server.addEventListener("message", async (evt) => {
      const c = this.clients.get(id);
      if (!c) return;

      if (typeof evt.data === "string") {
        let msg = null;
        try { msg = JSON.parse(evt.data); } catch { return; }
        if (!msg || typeof msg !== "object") return;

        if (msg.type === "role") {
          const role = msg.role === "send" ? "send" : "watch";

          if (role === "send") {
            if (this.senderId && this.senderId !== id && this.clients.has(this.senderId)) {
              sendText(server, { type: "role_denied", reason: "sender_exists" });
              return;
            }
            this.senderId = id;
            c.role = "send";
            this.clients.set(id, c);
            sendText(server, { type: "role_ok", role: "send" });
            await touchLobby();
            return;
          }

          c.role = "watch";
          this.clients.set(id, c);
          sendText(server, { type: "role_ok", role: "watch" });
          if (this.lastFrame) sendBin(server, this.lastFrame);
          await touchLobby();
          return;
        }

        if (msg.type === "pong") return;
        return;
      }

      if (!(evt.data instanceof ArrayBuffer)) return;

      if (id !== this.senderId) {
        sendText(server, { type: "frame_denied" });
        return;
      }

      this.lastFrame = evt.data;
      this.lastFrameAt = Date.now();

      for (const [oid, other] of this.clients.entries()) {
        if (oid === id) continue;
        if (other.role !== "watch") continue;
        sendBin(other.ws, evt.data);
      }

      await touchLobby();
    });

    await touchLobby();
    return new Response(null, { status: 101, webSocket: client });
  }
}

// ---------------------------
// UI HTML
// ---------------------------
const HTML_LOBBY = `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>Webcam – Gruppen</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#0b0b0c; color:#fff; }
    .wrap { max-width: 920px; margin: 0 auto; padding: 16px; }
    .card { background:#141417; border:1px solid #24242a; border-radius: 14px; padding: 14px; margin-bottom: 12px; }
    input, button { font-size: 16px; }
    input { width: 100%; padding: 10px 12px; border-radius: 12px; border:1px solid #2a2a33; background:#0f0f13; color:#fff; outline:none; }
    button { padding: 10px 12px; border-radius: 12px; border:1px solid #2a2a33; background:#1b1b22; color:#fff; cursor:pointer; }
    button:hover { filter: brightness(1.1); }
    .row { display:flex; gap:10px; align-items:center; }
    .row > * { flex: 1; }
    .small { opacity:.85; font-size: 13px; line-height: 1.35; }
    .list { display:flex; flex-direction:column; gap:10px; margin-top: 10px; }
    .item { display:flex; gap:10px; align-items:center; justify-content:space-between; padding: 12px; border-radius: 14px; border:1px solid #24242a; background:#101014; }
    .badge { display:inline-block; padding: 2px 8px; border-radius: 999px; border:1px solid #2a2a33; background:#101017; font-size: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2 style="margin: 0 0 6px;">Aktive Gruppen</h2>
      <div class="small">Hier siehst du Gruppen, in denen gerade jemand live sendet.</div>
      <div class="list" id="list"></div>
      <div class="small" style="margin-top:10px;">Auto-Refresh: alle 3 Sekunden</div>
    </div>

    <div class="card">
      <h2 style="margin: 0 0 6px;">Neue Gruppe erstellen</h2>
      <div class="row">
        <input id="room" placeholder="Gruppenname (z.B. flix)" />
        <button id="create">Erstellen & Senden</button>
      </div>
      <div class="small" style="margin-top:10px;">
        Tipp: FPS 2–4, Breite 480/640, Qualität 0.5–0.7 (in der Gruppe einstellbar).
      </div>
    </div>
  </div>

<script>
(() => {
  const listEl = document.getElementById("list");
  const roomEl = document.getElementById("room");
  const createBtn = document.getElementById("create");

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  async function load() {
    try {
      const r = await fetch("/webcam-live/groups", { cache: "no-store" });
      const j = await r.json();
      const rooms = j.rooms || [];
      if (!rooms.length) {
        listEl.innerHTML = '<div class="small">Keine aktiven Gruppen.</div>';
        return;
      }
      listEl.innerHTML = rooms.map(x => {
        const room = escapeHtml(x.room);
        const viewers = Number(x.viewers || 0);
        return `
          <div class="item">
            <div>
              <div><b>${room}</b> <span class="badge">LIVE</span></div>
              <div class="small">Zuschauer: ${viewers}</div>
            </div>
            <div>
              <button onclick="location.href='/webcam-live/room?room=${encodeURIComponent(room)}&mode=watch'">Zuschauen</button>
            </div>
          </div>`;
      }).join("");
    } catch (e) {
      listEl.innerHTML = '<div class="small">Fehler beim Laden.</div>';
    }
  }

  createBtn.onclick = () => {
    const room = (roomEl.value || "").trim();
    if (!room) return alert("Gruppenname fehlt");
    location.href = "/webcam-live/room?room=" + encodeURIComponent(room) + "&mode=send";
  };

  load();
  setInterval(load, 3000);
})();
</script>
</body>
</html>`;

const HTML_ROOM = `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>Webcam – Room</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#0b0b0c; color:#fff; }
    .wrap { max-width: 920px; margin: 0 auto; padding: 16px; }
    .card { background:#141417; border:1px solid #24242a; border-radius: 14px; padding: 14px; }
    input, button { font-size: 16px; }
    button { padding: 10px 12px; border-radius: 12px; border:1px solid #2a2a33; background:#1b1b22; color:#fff; cursor:pointer; }
    button:hover { filter: brightness(1.1); }
    video, img { width:100%; background:#000; border-radius: 14px; border:1px solid #24242a; aspect-ratio: 16/9; object-fit: cover; }
    .grid { display:grid; grid-template-columns: 1fr; gap: 12px; margin-top: 12px; }
    @media(min-width: 860px){ .grid { grid-template-columns: 1fr 1fr; } }
    .small { opacity:.85; font-size: 13px; line-height: 1.35; }
    .row { display:flex; gap:10px; align-items:center; }
    .row > * { flex: 1; }
    .badge { display:inline-block; padding: 2px 8px; border-radius: 999px; border:1px solid #2a2a33; background:#101017; font-size: 12px; }
    .log { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; background:#0f0f13; border:1px solid #24242a; border-radius: 14px; padding: 10px; height: 140px; overflow:auto; margin-top: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="row" style="align-items:flex-start;">
        <div>
          <div class="badge" id="status">offline</div>
          <h2 style="margin: 10px 0 6px;">Room: <span id="roomName"></span></h2>
          <div class="small">Modus: <b id="modeName"></b></div>
        </div>
        <div style="max-width: 220px;">
          <button onclick="location.href='/webcam-live'">← Zurück</button>
        </div>
      </div>

      <div class="grid">
        <div id="localBox">
          <div class="small" style="margin-bottom:6px;">Local (Sender)</div>
          <video id="local" playsinline muted autoplay></video>
        </div>
        <div>
          <div class="small" style="margin-bottom:6px;">Remote (Livebild)</div>
          <img id="remote" alt="Remote" />
        </div>
      </div>

      <div id="senderSettings" style="margin-top:12px;">
        <div class="small">Sender-Einstellungen:</div>
        <div class="row" style="margin-top:8px;">
          <div>
            <label class="small">FPS</label>
            <input id="fps" type="number" min="1" max="15" value="4" />
          </div>
          <div>
            <label class="small">Breite (px)</label>
            <input id="w" type="number" min="160" max="1280" value="640" />
          </div>
          <div>
            <label class="small">Qualität (0.3–0.95)</label>
            <input id="q" type="number" min="0.3" max="0.95" step="0.05" value="0.7" />
          </div>
        </div>
        <div class="small" style="margin-top:8px;">Tipp: Display an lassen, sonst stoppt iOS/Android die Kamera im Hintergrund.</div>
      </div>

      <div class="row" style="margin-top:12px;">
        <button id="btnGo">Verbinden</button>
        <button id="btnHang">Trennen</button>
      </div>

      <div class="log" id="log"></div>
    </div>
  </div>

<script>
(() => {
  const $ = (id) => document.getElementById(id);

  const statusEl = $("status");
  const logEl = $("log");
  const localV = $("local");
  const remoteImg = $("remote");
  const btnGo = $("btnGo");
  const btnHang = $("btnHang");
  const fpsEl = $("fps");
  const wEl = $("w");
  const qEl = $("q");
  const localBox = $("localBox");
  const senderSettings = $("senderSettings");

  const params = new URLSearchParams(location.search);
  const room = (params.get("room") || "").trim() || "default";
  const mode = (params.get("mode") || "watch") === "send" ? "send" : "watch";

  $("roomName").textContent = room;
  $("modeName").textContent = mode;

  if (mode !== "send") {
    localBox.style.display = "none";
    senderSettings.style.display = "none";
  }

  const log = (...a) => {
    const line = a.map(x => typeof x === "string" ? x : JSON.stringify(x)).join(" ");
    logEl.textContent += line + "\n";
    logEl.scrollTop = logEl.scrollHeight;
  };

  let ws = null;
  let localStream = null;
  let running = false;
  let lastUrl = null;

  function setStatus(s) { statusEl.textContent = s; }

  function wsUrl() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    return proto + "//" + location.host + "/webcam-live/ws?room=" + encodeURIComponent(room);
  }

  function setRemoteFromBuffer(buf) {
    try {
      const blob = new Blob([buf], { type: "image/jpeg" });
      const url = URL.createObjectURL(blob);
      remoteImg.src = url;
      if (lastUrl) URL.revokeObjectURL(lastUrl);
      lastUrl = url;
    } catch {}
  }

  async function startSenderLoop() {
    const width = Math.max(160, Math.min(1280, parseInt(wEl.value || "640", 10) || 640));
    const fps = Math.max(1, Math.min(15, parseInt(fpsEl.value || "4", 10) || 4));
    const quality = Math.max(0.3, Math.min(0.95, parseFloat(qEl.value || "0.7") || 0.7));
    const intervalMs = Math.round(1000 / fps);

    localStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
      audio: false
    });
    localV.srcObject = localStream;

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { alpha: false });

    await new Promise((res) => {
      if (localV.readyState >= 2) return res();
      localV.onloadedmetadata = () => res();
    });

    const srcW = localV.videoWidth || 1280;
    const srcH = localV.videoHeight || 720;
    const height = Math.round(width * (srcH / srcW));
    canvas.width = width;
    canvas.height = height;

    log("send:", fps, "fps", width + "x" + height, "q=" + quality);

    const blobToArrayBuffer = (blob) => new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = reject;
      r.readAsArrayBuffer(blob);
    });

    running = true;

    while (running) {
      if (!ws || ws.readyState !== 1) { await new Promise(r => setTimeout(r, 200)); continue; }
      if (!localV || localV.readyState < 2) { await new Promise(r => setTimeout(r, 100)); continue; }

      try {
        ctx.drawImage(localV, 0, 0, width, height);
        const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", quality));
        if (blob) {
          const buf = await blobToArrayBuffer(blob);
          ws.send(buf);
        }
      } catch {}

      await new Promise(r => setTimeout(r, intervalMs));
    }
  }

  function stopSender() {
    running = false;
    if (localStream) {
      for (const t of localStream.getTracks()) try { t.stop(); } catch {}
    }
    localStream = null;
    localV.srcObject = null;
  }

  function cleanupWs() {
    if (ws) { try { ws.close(); } catch {} }
    ws = null;
  }

  function connect() {
    cleanupWs();
    setStatus("connecting...");
    ws = new WebSocket(wsUrl());
    ws.binaryType = "arraybuffer";

    ws.onopen = () => {
      setStatus("connected");
      ws.send(JSON.stringify({ type: "role", role: mode }));
      log("WS open");
    };

    ws.onclose = () => { setStatus("offline"); log("WS close"); };
    ws.onerror = () => { log("WS error"); };

    ws.onmessage = async (evt) => {
      if (typeof evt.data === "string") {
        let msg = null;
        try { msg = JSON.parse(evt.data); } catch { return; }

        if (msg.type === "role_ok") {
          setStatus("ready (" + msg.role + ")");
          if (msg.role === "send") {
            try { await startSenderLoop(); } catch (e) { alert(String(e)); }
          }
          return;
        }

        if (msg.type === "role_denied") {
          alert("Senden nicht möglich: Es gibt bereits einen Sender in dieser Gruppe.");
          setStatus("watch only");
          return;
        }

        if (msg.type === "ping") {
          try { ws.send(JSON.stringify({ type: "pong" })); } catch {}
          return;
        }

        return;
      }

      if (evt.data instanceof ArrayBuffer) {
        setRemoteFromBuffer(evt.data);
      }
    };
  }

  btnGo.onclick = () => connect();
  btnHang.onclick = () => { stopSender(); cleanupWs(); setStatus("offline"); };

  setInterval(() => {
    if (!ws) return;
    if (ws.readyState === 2 || ws.readyState === 3) {
      log("reconnect...");
      stopSender();
      connect();
    }
  }, 3000);

  setStatus("offline");
})();
</script>
</body>
</html>`;

// ---------------------------
// Worker helper: routing
// ---------------------------
function roomFromReq(req) {
  const url = new URL(req.url);
  return (url.searchParams.get("room") || "default").slice(0, 64);
}

export async function handleWebcamLive(req, env) {
  const url = new URL(req.url);

  if (url.pathname === "/webcam-live/groups") {
    if (!env.LOBBY) return new Response("Missing DO binding: LOBBY", { status: 500 });
    const lobbyId = env.LOBBY.idFromName("global");
    const lobby = env.LOBBY.get(lobbyId);
    return lobby.fetch("https://internal/webcam-live/groups", req);
  }

  if (url.pathname === "/webcam-live/ws") {
    if (!env.STREAM) return new Response("Missing DO binding: STREAM", { status: 500 });
    const room = roomFromReq(req);
    const id = env.STREAM.idFromName("room:" + room);
    const stub = env.STREAM.get(id);
    return stub.fetch(req);
  }

  if (url.pathname === "/webcam-live/room") {
    return new Response(HTML_ROOM, {
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    });
  }

  return new Response(HTML_LOBBY, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}
