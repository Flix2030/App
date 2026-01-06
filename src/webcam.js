// src/webcam.js
// ✅ Kostenlos + stabil über verschiedene Netze (auch Mobile Daten) – ohne WebRTC
// ✅ Mit Gruppenliste: Besucher sehen aktive "LIVE"-Gruppen und können nur zuschauen.
// ✅ Pro Gruppe nur 1 Sender (weitere Sender werden abgelehnt)
//
// Worker-Routen (müssen im src/worker.js VOR dem Login-Gate abgefangen werden):
// - GET  /webcam-live                 -> Lobby UI (aktive Gruppen + neue Gruppe)
// - GET  /webcam-live/room            -> Room UI (send/watch)
// - GET  /webcam-live/groups          -> JSON Liste aktiver Gruppen
// - WS   /webcam-live/ws?room=NAME    -> STREAM WebSocket (Frames + Control)
//
// wrangler.jsonc:
// durable_objects.bindings: [{name:"LOBBY", class_name:"LOBBY"}, {name:"STREAM", class_name:"STREAM"}]
// migrations (Free plan): new_sqlite_classes für beide Klassen

// ---------------------------
// Durable Object: LOBBY (global)
// ---------------------------
export class LOBBY {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.code = null;
    this.adminName = null;
    this.senderName = null;
    this.approvedSender = null;
  }

  async _load() {
    if (this._loaded) return;
    this._loaded = true;
    const s = await this.state.storage.get("meta");
    if (s && typeof s === "object") {
      this.code = s.code || null;
      this.adminName = s.adminName || null;
      this.senderName = s.senderName || null;
      this.approvedSender = s.approvedSender || null;
    }
  }

  async _save() {
    await this.state.storage.put("meta", {
      code: this.code,
      adminName: this.adminName,
      senderName: this.senderName,
      approvedSender: this.approvedSender,
    });
  }

  _sockets() {
    try { return this.state.getWebSockets(); } catch { return []; }
  }

  _broadcast(obj) {
    const msg = JSON.stringify(obj);
    for (const ws of this._sockets()) {
      try { ws.send(msg); } catch {}
    }
  }

  _participants() {
    const names = new Set();
    for (const ws of this._sockets()) {
      try {
        const a = ws.deserializeAttachment?.() || null;
        if (a && a.name) names.add(a.name);
      } catch {}
    }
    return Array.from(names);
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
        if ((now - (info.lastSeen || 0)) > 120000) { // 2 min stale -> offline
          info.senderOnline = false;
          info.viewers = info.viewers || 0;
          changed = true;
        }
      }

      if (changed) await this.state.storage.put(key, rooms);
      return rooms;
    };

    // GET /groups -> list active rooms
    if (path.endsWith("/groups") && request.method === "GET") {
      const rooms = await loadRooms();
      const list = Object.entries(rooms)
        .filter(([_, r]) => r && r.senderOnline)
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

    // internal: POST /touch {room, senderOnline, viewers}
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
    this.code = null;
    this.adminName = null;
    this.senderName = null;
    this.approvedSender = null;

    this.senderId = null;
    this.clients = new Map(); // id -> { ws, role }
    this.lastFrame = null; // ArrayBuffer (JPEG)
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

    const providedCode = String(url.searchParams.get("code") || "").trim();
    const codeOk = (c) => typeof c === "string" && c.length >= 4 && c.length <= 32;
    const sha256Hex = async (str) => {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
      return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
    };
    const getStoredHash = async () => (await this.state.storage.get("codeHash")) || "";


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

    // Keepalive ping (hilft auf manchen Mobilfunknetzen)
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

      // Text messages
      if (typeof evt.data === "string") {
        let msg = null;
        try { msg = JSON.parse(evt.data); } catch { return; }
        if (!msg || typeof msg !== "object") return;

        if (msg.type === "role") {
          const role = msg.role === "send" ? "send" : "watch";
          const storedHash = await getStoredHash();
          if (!codeOk(providedCode)) {
            sendText(server, { type: "role_denied", reason: "code_required" });
            return;
          }
          const providedHash = await sha256Hex(providedCode);

          if (role === "send") {
            if (storedHash) {
              if (storedHash !== providedHash) {
                sendText(server, { type: "role_denied", reason: "wrong_code" });
                return;
              }
            } else {
              await this.state.storage.put("codeHash", providedHash);
            }
            // only one sender allowed
            if (this.senderId && this.senderId !== id && this.clients.has(this.senderId)) {
              sendText(server, { type: "role_denied", reason: "sender_exists" });
              return;
            }
            this.senderId = id;
            c.role = "send";
      try { ws.serializeAttachment({ name, role: "send" }); } catch {}
            this.clients.set(id, c);
            sendText(server, { type: "role_ok", role: "send" });
            await touchLobby();
            return;
          }

          // watch
          if (!storedHash) {
            sendText(server, { type: "role_denied", reason: "code_not_set" });
            return;
          }
          if (storedHash !== providedHash) {
            sendText(server, { type: "role_denied", reason: "wrong_code" });
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

        if (msg.type === "participants") {
          refreshGrantList(msg.names || []);
          return;
        }
        if (msg.type === "admin_ok") {
          log("admin: ok");
          return;
        }
        if (msg.type === "kicked") {
          alert("Du wurdest als Sender gestoppt.");
          stopSender();
          cleanupWs();
          setStatus("offline");
          return;
        }

        return;
      }

      // Binary frame
      if (!(evt.data instanceof ArrayBuffer)) return;

      if (id !== this.senderId) {
        sendText(server, { type: "frame_denied" });
        return;
      }

      this.lastFrame = evt.data;

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
// UI HTML (wichtig: keine ${} in Template-Strings!)
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
    .row.row-right > * { flex: 0 0 auto !important; }
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
      <div class="row row-right" style="margin-bottom:10px; justify-content:flex-end;">
        <button type="button" onclick="location.href='/home'">🏠 Home</button>
      </div>
      <h2 style="margin: 0 0 6px;">Aktive Gruppen</h2>
      <div class="small">Hier siehst du Gruppen, in denen gerade jemand live sendet.</div>
      <div class="list" id="list"></div>
      <div class="small" style="margin-top:10px;">Auto-Refresh: alle 3 Sekunden</div>
    </div>

    <div class="card">
      <h2 style="margin: 0 0 6px;">Neue Gruppe erstellen</h2>
      <div class="row">
        <input id="room" placeholder="Gruppenname (z.B. flix)" />
        <button id="create" type="button" onclick="__createRoom()">Erstellen & Senden</button>
      </div>
      <div class="row" style="margin-top:10px;">
        <input id="code" placeholder="Gruppen-Code (mind. 4 Zeichen)" />
      </div>
      <div class="row" style="margin-top:10px;">
        <input id="name" placeholder="Dein Name (für Admin/Chat)" />
      </div>
      <div class="small" style="margin-top:10px;">
        Tipp: FPS 2–4, Breite 480/640, Qualität 0.5–0.7 (in der Gruppe einstellbar).
      </div>
    </div>
  </div>

<script>
(function(){
  var listEl = document.getElementById("list");
  var roomEl = document.getElementById("room");
  var codeEl = document.getElementById("code");
  var nameEl = document.getElementById("name");

  function getNameOrAsk(){
    var n = (nameEl && nameEl.value ? nameEl.value : "").trim();
    if (!n) n = (sessionStorage.getItem("webcam_name") || "").trim();
    if (!n) n = prompt("Bitte gib deinen Namen ein:") || "";
    n = String(n).trim();
    if (n) sessionStorage.setItem("webcam_name", n);
    return n;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);
    });
  }

  window.__createRoom = function(){
    try {
      var room = (roomEl && roomEl.value ? roomEl.value : "").trim();
      if (!room) return alert("Gruppenname fehlt");

      var code = (codeEl && codeEl.value ? codeEl.value : "").trim();
      if (!code) return alert("Code fehlt");
      if (code.length < 4) return alert("Code zu kurz (mind. 4 Zeichen)");

      var name = getNameOrAsk();
      if (!name) return alert("Name fehlt");
      location.href = "/webcam-live/room?room=" + encodeURIComponent(room) + "&mode=send&code=" + encodeURIComponent(code) + "&name=" + encodeURIComponent(name) + "&admin=1";
    } catch (e) {
      alert("Create-Fehler: " + (e && e.message ? e.message : e));
    }
  };

  window.__watchRoom = function(room){
    var name = getNameOrAsk();
    if (!name) return alert("Name fehlt");
    location.href = "/webcam-live/room?room=" + encodeURIComponent(room) + "&mode=watch&name=" + encodeURIComponent(name);
  };

  function render(rooms) {
    if (!rooms || !rooms.length) {
      listEl.innerHTML = '<div class="small">Keine aktiven Gruppen.</div>';
      return;
    }
    var html = "";
    for (var i=0;i<rooms.length;i++){
      var r = rooms[i];
      var room = String(r.room || "");
      var viewers = Number(r.viewers || 0);
      html += ''
        + '<div class="item">'
        +   '<div>'
        +     '<div><b>' + escapeHtml(room) + '</b> <span class="badge">LIVE</span></div>'
        +     '<div class="small">Zuschauer: ' + viewers + '</div>'
        +   '</div>'
        +   '<div>'
        +     '<button type="button" onclick="__watchRoom(' + "'" + room.replace(/'/g,"\'") + "'" + ')">Zuschauen</button>'
        +   '</div>'
        + '</div>';
    }
    listEl.innerHTML = html;
  }

  async function load(){
    try {
      var r = await fetch("/webcam-live/groups", { cache: "no-store" });
      var j = await r.json();
      render(j.rooms || []);
    } catch (e) {
      listEl.innerHTML = '<div class="small">Fehler beim Laden.</div>';
    }
  }

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
    .row.row-right > * { flex: 0 0 auto !important; }
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
        <button id="btnGo" type="button" onclick="__connectNow()">Verbinden</button>
        <button id="btnHang" type="button" onclick="__disconnectNow()">Trennen</button>
      </div>

      <div id="adminPanel" class="card" style="margin-top:14px; display:none;">
        <h3 style="margin:0 0 8px;">Admin</h3>
        <div class="small" style="margin-bottom:8px;">Nur du kannst freigeben, wer senden darf (immer nur 1 gleichzeitig).</div>
        <div class="row">
          <select id="grantSelect"></select>
          <button id="btnGrant" type="button">Senden erlauben</button>
          <button id="btnKick" type="button">Sender stoppen</button>
        </div>
      </div>

      <div class="log" id="log"></div>
    </div>
  </div>

<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };

  var statusEl = $("status");
  var logEl = $("log");
  var localV = $("local");
  var remoteImg = $("remote");
  var btnGo = $("btnGo");
  var btnHang = $("btnHang");  var localBox = $("localBox");
  var params = new URLSearchParams(location.search);
  var room = (params.get("room") || "").trim() || "default";
  var mode = (params.get("mode") || "watch") === "send" ? "send" : "watch";

  // ✅ Code bei jedem Join (oder via URL)
  var codeFromUrl = (params.get("code") || "").trim();
  var code = codeFromUrl || prompt("Bitte Code für diese Gruppe eingeben:");
  if (!code || String(code).trim().length < 4) {
    alert("Ungültiger Code (mind. 4 Zeichen).");
    location.href = "/webcam-live";
    return;
  }
  code = String(code).trim();

  $("roomName").textContent = room;
  $("modeName").textContent = mode;

  if (mode !== "send") {
    localBox.style.display = "none";
  }

  function log() {
    var line = "";
    for (var i = 0; i < arguments.length; i++) {
      var x = arguments[i];
      line += (typeof x === "string" ? x : JSON.stringify(x)) + " ";
    }
    logEl.textContent += line.trim() + "\\n";
    logEl.scrollTop = logEl.scrollHeight;
  }

  var ws = null;
  var localStream = null;
  var running = false;
  var lastUrl = null;

  function refreshGrantList(list){
    if (!grantSelect) return;
    var me = name;
    var opts = (list || []).filter(function(x){ return x && x !== me; });
    grantSelect.innerHTML = opts.map(function(n){ return "<option value=\"" + n.replace(/"/g,"&quot;") + "\">" + n + "</option>"; }).join("") || "<option value=\"\">(keine)</option>";
  }

  if (adminPanel) {
    if (adminFlag && mode === "watch") adminPanel.style.display = "";
  }

  if (btnGrant) {
    btnGrant.onclick = function(){
      if (!ws || ws.readyState !== 1) return alert("Nicht verbunden.");
      var target = (grantSelect && grantSelect.value ? grantSelect.value : "").trim();
      if (!target) return alert("Niemand ausgewählt.");
      ws.send(JSON.stringify({ type: "admin_grant", target: target }));
    };
  }
  if (btnKick) {
    btnKick.onclick = function(){
      if (!ws || ws.readyState !== 1) return alert("Nicht verbunden.");
      ws.send(JSON.stringify({ type: "admin_kick" }));
    };
  }

function setStatus(s) { statusEl.textContent = s; }

  function wsUrl() {
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    return proto + "//" + location.host + "/webcam-live/ws?room=" + encodeURIComponent(room) + "&code=" + encodeURIComponent(code);
  }

  // ✅ Globale Handler für die Buttons
  window.__connectNow = function () {
    try { log("click: verbinden"); connect(); }
    catch (e) { alert("Connect-Fehler: " + (e && e.message ? e.message : e)); }
  };
  window.__disconnectNow = function () {
    try { log("click: trennen"); stopSender(); cleanupWs(); setStatus("offline"); }
    catch (e) {}
  };


  function setRemoteFromBuffer(buf) {
    try {
      var blob = new Blob([buf], { type: "image/jpeg" });
      var url = URL.createObjectURL(blob);
      remoteImg.src = url;
      if (lastUrl) URL.revokeObjectURL(lastUrl);
      lastUrl = url;
    } catch {}
  }

  async function startSenderLoop() {
    // 🔥 Beste feste Einstellungen (kein UI)
    var width = 1280;      // HD
    var fps = 15;          // max stabil
    var quality = 0.95;    // maximale Qualität
    var intervalMs = Math.round(1000 / fps);

    localStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
      audio: false
    });
    localV.srcObject = localStream;

    var canvas = document.createElement("canvas");
    var ctx = canvas.getContext("2d", { alpha: false });

    await new Promise(function (res) {
      if (localV.readyState >= 2) return res();
      localV.onloadedmetadata = function () { res(); };
    });

    var srcW = localV.videoWidth || 1280;
    var srcH = localV.videoHeight || 720;
    var height = Math.round(width * (srcH / srcW));
    canvas.width = width;
    canvas.height = height;

    log("send:", fps, "fps", width + "x" + height, "q=" + quality);

    function blobToArrayBuffer(blob) {
      return new Promise(function (resolve, reject) {
        var r = new FileReader();
        r.onload = function () { resolve(r.result); };
        r.onerror = reject;
        r.readAsArrayBuffer(blob);
      });
    }

    running = true;

    while (running) {
      if (!ws || ws.readyState !== 1) { await new Promise(r => setTimeout(r, 200)); continue; }
      if (!localV || localV.readyState < 2) { await new Promise(r => setTimeout(r, 100)); continue; }

      try {
        ctx.drawImage(localV, 0, 0, width, height);
        var blob = await new Promise(function (resolve) { canvas.toBlob(resolve, "image/jpeg", quality); });
        if (blob) {
          var buf = await blobToArrayBuffer(blob);
          ws.send(buf);
        }
      } catch {}

      await new Promise(r => setTimeout(r, intervalMs));
    }
  }

  function stopSender() {
    running = false;
    if (localStream) {
      var tracks = localStream.getTracks();
      for (var i = 0; i < tracks.length; i++) { try { tracks[i].stop(); } catch {} }
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

    ws.onopen = function () {
      setStatus("connected");
      ws.send(JSON.stringify({ type: "role", role: mode }));
      log("WS open");
    };

    ws.onclose = function () { setStatus("offline"); log("WS close"); };
    ws.onerror = function () { log("WS error"); };

    ws.onmessage = async function (evt) {
      if (typeof evt.data === "string") {
        var msg = null;
        try { msg = JSON.parse(evt.data); } catch { return; }

        if (msg.type === "role_ok") {
          setStatus("ready (" + msg.role + ")");
          if (msg.role === "send") {
            try { await startSenderLoop(); } catch (e) { alert(String(e)); }
          }
          return;
        }

        if (msg.type === "role_denied") {
          var reason = msg.reason || "denied";
          if (reason === "sender_exists") alert("Senden nicht möglich: Es gibt bereits einen Sender in dieser Gruppe.");
          else if (reason === "wrong_code") alert("Falscher Code.");
          else if (reason === "code_required") alert("Code fehlt.");
          else if (reason === "code_not_set") alert("Für diese Gruppe ist noch kein Code gesetzt (Sender muss zuerst verbinden).");
          else alert("Zugriff verweigert.");
          setStatus("offline");
          try { ws.close(); } catch {}
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
// Auto-Reconnect
  setInterval(function () {
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
    const name = (url.searchParams.get("name") || "").trim();
    const admin = (url.searchParams.get("admin") || "0");
  return (url.searchParams.get("room") || "default").slice(0, 64);
}

export async function handleWebcamLive(req, env) {
  const url = new URL(req.url);
    const name = (url.searchParams.get("name") || "").trim();
    const admin = (url.searchParams.get("admin") || "0");

  if (url.pathname === "/webcam-live/groups") {
    if (!env.LOBBY) return new Response("Missing DO binding: LOBBY", { status: 500 });
    const lobbyId = env.LOBBY.idFromName("global");
    const lobby = env.LOBBY.get(lobbyId);
    return lobby.fetch(new Request("https://internal/webcam-live/groups", req));
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

  // default lobby UI
  return new Response(HTML_LOBBY, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}
