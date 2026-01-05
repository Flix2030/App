// src/webcam.js
// Option C: Stabiler "Livebild"-Stream ohne WebRTC.
// Technik: Sender macht JPEG-Frames -> WebSocket -> Durable Object -> Zuschauer bekommen Frames (binär).
// Latenz: typisch 0.3–2s je nach FPS/Netz. Funktioniert auch über Mobilfunk/verschiedene Netze.

export class STREAM {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    /** @type {Map<string, {ws: WebSocket, role: "send"|"watch"}>} */
    this.clients = new Map();
    /** @type {ArrayBuffer|null} */
    this.lastFrame = null;
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const client = pair[1];
    const server = pair[0];

    const id = crypto.randomUUID();
    server.accept();

    // default role until we get "hello"
    this.clients.set(id, { ws: server, role: "watch" });

    const sendText = (ws, obj) => { try { ws.send(JSON.stringify(obj)); } catch {} };
    const sendBin = (ws, buf) => { try { ws.send(buf); } catch {} };

    // greet
    sendText(server, { type: "hello", id });

    // If we already have a frame, send it to new watchers after they say role=watch.
    server.addEventListener("message", (evt) => {
      const c = this.clients.get(id);
      if (!c) return;

      // Text message: role selection / ping
      if (typeof evt.data === "string") {
        let msg = null;
        try { msg = JSON.parse(evt.data); } catch { return; }
        if (!msg || typeof msg !== "object") return;

        if (msg.type === "role" && (msg.role === "send" || msg.role === "watch")) {
          c.role = msg.role;
          this.clients.set(id, c);

          sendText(server, { type: "role_ok", role: c.role });

          // If watcher joins and we have a last frame -> send it
          if (c.role === "watch" && this.lastFrame) {
            sendBin(server, this.lastFrame);
          }
          return;
        }

        if (msg.type === "ping") {
          sendText(server, { type: "pong" });
          return;
        }

        return;
      }

      // Binary message: frame from sender
      // Cloudflare delivers binary WS as ArrayBuffer
      const buf = evt.data; // ArrayBuffer
      if (!(buf instanceof ArrayBuffer)) return;

      // store last frame
      this.lastFrame = buf;

      // broadcast to watchers
      for (const [otherId, other] of this.clients.entries()) {
        if (otherId === id) continue;
        if (other.role !== "watch") continue;
        sendBin(other.ws, buf);
      }
    });

    const cleanup = () => {
      this.clients.delete(id);
    };
    server.addEventListener("close", cleanup);
    server.addEventListener("error", cleanup);

    return new Response(null, { status: 101, webSocket: client });
  }
}

const HTML_LIVE = `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>Livebild (stabil) – Webcam</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#0b0b0c; color:#fff; }
    .wrap { max-width: 920px; margin: 0 auto; padding: 16px; }
    .card { background:#141417; border:1px solid #24242a; border-radius: 14px; padding: 14px; }
    input, button, select { font-size: 16px; }
    input { width: 100%; padding: 10px 12px; border-radius: 12px; border:1px solid #2a2a33; background:#0f0f13; color:#fff; outline:none; }
    button { padding: 10px 12px; border-radius: 12px; border:1px solid #2a2a33; background:#1b1b22; color:#fff; cursor:pointer; }
    button:hover { filter: brightness(1.1); }
    .row { display:flex; gap:10px; align-items:center; }
    .row > * { flex: 1; }
    .grid { display:grid; grid-template-columns: 1fr; gap: 12px; margin-top: 12px; }
    @media(min-width: 860px){ .grid { grid-template-columns: 1fr 1fr; } }
    video, img { width:100%; background:#000; border-radius: 14px; border:1px solid #24242a; aspect-ratio: 16/9; object-fit: cover; }
    .small { opacity:.85; font-size: 13px; line-height: 1.35; }
    .log { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; background:#0f0f13; border:1px solid #24242a; border-radius: 14px; padding: 10px; height: 140px; overflow:auto; }
    .badge { display:inline-block; padding: 2px 8px; border-radius: 999px; border:1px solid #2a2a33; background:#101017; font-size: 12px; }
    .hint { margin-top: 8px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="badge" id="status">offline</div>
      <h2 style="margin:10px 0 6px;">Livebild (stabil, ohne WebRTC)</h2>
      <div class="small hint">
        Funktioniert auch über Mobilfunk/verschiedene Netze. Latenz hängt von FPS/Netz ab.<br/>
        Tipp: Sender nutzt am besten WLAN + Handy ans Ladegerät.
      </div>

      <div style="height:10px"></div>

      <div class="row">
        <div>
          <label class="small">Room</label>
          <input id="room" placeholder="room-name" />
        </div>
        <div style="max-width: 240px;">
          <label class="small">Modus</label>
          <select id="mode" style="width:100%; padding:10px 12px; border-radius:12px; border:1px solid #2a2a33; background:#0f0f13; color:#fff;">
            <option value="send">send (Kamera)</option>
            <option value="watch">watch (Zuschauer)</option>
          </select>
        </div>
      </div>

      <div style="height:10px"></div>

      <div class="row">
        <button id="btnGo">Verbinden</button>
        <button id="btnHang">Trennen</button>
      </div>

      <div class="grid">
        <div>
          <div class="small" style="margin-bottom:6px;">Local (nur Sender)</div>
          <video id="local" playsinline muted autoplay></video>
        </div>
        <div>
          <div class="small" style="margin-bottom:6px;">Remote (Livebild)</div>
          <img id="remote" alt="Remote" />
        </div>
      </div>

      <div style="height:12px"></div>
      <div class="small">Einstellungen (nur Sender):</div>
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
          <label class="small">Qualität (0.3–0.9)</label>
          <input id="q" type="number" min="0.3" max="0.95" step="0.05" value="0.7" />
        </div>
      </div>

      <div style="height:12px"></div>
      <div class="log" id="log"></div>
    </div>
  </div>

<script>
(() => {
  const $ = (id) => document.getElementById(id);
  const roomEl = $("room");
  const modeEl = $("mode");
  const statusEl = $("status");
  const logEl = $("log");
  const localV = $("local");
  const remoteImg = $("remote");
  const btnGo = $("btnGo");
  const btnHang = $("btnHang");
  const fpsEl = $("fps");
  const wEl = $("w");
  const qEl = $("q");

  const params = new URLSearchParams(location.search);
  if (params.get("room")) roomEl.value = params.get("room");
  if (params.get("mode")) modeEl.value = params.get("mode");

  const log = (...a) => {
    const line = a.map(x => typeof x === "string" ? x : JSON.stringify(x)).join(" ");
    logEl.textContent += line + "\\n";
    logEl.scrollTop = logEl.scrollHeight;
  };

  let ws = null;
  let localStream = null;
  let sendTimer = null;
  let lastUrl = null;

  function setStatus(s) { statusEl.textContent = s; }

  function wsUrl(room) {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    return proto + "//" + location.host + "/webcam-live/ws?room=" + encodeURIComponent(room);
  }

  function blobToArrayBuffer(blob) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = reject;
      r.readAsArrayBuffer(blob);
    });
  }

  async function startSender(room) {
    const width = Math.max(160, Math.min(1280, parseInt(wEl.value || "640", 10) || 640));
    const fps = Math.max(1, Math.min(15, parseInt(fpsEl.value || "4", 10) || 4));
    const quality = Math.max(0.3, Math.min(0.95, parseFloat(qEl.value || "0.7") || 0.7));

    localStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
      audio: false
    });

    localV.srcObject = localStream;

    const videoTrack = localStream.getVideoTracks()[0];
    const settings = videoTrack.getSettings ? videoTrack.getSettings() : {};
    log("camera:", settings.width, "x", settings.height);

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { alpha: false });

    // wait for video metadata
    await new Promise((res) => {
      if (localV.readyState >= 2) return res();
      localV.onloadedmetadata = () => res();
    });

    const srcW = localV.videoWidth || 1280;
    const srcH = localV.videoHeight || 720;
    const height = Math.round(width * (srcH / srcW));
    canvas.width = width;
    canvas.height = height;

    const intervalMs = Math.round(1000 / fps);
    log("send:", fps, "fps", width + "x" + height, "q=" + quality);

    let running = true;
    sendTimer = { stop: () => (running = false) };

    const loop = async () => {
      while (running) {
        if (!ws || ws.readyState !== 1) { await new Promise(r => setTimeout(r, 200)); continue; }
        if (!localV || localV.readyState < 2) { await new Promise(r => setTimeout(r, 100)); continue; }

        try {
          ctx.drawImage(localV, 0, 0, width, height);
          const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", quality));
          if (!blob) { await new Promise(r => setTimeout(r, 50)); continue; }
          const buf = await blobToArrayBuffer(blob);
          ws.send(buf);
        } catch (e) {
          // Safari wirft hier gerne InvalidStateError -> kurz warten und weiter
        }

        await new Promise(r => setTimeout(r, intervalMs));
      }
    };
    loop();

  function stopSender() {
    if (sendTimer?.stop) sendTimer.stop();
    sendTimer = null;
    if (localStream) {
      for (const t of localStream.getTracks()) try { t.stop(); } catch {}
    }
    localStream = null;
    localV.srcObject = null;
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

  async function start() {
    const room = (roomEl.value || "").trim();
    const mode = modeEl.value;
    if (!room) { alert("Room fehlt"); return; }

    const u = new URL(location.href);
    u.searchParams.set("room", room);
    u.searchParams.set("mode", mode);
    history.replaceState(null, "", u.toString());

    await hangup();

    ws = new WebSocket(wsUrl(room));
    ws.binaryType = "arraybuffer";

    ws.onopen = () => {
      setStatus("signaling online");
      ws.send(JSON.stringify({ type: "role", role: mode }));
      log("WS open");
    };

    ws.onclose = () => { setStatus("offline"); log("WS close"); };
    ws.onerror = () => { log("WS error"); };

    ws.onmessage = async (evt) => {
      if (typeof evt.data === "string") {
        let msg = null;
        try { msg = JSON.parse(evt.data); } catch { return; }
        if (msg?.type === "hello") return;
        if (msg?.type === "role_ok") {
          setStatus("ready (" + msg.role + ")");
          if (msg.role === "send") {
            try { await startSender(room); } catch (e) { alert(String(e)); }
          } else {
            stopSender();
          }
        }
        return;
      }
      // binary frame
      if (evt.data instanceof ArrayBuffer) setRemoteFromBuffer(evt.data);
    };
  }

  async function hangup() {
    stopSender();
    if (ws) { try { ws.close(); } catch {} }
    ws = null;
    setStatus("offline");
  }

  btnGo.onclick = () => start().catch(e => alert(String(e)));
  btnHang.onclick = () => hangup();

  setStatus("offline");
})();
</script>
</body>
</html>`;

function roomIdFromRequest(req) {
  const url = new URL(req.url);
  return (url.searchParams.get("room") || "default").slice(0, 64);
}

export async function handleWebcamLive(req, env) {
  const url = new URL(req.url);

  if (url.pathname === "/webcam-live/ws") {
    if (!env.STREAM) return new Response("Missing Durable Object binding: STREAM", { status: 500 });
    const room = roomIdFromRequest(req);
    const id = env.STREAM.idFromName("room:" + room);
    const stub = env.STREAM.get(id);
    return stub.fetch(req);
  }

  return new Response(HTML_LIVE, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    }
  });
}
