// src/webcam.js
// WebRTC Kamera-Demo: Handy A (send) -> Handy B (watch)
// Signaling via Durable Object (WebSocket). STUN-only (für Mobilfunk oft TURN nötig).

export class SIGNAL {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.clients = new Map(); // clientId -> WebSocket
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const client = pair[1];
    const server = pair[0];

    const clientId = crypto.randomUUID();
    server.accept();
    this.clients.set(clientId, server);

    const send = (ws, obj) => { try { ws.send(JSON.stringify(obj)); } catch {} };

    send(server, { type: "hello", clientId, peers: this.clients.size - 1 });

    server.addEventListener("message", (evt) => {
      let msg;
      try { msg = JSON.parse(evt.data); } catch { return; }
      if (!msg || typeof msg !== "object") return;

      // simple broadcast to other peers in same room
      for (const [id, ws] of this.clients.entries()) {
        if (id === clientId) continue;
        send(ws, { ...msg, _from: clientId });
      }
    });

    const cleanup = () => {
      this.clients.delete(clientId);
      for (const ws of this.clients.values()) {
        send(ws, { type: "peer_left", clientId });
      }
    };

    server.addEventListener("close", cleanup);
    server.addEventListener("error", cleanup);

    return new Response(null, { status: 101, webSocket: client });
  }
}

const HTML = `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>WebRTC Kamera Demo</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#0b0b0c; color:#fff; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 16px; }
    .card { background:#141417; border:1px solid #24242a; border-radius: 14px; padding: 14px; }
    input, button, select { font-size: 16px; }
    input { width: 100%; padding: 10px 12px; border-radius: 12px; border:1px solid #2a2a33; background:#0f0f13; color:#fff; outline:none; }
    button { padding: 10px 12px; border-radius: 12px; border:1px solid #2a2a33; background:#1b1b22; color:#fff; cursor:pointer; }
    button:hover { filter: brightness(1.1); }
    .row { display:flex; gap:10px; align-items:center; }
    .row > * { flex: 1; }
    .grid { display:grid; grid-template-columns: 1fr; gap: 12px; margin-top: 12px; }
    @media(min-width: 860px){ .grid { grid-template-columns: 1fr 1fr; } }
    video { width:100%; background:#000; border-radius: 14px; border:1px solid #24242a; aspect-ratio: 16/9; }
    .small { opacity:.85; font-size: 13px; line-height: 1.35; }
    .log { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; background:#0f0f13; border:1px solid #24242a; border-radius: 14px; padding: 10px; height: 150px; overflow:auto; }
    .badge { display:inline-block; padding: 2px 8px; border-radius: 999px; border:1px solid #2a2a33; background:#101017; font-size: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="badge" id="status">offline</div>
      <h2 style="margin:10px 0 6px;">Kamera → anderes Handy (WebRTC)</h2>
      <div class="small">
        1) Room eingeben (z.B. <b>flix</b>)<br/>
        2) Handy A: <b>send</b> + Verbinden<br/>
        3) Handy B: <b>watch</b> + Verbinden<br/>
        Hinweis: Mobilfunk kann ohne TURN scheitern.
      </div>

      <div style="height:10px"></div>

      <div class="row">
        <div>
          <label class="small">Room</label>
          <input id="room" placeholder="room-name" />
        </div>
        <div style="max-width: 220px;">
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
          <div class="small" style="margin-bottom:6px;">Local</div>
          <video id="local" playsinline muted autoplay></video>
        </div>
        <div>
          <div class="small" style="margin-bottom:6px;">Remote</div>
          <video id="remote" playsinline autoplay></video>
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
  const remoteV = $("remote");
  const btnGo = $("btnGo");
  const btnHang = $("btnHang");

  const params = new URLSearchParams(location.search);
  if (params.get("room")) roomEl.value = params.get("room");
  if (params.get("mode")) modeEl.value = params.get("mode");

  const log = (...a) => {
    const line = a.map(x => typeof x === "string" ? x : JSON.stringify(x)).join(" ");
    logEl.textContent += line + "\\n";
    logEl.scrollTop = logEl.scrollHeight;
  };

  let ws = null;
  let pc = null;
  let localStream = null;

  function setStatus(s) { statusEl.textContent = s; }

  function wsUrl(room) {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    return proto + "//" + location.host + "/webcam/ws?room=" + encodeURIComponent(room);
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
    ws.onopen = () => setStatus("signaling online");
    ws.onclose = () => setStatus("offline");

    pc = new RTCPeerConnection({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" }
      ]
    });

    pc.onicecandidate = (e) => {
      if (e.candidate && ws?.readyState === 1) {
        ws.send(JSON.stringify({ type: "ice", candidate: e.candidate }));
      }
    };

    pc.onconnectionstatechange = () => setStatus("pc: " + pc.connectionState);

    pc.ontrack = (e) => {
      if (remoteV.srcObject !== e.streams[0]) remoteV.srcObject = e.streams[0];
    };

    ws.onmessage = async (evt) => {
      let msg;
      try { msg = JSON.parse(evt.data); } catch { return; }

      if (msg.type === "hello") {
        setStatus("ready (" + mode + ")");
        return;
      }

      if (msg.type === "offer") {
        await pc.setRemoteDescription(msg.sdp);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        ws.send(JSON.stringify({ type: "answer", sdp: pc.localDescription }));
        return;
      }

      if (msg.type === "answer") {
        await pc.setRemoteDescription(msg.sdp);
        return;
      }

      if (msg.type === "ice" && msg.candidate) {
        try { await pc.addIceCandidate(msg.candidate); } catch {}
      }
    };

    if (mode === "send") {
      localStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false
      });
      localV.srcObject = localStream;
      for (const track of localStream.getTracks()) pc.addTrack(track, localStream);

      const offer = await pc.createOffer({ offerToReceiveVideo: true });
      await pc.setLocalDescription(offer);
      ws.send(JSON.stringify({ type: "offer", sdp: pc.localDescription }));
      log("offer sent");
    } else {
      log("watching...");
    }
  }

  async function hangup() {
    try { if (ws) ws.close(); } catch {}
    ws = null;

    try { if (pc) pc.close(); } catch {}
    pc = null;

    if (localStream) {
      for (const t of localStream.getTracks()) try { t.stop(); } catch {}
    }
    localStream = null;

    localV.srcObject = null;
    remoteV.srcObject = null;
    setStatus("offline");
  }

  btnGo.onclick = () => start().catch(e => alert(String(e)));
  btnHang.onclick = () => hangup();
})();
</script>
</body>
</html>`;

function roomIdFromRequest(req) {
  const url = new URL(req.url);
  return (url.searchParams.get("room") || "default").slice(0, 64);
}

export async function handleWebcam(req, env) {
  const url = new URL(req.url);

  // WebSocket endpoint => Durable Object room
  if (url.pathname === "/webcam/ws") {
    if (!env.SIGNAL) return new Response("Missing Durable Object binding: SIGNAL", { status: 500 });
    const room = roomIdFromRequest(req);
    const id = env.SIGNAL.idFromName(room);
    const stub = env.SIGNAL.get(id);
    return stub.fetch(req);
  }

  // Page
  return new Response(HTML, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    }
  });
}
