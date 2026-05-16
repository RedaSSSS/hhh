#!/usr/bin/env python3
"""
================================================================
  COMMAND SERVER — Raspberry Pi 3
  Search & Rescue Proof of Concept
================================================================
  Flask application providing:
    1. Captive Portal  → redirects all HTTP to the SOS page
    2. SOS Form        → victims submit name + status message
    3. UDP Receiver    → background thread listens for ESP32
                         probe-request sniff reports (MAC|RSSI)
    4. SQLite DB       → persists both SOS messages and sniff data
    5. Dashboard       → read-only view of all collected data
       (accessible from the operator's laptop on the same LAN)

  Install dependencies:
    pip3 install flask

  Run (as root for port 80):
    sudo python3 server.py

  Or run on port 8080 and use iptables to redirect:
    sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
    python3 server.py --port 8080
================================================================
"""

import sqlite3
import socket
import threading
import datetime
import argparse
import os
import sys
from flask import Flask, request, redirect, jsonify, g

# ─── CONFIG ──────────────────────────────────────────────────
DB_PATH       = "/var/db/rescue.db"       # Persistent database path
UDP_LISTEN_IP = "0.0.0.0"
UDP_PORT      = 5005
FLASK_PORT    = 443                        # Use 8080 if not running as root
PI_AP_IP      = "10.0.0.1"               # Pi 3's own IP on its hotspot network
                                          # Change to match your Pi's actual IP

# ─── DATABASE ────────────────────────────────────────────────
def get_db():
    """Return a per-request SQLite connection (stored on Flask's g object)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    """Create tables if they don't exist. Called once at startup."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sos_messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT,
            message    TEXT NOT NULL,
            ip_addr    TEXT,
            timestamp  TEXT DEFAULT (datetime('now','localtime'))
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS probe_sightings (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            mac       TEXT NOT NULL,
            rssi      INTEGER NOT NULL,
            source_ip TEXT,
            timestamp TEXT DEFAULT (datetime('now','localtime'))
        )
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Database initialised at {DB_PATH}")

# ─── FLASK APP ───────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "rescue_poc_2024"

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ── Captive Portal Redirect ───────────────────────────────────
# iOS, Android, and Windows use specific URLs to test connectivity.
# We catch them and redirect to our SOS page, triggering the
# captive portal pop-up on the victim's device.
CAPTIVE_PORTAL_URLS = [
    "/generate_204",          # Android
    "/gen_204",
    "/hotspot-detect.html",   # Apple
    "/library/test/success.html",
    "/ncsi.txt",              # Windows
    "/connecttest.txt",
    "/redirect",
]

@app.before_request
def captive_portal_intercept():
    """Intercept captive portal probes and redirect all non-API traffic."""
    path = request.path

    # Let API endpoints through
    if path.startswith("/api") or path in ("/sos", "/dashboard"):
        return None

    # Redirect captive portal probes
    if any(path.startswith(url) for url in CAPTIVE_PORTAL_URLS):
        return redirect(f"http://{PI_AP_IP}/", code=302)

    # Redirect requests to wrong hostnames (catch-all for captive detection)
    if request.host not in (PI_AP_IP, f"{PI_AP_IP}:{FLASK_PORT}", "localhost"):
        return redirect(f"http://{PI_AP_IP}/", code=302)

    return None

# ── SOS Portal Page ──────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    """Serve the victim-facing SOS + VoIP page."""
    return SOS_HTML_PAGE

@app.route("/sos", methods=["POST"])
def receive_sos():
    """Accept SOS form submissions from victims."""
    name    = request.form.get("name", "Unknown").strip()[:64]
    message = request.form.get("message", "").strip()[:512]
    ip_addr = request.remote_addr

    if not message:
        return "Missing message", 400

    db = get_db()
    db.execute(
        "INSERT INTO sos_messages (name, message, ip_addr) VALUES (?, ?, ?)",
        (name, message, ip_addr)
    )
    db.commit()

    print(f"[SOS] {ip_addr} | {name}: {message}")

    # Return confirmation page
    return CONFIRMATION_HTML.format(name=name), 200

# ── Probe Sighting Endpoint (HTTP fallback) ───────────────────
@app.route("/api/probes", methods=["POST"])
def receive_probes_http():
    """HTTP POST fallback for ESP32 probe reports (if UDP is blocked)."""
    raw  = request.data.decode("utf-8", errors="ignore")
    _save_probe_payload(raw, request.remote_addr)
    return "OK", 200

# ── Dashboard (operator only) ─────────────────────────────────
@app.route("/dashboard", methods=["GET"])
def dashboard():
    db       = get_db()
    messages = db.execute(
        "SELECT * FROM sos_messages ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()
    probes   = db.execute(
        "SELECT * FROM probe_sightings ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()

    rows_sos = "".join(
        f"<tr><td>{r['timestamp']}</td><td>{r['name']}</td>"
        f"<td>{r['message']}</td><td>{r['ip_addr']}</td></tr>"
        for r in messages
    )
    rows_probes = "".join(
        f"<tr><td>{r['timestamp']}</td><td>{r['mac']}</td>"
        f"<td>{r['rssi']} dBm</td><td>{r['source_ip']}</td></tr>"
        for r in probes
    )

    return DASHBOARD_HTML.format(
        sos_count=len(messages),
        probe_count=len(probes),
        sos_rows=rows_sos or "<tr><td colspan='4'>No messages yet</td></tr>",
        probe_rows=rows_probes or "<tr><td colspan='4'>No sightings yet</td></tr>",
    )

# ── API: JSON data export ─────────────────────────────────────
@app.route("/api/data", methods=["GET"])
def api_data():
    """Return all data as JSON for integration with external tools."""
    db       = get_db()
    messages = db.execute("SELECT * FROM sos_messages ORDER BY timestamp DESC").fetchall()
    probes   = db.execute("SELECT * FROM probe_sightings ORDER BY timestamp DESC").fetchall()
    return jsonify({
        "sos_messages":   [dict(r) for r in messages],
        "probe_sightings": [dict(r) for r in probes],
    })

# ─── UDP LISTENER THREAD ─────────────────────────────────────
def _save_probe_payload(raw: str, source_ip: str):
    """
    Parse ESP32 probe report lines and write to DB.
    Format per line: MAC|RSSI
    Example: AA:BB:CC:DD:EE:FF|-67
    """
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    count = 0

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) != 2:
            continue
        mac, rssi_str = parts[0].strip(), parts[1].strip()
        try:
            rssi = int(rssi_str)
        except ValueError:
            continue

        cur.execute(
            "INSERT INTO probe_sightings (mac, rssi, source_ip) VALUES (?, ?, ?)",
            (mac, rssi, source_ip)
        )
        count += 1

    conn.commit()
    conn.close()
    if count:
        print(f"[UDP] Saved {count} probe sighting(s) from {source_ip}")

def udp_listener():
    """
    Background thread: listens for UDP probe reports from the ESP32.
    Runs forever; restarts socket on error.
    """
    print(f"[UDP] Listener starting on {UDP_LISTEN_IP}:{UDP_PORT}")
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((UDP_LISTEN_IP, UDP_PORT))
            print(f"[UDP] Bound. Waiting for ESP32 reports...")

            while True:
                data, addr = sock.recvfrom(4096)
                raw = data.decode("utf-8", errors="ignore")
                _save_probe_payload(raw, addr[0])

        except Exception as e:
            print(f"[UDP] Error: {e}. Restarting in 3s...")
            import time; time.sleep(3)

# ─── HTML TEMPLATES ──────────────────────────────────────────
# These are inlined here for single-file deployment convenience.
# In production you'd use Flask's templates/ directory.

SOS_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>RESCUE NODE — Emergency Portal</title>
<style>
  /* ── Font Import ── */
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Bebas+Neue&display=swap');

  :root {
    --red:    #FF2D2D;
    --amber:  #FFB800;
    --green:  #00FF88;
    --dark:   #0A0A0A;
    --panel:  #111418;
    --border: #1E2830;
    --text:   #C8D6DF;
    --dim:    #556677;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--dark);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0 16px 40px;
    background-image:
      repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(255,45,45,0.015) 2px,
        rgba(255,45,45,0.015) 4px
      );
  }

  /* ── Header ── */
  .header {
    width: 100%;
    max-width: 520px;
    padding: 28px 0 20px;
    text-align: center;
    border-bottom: 1px solid var(--red);
    margin-bottom: 28px;
  }
  .pulse-dot {
    display: inline-block;
    width: 10px; height: 10px;
    background: var(--red);
    border-radius: 50%;
    margin-right: 8px;
    animation: pulse 1.2s ease-in-out infinite;
    vertical-align: middle;
  }
  @keyframes pulse {
    0%,100% { opacity:1; transform:scale(1); box-shadow: 0 0 0 0 rgba(255,45,45,0.6); }
    50%      { opacity:.7; transform:scale(1.3); box-shadow: 0 0 0 8px rgba(255,45,45,0); }
  }
  .title {
    font-family: 'Bebas Neue', sans-serif;
    font-size: 2.4rem;
    letter-spacing: 4px;
    color: var(--red);
    text-shadow: 0 0 20px rgba(255,45,45,0.5);
  }
  .subtitle {
    font-size: 0.7rem;
    color: var(--dim);
    letter-spacing: 3px;
    margin-top: 4px;
    text-transform: uppercase;
  }

  /* ── Status Banner ── */
  .status-bar {
    width: 100%;
    max-width: 520px;
    background: rgba(255,184,0,0.08);
    border: 1px solid rgba(255,184,0,0.3);
    border-radius: 4px;
    padding: 10px 16px;
    font-size: 0.72rem;
    color: var(--amber);
    letter-spacing: 1px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .status-bar::before { content: "▶"; }

  /* ── Panel ── */
  .panel {
    width: 100%;
    max-width: 520px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 24px;
    margin-bottom: 16px;
    position: relative;
  }
  .panel-label {
    font-size: 0.6rem;
    letter-spacing: 3px;
    color: var(--dim);
    text-transform: uppercase;
    margin-bottom: 16px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
  }
  .panel-label span { color: var(--amber); }

  /* ── Form ── */
  label {
    display: block;
    font-size: 0.65rem;
    letter-spacing: 2px;
    color: var(--dim);
    margin-bottom: 6px;
    text-transform: uppercase;
  }
  input[type=text], textarea {
    width: 100%;
    background: #0D1117;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9rem;
    padding: 10px 12px;
    margin-bottom: 18px;
    outline: none;
    transition: border-color 0.2s;
  }
  input[type=text]:focus, textarea:focus {
    border-color: var(--amber);
  }
  textarea { resize: vertical; min-height: 100px; }

  /* ── Buttons ── */
  .btn {
    display: block;
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 4px;
    font-family: 'Bebas Neue', sans-serif;
    font-size: 1.2rem;
    letter-spacing: 3px;
    cursor: pointer;
    transition: all 0.15s;
    text-align: center;
    text-decoration: none;
  }
  .btn-sos {
    background: var(--red);
    color: #fff;
    box-shadow: 0 0 20px rgba(255,45,45,0.35);
  }
  .btn-sos:hover { background: #ff4444; box-shadow: 0 0 30px rgba(255,45,45,0.55); }
  .btn-sos:active { transform: scale(0.98); }

  .btn-call {
    background: transparent;
    color: var(--green);
    border: 1px solid var(--green);
    box-shadow: 0 0 12px rgba(0,255,136,0.15);
    margin-top: 8px;
    font-size: 1rem;
  }
  .btn-call:hover { background: rgba(0,255,136,0.08); box-shadow: 0 0 20px rgba(0,255,136,0.3); }
  .btn-call.calling { color: var(--amber); border-color: var(--amber); animation: callpulse 1s infinite; }
  .btn-call.error   { color: var(--red);   border-color: var(--red); }
  @keyframes callpulse { 0%,100%{opacity:1} 50%{opacity:0.5} }

  /* ── Call Status ── */
  #call-status {
    font-size: 0.68rem;
    letter-spacing: 2px;
    color: var(--dim);
    text-align: center;
    margin-top: 10px;
    min-height: 18px;
  }
  #call-status.active { color: var(--green); }
  #call-status.error  { color: var(--red); }

  /* ── Footer ── */
  .footer {
    font-size: 0.55rem;
    color: var(--dim);
    letter-spacing: 2px;
    text-align: center;
    margin-top: 20px;
    opacity: 0.6;
  }

  /* ── Hidden audio ── */
  #remote-audio { display: none; }
</style>
</head>
<body>

<div class="header">
  <div><span class="pulse-dot"></span><span class="title">RESCUE NODE</span></div>
  <div class="subtitle">Emergency Communication Portal &nbsp;·&nbsp; SAR Network</div>
</div>

<div class="status-bar">
  RELAY ONLINE &nbsp;|&nbsp; COMMAND SERVER CONNECTED &nbsp;|&nbsp; TRANSMITTING GPS DATA
</div>

<!-- ── SOS Message Form ── -->
<div class="panel">
  <div class="panel-label">MODULE <span>01</span> — SEND SOS MESSAGE</div>
  <form action="/sos" method="POST">
    <label>Your Name (optional)</label>
    <input type="text" name="name" placeholder="e.g. Jane Doe" maxlength="64">

    <label>Situation Report *</label>
    <textarea name="message" placeholder="Describe your location, injuries, and number of people. e.g: Trapped on north ridge, 2 injured, near the red barn." maxlength="512" required></textarea>

    <button type="submit" class="btn btn-sos">▲ SEND SOS TO COMMAND</button>
  </form>
</div>

<!-- ── VoIP Call Module ── -->
<div class="panel">
  <div class="panel-label">MODULE <span>02</span> — VOICE CALL COMMAND CENTER</div>

  <button id="call-btn" class="btn btn-call" onclick="handleCallButton()">
    ☎ CALL COMMAND CENTER (EXT. 100)
  </button>
  <div id="call-status">READY — TAP TO INITIATE VOIP CALL</div>
  <audio id="remote-audio" autoplay></audio>
</div>

<div class="footer">
  SAR RELAY v1.0 &nbsp;·&nbsp; AIRBORNE RELAY ACTIVE &nbsp;·&nbsp; DO NOT POWER OFF DEVICE
</div>

<!-- ═══════════════════════════════════════════════════════════════
     JsSIP WebRTC VoIP Stack
     JsSIP 3.1.1 — loaded from CDN
     ═══════════════════════════════════════════════════════════════ -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jssip/3.1.1/jssip.min.js"></script>
<script>
// ────────────────────────────────────────────────────────────────
//  WebRTC / JsSIP Configuration
// ────────────────────────────────────────────────────────────────

const PI_HOST     = window.location.hostname;
const PI_WS_URL   = "ws://" + PI_HOST + ":8088/ws";
const SIP_USER    = "200";
const SIP_PASS    = "victim200pass";
const SIP_REALM   = PI_HOST;
const CALL_TARGET = "100";

let userAgent     = null;
let activeSession = null;

function initSIP() {
  const socket = new JsSIP.WebSocketInterface(PI_WS_URL);
  const configuration = {
    sockets: [socket],
    uri: "sip:" + SIP_USER + "@" + SIP_REALM,
    password: SIP_PASS,
    register: true
  };

  userAgent = new JsSIP.UA(configuration);

  userAgent.on("connected",    () => setStatus("WS CONNECTED — REGISTERING...", "active"));
  userAgent.on("disconnected", () => setStatus("WS DISCONNECTED", "error"));
  userAgent.on("registered",   () => setStatus("REGISTERED — READY TO CALL", "active"));
  userAgent.on("registrationFailed", (e) => setStatus("REGISTER FAILED: " + e.cause, "error"));

  userAgent.start();
}

function placeCall() {
  if (!userAgent || !userAgent.isRegistered()) {
    setStatus("ERROR: NOT REGISTERED", "error");
    return;
  }

  const eventHandlers = {
    progress:  () => {
      setStatus("CALLING... RINGING", "active");
      document.getElementById("call-btn").textContent = "CALLING...";
      document.getElementById("call-btn").className = "btn btn-call calling";
    },
    failed:    (e) => {
      setStatus("CALL FAILED: " + e.cause, "error");
      resetCallButton();
    },
    ended:     () => {
      setStatus("CALL ENDED", "");
      resetCallButton();
    },
    confirmed: () => {
      setStatus("CALL CONNECTED", "active");
      document.getElementById("call-btn").textContent = "END CALL";
      document.getElementById("call-btn").onclick = endCall;
    }
  };

  const options = {
    eventHandlers: eventHandlers,
    mediaConstraints: { audio: true, video: false },
    pcConfig: {
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
    }
  };

  activeSession = userAgent.call("sip:" + CALL_TARGET + "@" + SIP_REALM, options);

  activeSession.connection.addEventListener("addstream", (e) => {
    const audioEl = document.getElementById("remote-audio");
    audioEl.srcObject = e.stream;
    audioEl.play().catch(err => console.warn("Audio play blocked:", err));
  });
}

function endCall() {
  if (activeSession) {
    activeSession.terminate();
    activeSession = null;
  }
  resetCallButton();
  setStatus("CALL TERMINATED", "");
}

function setStatus(msg, cls) {
  const el = document.getElementById("call-status");
  el.textContent = msg;
  el.className = cls;
}

function resetCallButton() {
  const btn = document.getElementById("call-btn");
  btn.textContent = "CALL COMMAND CENTER (EXT. 100)";
  btn.className = "btn btn-call";
  btn.onclick = handleCallButton;
}

let sipInitialised = false;

function handleCallButton() {
  if (!sipInitialised) {
    sipInitialised = true;
    setStatus("CONNECTING TO PBX...", "active");
    initSIP();
    setTimeout(placeCall, 6000);
  } else {
    placeCall();
  }
}
</script>
</body>
</html>
"""

CONFIRMATION_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOS Received</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Bebas+Neue&display=swap');
  body {{ background:#0A0A0A; color:#C8D6DF; font-family:'Share Tech Mono',monospace;
         display:flex; align-items:center; justify-content:center; min-height:100vh; text-align:center; padding:20px; }}
  .box {{ max-width:400px; border:1px solid #00FF88; padding:40px 30px; border-radius:6px;
          background:#111418; box-shadow:0 0 30px rgba(0,255,136,0.15); }}
  h1 {{ font-family:'Bebas Neue',sans-serif; font-size:2rem; color:#00FF88; letter-spacing:4px; margin-bottom:16px; }}
  p  {{ font-size:0.8rem; color:#556677; letter-spacing:1px; line-height:1.7; }}
  a  {{ color:#FFB800; font-size:0.75rem; letter-spacing:2px; }}
</style>
</head>
<body>
<div class="box">
  <h1>✓ SOS RECEIVED</h1>
  <p>Your message has been transmitted to the Command Center, {name}.<br><br>
     Help is on the way. Stay calm and remain at your current location if safe to do so.</p>
  <br>
  <a href="/">← RETURN TO PORTAL</a>
</div>
</body>
</html>
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Command Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Bebas+Neue&display=swap');
  :root {{ --red:#FF2D2D; --amber:#FFB800; --green:#00FF88; --dark:#0A0A0A;
           --panel:#111418; --border:#1E2830; --text:#C8D6DF; --dim:#556677; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--dark); color:var(--text); font-family:'Share Tech Mono',monospace;
          padding:30px 20px; }}
  h1 {{ font-family:'Bebas Neue',sans-serif; color:var(--red); letter-spacing:4px;
        font-size:1.8rem; margin-bottom:6px; }}
  .meta {{ font-size:0.65rem; color:var(--dim); letter-spacing:2px; margin-bottom:30px; }}
  .section-title {{ font-family:'Bebas Neue',sans-serif; font-size:1.1rem;
                    color:var(--amber); letter-spacing:3px; margin:24px 0 12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.72rem; }}
  th {{ text-align:left; padding:8px 12px; background:var(--panel);
        color:var(--dim); letter-spacing:2px; font-size:0.6rem;
        border-bottom:1px solid var(--border); }}
  td {{ padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; }}
  tr:hover td {{ background:rgba(255,184,0,0.03); }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:3px; font-size:0.62rem;
            letter-spacing:1px; }}
  .sos-badge  {{ background:rgba(255,45,45,0.15); color:var(--red); border:1px solid rgba(255,45,45,0.3); }}
  .prob-badge {{ background:rgba(0,255,136,0.1);  color:var(--green); border:1px solid rgba(0,255,136,0.3); }}
</style>
</head>
<body>
<h1>⬡ COMMAND DASHBOARD</h1>
<div class="meta">
  LIVE DATA &nbsp;·&nbsp;
  SOS MESSAGES: {sos_count} &nbsp;·&nbsp;
  PROBE SIGHTINGS: {probe_count} &nbsp;·&nbsp;
  <a href="/api/data" style="color:#FFB800">JSON EXPORT</a> &nbsp;·&nbsp;
  <a href="/" style="color:#556677">PORTAL</a>
</div>

<div class="section-title">SOS MESSAGES</div>
<table>
  <tr><th>TIMESTAMP</th><th>NAME</th><th>MESSAGE</th><th>IP ADDRESS</th></tr>
  {sos_rows}
</table>

<div class="section-title">PROBE SIGHTINGS (Wi-Fi Device Detection)</div>
<table>
  <tr><th>TIMESTAMP</th><th>MAC ADDRESS</th><th>RSSI</th><th>RELAY (ESP32)</th></tr>
  {probe_rows}
</table>

<script>setTimeout(()=>location.reload(), 10000);</script>
</body>
</html>
"""

# ─── ENTRY POINT ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAR Command Server")
    parser.add_argument("--port", type=int, default=FLASK_PORT)
    args = parser.parse_args()

    init_db()

    # Start UDP listener in a daemon thread
    t = threading.Thread(target=udp_listener, daemon=True)
    t.start()

    print(f"""
╔══════════════════════════════════════════════╗
║       SAR COMMAND SERVER STARTING            ║
║  Portal    : http://{PI_AP_IP}:{args.port:<5}          ║
║  Dashboard : http://{PI_AP_IP}:{args.port:<5}/dashboard ║
║  UDP port  : {UDP_PORT:<5}                         ║
╚══════════════════════════════════════════════╝
""")

    # Use threaded=True so the UDP thread and Flask can coexist
    app.run(
        host="0.0.0.0",
        port=args.port,
        threaded=True,
        debug=False,
        ssl_context=('/home/reda/hhh/cert.pem', '/home/reda/hhh/key.pem'),   # Set to ('cert.pem','key.pem') to enable HTTPS
    )
