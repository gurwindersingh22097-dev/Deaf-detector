import asyncio
import json
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse

app = FastAPI(title="Deaf Detector — Inline WAF & SOC Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SIGNATURE_RULES = [
    {
        "id": "RULE-001",
        "name": "SQL Injection (SQLi)",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(\bUNION\b.*\bSELECT\b|'\s*OR\s*'1'='1|--\s*$|;\s*DROP\s+TABLE)", re.IGNORECASE),
    },
    {
        "id": "RULE-002",
        "name": "Cross-Site Scripting (XSS)",
        "mitre": "T1059.007 - JavaScript Execution",
        "severity": "HIGH",
        "pattern": re.compile(r"(<\s*script\b|onerror\s*=|onload\s*=|javascript\s*:)", re.IGNORECASE),
    },
    {
        "id": "RULE-003",
        "name": "Path Traversal / LFI",
        "mitre": "T1083 - File and Directory Discovery",
        "severity": "HIGH",
        "pattern": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|windows\\win\.ini)", re.IGNORECASE),
    },
    {
        "id": "RULE-004",
        "name": "OS Command Injection",
        "mitre": "T1059.004 - Unix Shell",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(;\s*(cat|id|whoami|uname|nc|bash|dir|type)\b|\|\s*(whoami|id|sh|cmd)\b|\$\(.*\))", re.IGNORECASE),
    },
]

subscribers: set[asyncio.Queue] = set()
failed_logins: dict[str, deque] = defaultdict(deque)
blocked_ips: dict[str, dict] = {}
stats = {"total_events": 0, "threats_detected": 0}


async def broadcast(event_data: dict):
    for queue in list(subscribers):
        await queue.put(event_data)


def evaluate_traffic(source_ip: str, endpoint: str, payload: str, status_code: int = 200) -> dict:
    now = time.time()
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    stats["total_events"] += 1

    if source_ip in blocked_ips:
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "endpoint": endpoint,
            "payload": payload[:120] or "(blocked connection)",
            "status": "BLOCKED",
            "severity": "HIGH",
            "rule": "Active IP Quarantine",
            "mitre": "T1078 - Repeat Offender Blocked",
        }

    for rule in SIGNATURE_RULES:
        if rule["pattern"].search(payload) or rule["pattern"].search(endpoint):
            stats["threats_detected"] += 1
            blocked_ips[source_ip] = {"reason": rule["name"], "blocked_at": timestamp}
            return {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "endpoint": endpoint,
                "payload": payload[:120],
                "status": "ALERT",
                "severity": rule["severity"],
                "rule": f"{rule['id']}: {rule['name']}",
                "mitre": rule["mitre"],
            }

    if status_code == 401:
        window = failed_logins[source_ip]
        window.append(now)
        while window and now - window[0] > 15:
            window.popleft()
        if len(window) >= 5:
            stats["threats_detected"] += 1
            blocked_ips[source_ip] = {"reason": "Brute Force (5+ failures / 15s)", "blocked_at": timestamp}
            window.clear()
            return {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "endpoint": endpoint,
                "payload": "5 failed login attempts in 15s",
                "status": "ALERT",
                "severity": "CRITICAL",
                "rule": "RULE-005: Brute-Force Burst",
                "mitre": "T1110 - Brute Force",
            }

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "endpoint": endpoint,
        "payload": payload[:120] or "(clean page load)",
        "status": "CLEAN",
        "severity": "INFO",
        "rule": "Passed WAF Inspection",
        "mitre": "-",
    }


@app.middleware("http")
async def inline_waf_shield(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/site"):
        return await call_next(request)

    client_ip = request.headers.get(
        "X-Forwarded-For", request.client.host if request.client else "127.0.0.1"
    ).split(",")[0].strip()

    raw_query = unquote_plus(request.url.query)
    body_bytes = await request.body()
    raw_body = unquote_plus(body_bytes.decode("utf-8", errors="ignore"))
    combined_payload = f"{raw_query} {raw_body}".strip()

    result = evaluate_traffic(client_ip, path, combined_payload, 200)
    if result["status"] in ("ALERT", "BLOCKED"):
        await broadcast({"event": result, "stats": stats, "blocked_ips": blocked_ips})
        return HTMLResponse(
            status_code=403,
            content=f"""
            <!DOCTYPE html>
            <html>
            <head><title>403 Blocked by Deaf Detector WAF</title></head>
            <body style="background:#090d16;color:#f8fafc;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
              <div style="background:#160b0e;border:2px solid #ef4444;border-radius:12px;padding:36px;max-width:560px;box-shadow:0 20px 50px rgba(239,68,68,0.2);">
                <div style="color:#ef4444;font-weight:800;font-size:0.85rem;letter-spacing:1px;text-transform:uppercase;">Deaf Detector Active Defense Shield</div>
                <h1 style="margin:8px 0 16px 0;font-size:1.6rem;">403 Forbidden — Attack Blocked</h1>
                <p style="color:#cbd5e1;line-height:1.5;">Your request was intercepted before reaching the target application server.</p>
                <div style="background:#0b0f17;padding:14px;border-radius:8px;font-family:monospace;font-size:0.85rem;margin:18px 0;border:1px solid #334155;">
                  <div><span style="color:#94a3b8;">Trigger Rule:</span> <strong style="color:#f87171;">{result['rule']}</strong></div>
                  <div style="margin-top:6px;"><span style="color:#94a3b8;">MITRE ATT&CK:</span> {result['mitre']}</div>
                  <div style="margin-top:6px;"><span style="color:#94a3b8;">Client IP:</span> {client_ip} (Quarantined)</div>
                </div>
                <p style="font-size:0.85rem;color:#94a3b8;">All subsequent requests from your IP are blocked until an analyst lifts the quarantine in the Deaf Detector SOC Dashboard.</p>
                <a href="/site" style="display:inline-block;margin-top:10px;background:#ef4444;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;font-weight:600;">Test Reloading Website</a>
              </div>
            </body>
            </html>
            """,
        )

    response = await call_next(request)

    if response.status_code == 401:
        stats["total_events"] -= 1
        result = evaluate_traffic(client_ip, path, combined_payload, 401)

    await broadcast({"event": result, "stats": stats, "blocked_ips": blocked_ips})
    return response


@app.get("/", response_class=HTMLResponse)
async def serve_soc_dashboard():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>index.html not found in project root</h1>"


TARGET_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NexaCloud — Protected by Deaf Detector</title>
  <style>
    :root { --bg:#f1f5f9; --card:#ffffff; --ink:#0f172a; --muted:#64748b; --brand:#2563eb; --danger:#dc2626; --ok:#16a34a; }
    * { box-sizing:border-box; font-family:system-ui,-apple-system,sans-serif; }
    body { margin:0; background:var(--bg); color:var(--ink); }
    nav { background:#0f172a; color:#fff; padding:14px 28px; display:flex; justify-content:space-between; align-items:center; }
    nav .logo { font-weight:800; font-size:1.15rem; letter-spacing:0.4px; }
    nav .shield { background:rgba(34,197,94,0.18); color:#4ade80; padding:4px 12px; border-radius:999px; font-size:0.8rem; font-weight:600; }
    .container { max-width:1050px; margin:28px auto; padding:0 20px; }
    .banner { background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px; padding:16px 20px; margin-bottom:24px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(450px, 1fr)); gap:20px; }
    .card { background:var(--card); border:1px solid #e2e8f0; border-radius:10px; padding:22px; box-shadow:0 2px 8px rgba(15,23,42,0.04); }
    .card h3 { margin:0 0 6px 0; font-size:1.1rem; }
    .card p { margin:0 0 14px 0; color:var(--muted); font-size:0.88rem; }
    input { width:100%; padding:10px 12px; border:1px solid #cbd5e1; border-radius:6px; font-size:0.92rem; margin-bottom:10px; }
    button { background:var(--brand); color:#fff; border:none; padding:10px 16px; border-radius:6px; font-weight:600; cursor:pointer; }
    button:hover { opacity:0.92; }
    .presets { margin-top:12px; padding-top:12px; border-top:1px dashed #e2e8f0; display:flex; gap:8px; flex-wrap:wrap; align-items:center; font-size:0.78rem; color:var(--muted); }
    .chip { background:#f8fafc; border:1px solid #cbd5e1; color:#334155; padding:4px 9px; border-radius:4px; cursor:pointer; font-size:0.76rem; }
    .chip.atk { border-color:#fecaca; background:#fef2f2; color:var(--danger); font-weight:600; }
    .result-box { background:#f8fafc; border-left:4px solid var(--brand); padding:14px; border-radius:6px; margin-bottom:20px; }
  </style>
</head>
<body>
  <nav>
    <div class="logo">NexaCloud Enterprise Portal</div>
    <div class="shield">● Protected by Deaf Detector</div>
  </nav>
  <div class="container">
    <div class="banner">
      <div>
        <strong>Live Protected Web Application</strong> — Every HTTP request and form submission below is inspected inline by Deaf Detector.
      </div>
      <a href="/" target="_blank" style="color:#2563eb;font-weight:700;text-decoration:none;">Open Deaf Detector SOC ↗</a>
    </div>
    __CONTENT__
  </div>
</body>
</html>
"""


@app.get("/site", response_class=HTMLResponse)
async def target_home():
    body = """
    <div class="grid">
      <div class="card">
        <h3>1. Cloud Catalog Search</h3>
        <p>Tests query parameter inspection against Reflected XSS and SQL Injection.</p>
        <form method="GET" action="/site/search">
          <input id="searchInput" name="q" placeholder="Search servers, firewalls, storage..." required />
          <button type="submit">Search Catalog</button>
        </form>
        <div class="presets">
          <span>Quick Fill:</span>
          <button type="button" class="chip" onclick="document.getElementById('searchInput').value='Dedicated NVMe Server'">Normal Query</button>
          <button type="button" class="chip atk" onclick="document.getElementById('searchInput').value='<script>alert(document.cookie)</script>'">XSS Payload</button>
          <button type="button" class="chip atk" onclick="document.getElementById('searchInput').value='server UNION SELECT username, password FROM users'">UNION SQLi</button>
        </div>
      </div>

      <div class="card">
        <h3>2. Admin & Partner Login</h3>
        <p>Tests POST body inspection for Auth Bypass SQLi and 5-attempt Brute-Force detection.</p>
        <form method="POST" action="/site/login">
          <input id="loginUser" name="username" placeholder="Username (e.g. admin)" required />
          <input id="loginPass" name="password" type="password" placeholder="Password" required />
          <button type="submit">Sign In</button>
        </form>
        <div class="presets">
          <span>Quick Fill:</span>
          <button type="button" class="chip" onclick="document.getElementById('loginUser').value='admin';document.getElementById('loginPass').value='Pass123!'">Valid Admin</button>
          <button type="button" class="chip atk" onclick="document.getElementById('loginUser').value='admin';document.getElementById('loginPass').value=&quot;' OR '1'='1 --&quot;">Auth Bypass SQLi</button>
        </div>
      </div>

      <div class="card">
        <h3>3. Billing Invoice Viewer</h3>
        <p>Tests file parameter sanitization against Directory Traversal attacks.</p>
        <form method="GET" action="/site/docs">
          <input id="docInput" name="file" placeholder="Filename (e.g. invoice_2026_09.pdf)" required />
          <button type="submit">Download Invoice</button>
        </form>
        <div class="presets">
          <span>Quick Fill:</span>
          <button type="button" class="chip" onclick="document.getElementById('docInput').value='invoice_2026_09.pdf'">Valid Invoice</button>
          <button type="button" class="chip atk" onclick="document.getElementById('docInput').value='../../../../etc/passwd'">Linux /etc/passwd</button>
        </div>
      </div>

      <div class="card">
        <h3>4. Edge Node Ping Diagnostics</h3>
        <p>Tests network utility inputs against shell chaining & OS Command Injection.</p>
        <form method="POST" action="/site/ping">
          <input id="pingInput" name="host" placeholder="Target IP or Hostname (e.g. 8.8.8.8)" required />
          <button type="submit">Run Ping Test</button>
        </form>
        <div class="presets">
          <span>Quick Fill:</span>
          <button type="button" class="chip" onclick="document.getElementById('pingInput').value='8.8.8.8'">Clean Ping</button>
          <button type="button" class="chip atk" onclick="document.getElementById('pingInput').value='8.8.8.8; cat /etc/shadow'">Command Injection</button>
        </div>
      </div>
    </div>
    """
    return TARGET_LAYOUT.replace("__CONTENT__", body)


@app.get("/site/search", response_class=HTMLResponse)
async def target_search(q: str = ""):
    body = f"""
    <div class="result-box">
      <h3>Search Results for "{q}"</h3>
      <p>WAF Status: <strong>Clean Request Approved</strong>. Showing 3 matching cloud hardware SKUs.</p>
      <a href="/site">← Back to NexaCloud Portal</a>
    </div>
    """
    return TARGET_LAYOUT.replace("__CONTENT__", body)


@app.post("/site/login", response_class=HTMLResponse)
async def target_login(request: Request):
    form = await request.form()
    user = form.get("username", "")
    pwd = form.get("password", "")
    if user == "admin" and pwd == "Pass123!":
        body = """
        <div class="result-box" style="border-color:#16a34a;">
          <h3>Welcome back, Administrator!</h3>
          <p>Authenticated cleanly through Deaf Detector WAF.</p>
          <a href="/site">← Back to NexaCloud Portal</a>
        </div>
        """
        return TARGET_LAYOUT.replace("__CONTENT__", body)

    body = f"""
    <div class="result-box" style="border-color:#f59e0b;">
      <h3>Authentication Failed (HTTP 401)</h3>
      <p>Invalid password for user <strong>{user}</strong>. Note: 5 failed attempts within 15 seconds will trigger automatic IP quarantine.</p>
      <a href="/site">← Try Again</a>
    </div>
    """
    return HTMLResponse(TARGET_LAYOUT.replace("__CONTENT__", body), status_code=401)


@app.get("/site/docs", response_class=HTMLResponse)
async def target_docs(file: str = ""):
    body = f"""
    <div class="result-box">
      <h3>Document Ready: {file}</h3>
      <p>Verified clean filename. Simulated PDF invoice stream ready.</p>
      <a href="/site">← Back to NexaCloud Portal</a>
    </div>
    """
    return TARGET_LAYOUT.replace("__CONTENT__", body)


@app.post("/site/ping", response_class=HTMLResponse)
async def target_ping(request: Request):
    form = await request.form()
    host = form.get("host", "8.8.8.8")
    body = f"""
    <div class="result-box">
      <h3>ICMP Ping Diagnostics: {host}</h3>
      <pre style="background:#0f172a;color:#38bdf8;padding:12px;border-radius:6px;">PING {host}: 56 data bytes\n64 bytes from {host}: icmp_seq=0 ttl=117 time=14.2 ms\n--- {host} ping statistics --- 1 packets transmitted, 1 received, 0% packet loss</pre>
      <a href="/site">← Back to NexaCloud Portal</a>
    </div>
    """
    return TARGET_LAYOUT.replace("__CONTENT__", body)


@app.post("/unblock/{ip}")
async def unblock_ip(ip: str):
    blocked_ips.pop(ip, None)
    packet = {
        "event": {
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            "source_ip": ip,
            "endpoint": "/soc/admin",
            "payload": "Manual IP quarantine lifted by analyst",
            "status": "CLEAN",
            "severity": "INFO",
            "rule": "Analyst Override",
            "mitre": "-",
        },
        "stats": stats,
        "blocked_ips": blocked_ips,
    }
    await broadcast(packet)
    return {"unblocked": ip}


@app.get("/stream")
async def stream_events(request: Request):
    queue: asyncio.Queue = asyncio.Queue()
    subscribers.add(queue)

    async def event_generator():
        try:
            yield f"data: {json.dumps({'stats': stats, 'blocked_ips': blocked_ips})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                data = await queue.get()
                yield f"data: {json.dumps(data)}\n\n"
        finally:
            subscribers.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
