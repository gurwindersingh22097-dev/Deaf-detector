# Deaf Detector

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Inline_WAF-009688?logo=fastapi&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-ef4444)
![License](https://img.shields.io/badge/License-MIT-22c55e)

**Deaf Detector** is a real-time inline **Web Application Firewall (WAF)** and **Security Operations Center (SOC)** telemetry dashboard built with **Python (FastAPI)** and **Server-Sent Events (SSE)**.

Acting as an inline HTTP middleware, Deaf Detector inspects decoded URL query parameters, paths, and POST form payloads before they reach protected web routes—blocking malicious traffic with `HTTP 403 Forbidden`, mapping alerts to **MITRE ATT&CK** techniques, and automatically quarantining offending source IPs.

---

## Architecture

```text
                       ┌──────────────────────────────────────────┐
                       │        Deaf Detector Inline WAF          │
[Client / Browser] ───►│  1. Active IP Quarantine Check           │
                       │  2. Regex Signature Inspection Engine    │
                       │  3. Sliding-Window Brute-Force Tracker   │
                       └──────────────┬───────────────┬───────────┘
                                      │               │
                       (Clean Traffic)│               │(Threat Detected)
                                      ▼               ▼
                       ┌──────────────────┐   ┌───────────────────┐
                       │ Protected Target │   │ HTTP 403 Block    │
                       │ Web App (/site)  │   │ + IP Quarantine   │
                       └──────────────────┘   │ + Live SSE Alert  │
                                              └─────────┬─────────┘
                                                        │
                                                        ▼
                                              ┌───────────────────┐
                                              │ Live SOC Web UI   │
                                              │        (/)        │
                                              └───────────────────┘
```

---

## Detection Rules & MITRE ATT&CK Mapping

| Rule ID | Threat Category | Detection Mechanism | MITRE ATT&CK Technique | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `RULE-001` | **SQL Injection (SQLi)** | Detects `UNION SELECT`, boolean tautologies (`' OR '1'='1`), comment truncation (`--`), and `DROP TABLE` | `T1190` — Exploit Public-Facing Application | `CRITICAL` |
| `RULE-002` | **Cross-Site Scripting (XSS)** | Flags `<script>` tags, inline event handlers (`onerror=`, `onload=`), and `javascript:` URIs | `T1059.007` — JavaScript Execution | `HIGH` |
| `RULE-003` | **Path Traversal / LFI** | Blocks directory traversal sequences (`../`, `..\`) and sensitive file targets (`/etc/passwd`, `/etc/shadow`, `win.ini`) | `T1083` — File and Directory Discovery | `HIGH` |
| `RULE-004` | **OS Command Injection** | Intercepts shell command chaining (`;`, `\|`, `$()`) invoking system binaries (`cat`, `whoami`, `bash`, `nc`, `cmd`) | `T1059.004` — Unix Shell | `CRITICAL` |
| `RULE-005` | **Credential Brute Force** | Behavioral sliding-window tracker that flags **5+ failed logins (`HTTP 401`) within 15 seconds** | `T1110` — Brute Force | `CRITICAL` |

---

## Key Capabilities

- **Inline HTTP Request Interception:** Evaluates decoded URL queries and form bodies in real time before forwarding requests to backend routes.
- **Automated IP Quarantine & Analyst Override:** Flagged source IPs are immediately blocked from all subsequent requests until an analyst lifts the block from the SOC dashboard.
- **Zero-Refresh Live Telemetry:** Uses native `EventSource` Server-Sent Events (SSE) to push live alerts, KPI counters, and blocklist updates to connected browsers with sub-second latency.
- **Integrated Target Portal (`/site`):** Includes a multi-module enterprise web portal (*Catalog Search*, *Admin Login*, *Billing Invoice Viewer*, and *Ping Diagnostics*) with quick-fill payload presets for live security testing.

---

## Project Structure

```text
deaf-detector/
├── backend.py          # FastAPI server, inline WAF middleware, MITRE rules, SSE stream & /site portal
├── index.html          # Real-time SOC monitoring dashboard
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules
├── LICENSE             # MIT License
└── README.md           # Project documentation
```

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/deaf-detector.git
cd deaf-detector
```

### 2. Create a Virtual Environment & Install Dependencies
**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Start the Server
```bash
uvicorn backend:app --reload --port 8000
```

### 4. Open the Web Interfaces
- **Deaf Detector SOC Dashboard:** `[http://127.0.0.1:8000/](http://127.0.0.1:8000/)`
- **Protected Target Portal:** `[http://127.0.0.1:8000/site](http://127.0.0.1:8000/site)`

---

## Live Demo Walkthrough

1. Open **`[http://127.0.0.1:8000/](http://127.0.0.1:8000/)`** (SOC Dashboard) and **`[http://127.0.0.1:8000/site](http://127.0.0.1:8000/site)`** (Protected Target Portal) side-by-side.
2. **Baseline Normal Traffic:** Submit a clean search query on the target portal. The request passes inspection and logs a green `INFO` event on the SOC stream.
3. **Trigger Signature Prevention:** Click any red **Quick Fill** attack preset (such as *Auth Bypass SQLi* or *Linux `/etc/passwd`*) and submit the form. The WAF intercepts the payload, returns an `HTTP 403 Forbidden` shield page, logs a `CRITICAL`/`HIGH` alert, and adds your IP to **Auto-Quarantined IPs**.
4. **Verify Zero-Trust Quarantine:** Reload `/site` while quarantined—even clean page loads are denied until you click **Unblock** on the SOC dashboard.
5. **Trigger Behavioral Brute-Force Detection:** Submit an invalid password 5 times within 15 seconds on the login form to trigger `RULE-005` and automatic IP quarantine.

---

## Tech Stack

- **Backend:** Python 3.10+, FastAPI, Uvicorn, AsyncIO
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (`EventSource` SSE)
- **Security Standards:** OWASP Top 10, MITRE ATT&CK Framework

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
