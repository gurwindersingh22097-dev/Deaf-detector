# Deaf Detector — Real-Time Inline WAF & Threat Detection SOC

**Deaf Detector** is a lightweight, real-time Web Application Firewall (WAF) and Security Operations Center (SOC) telemetry dashboard built with **Python (FastAPI)** and **Server-Sent Events (SSE)**. 

Acting as an inline HTTP security middleware, it inspects incoming URL query parameters, request paths, and POST form payloads before they reach protected web endpoints—blocking malicious requests with `HTTP 403 Forbidden`, mapping alerts to **MITRE ATT&CK** techniques, and automatically quarantining offending source IPs.

---

## System Architecture

```text
                        ┌─────────────────────────────────────────┐
                        │       Deaf Detector Inline WAF          │
[Client / Browser] ────►│  1. IP Quarantine Check                 │
                        │  2. Regex Signature Inspection Engine   │
                        │  3. Sliding-Window Brute-Force Tracker  │
                        └──────────────┬──────────────┬───────────┘
                                       │              │
                        (Clean Traffic)│              │(Threat Detected)
                                       ▼              ▼
                        ┌──────────────────┐   ┌──────────────────┐
                        │ Protected Target │   │ HTTP 403 Block   │
                        │ Web App (/site)  │   │ + IP Quarantine  │
                        └──────────────────┘   │ + Live SSE Alert │
                                               └────────┬─────────┘
                                                        │
                                                        ▼
                                               ┌──────────────────┐
                                               │ Live SOC Web UI  │
                                               │       (/)        │
                                               └──────────────────┘
