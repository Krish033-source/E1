# CyberTotalX — E1 Watchdog

A Flask + HTML/CSS/JS MVP for the **External Assessment** mode of E1.

## What this MVP does

- URL-based website assessment
- SSRF-aware target validation and redirect revalidation
- HTTP/HTTPS and TLS inspection
- Security header analysis and basic cookie flag observations
- Same-origin public route discovery
- Public JavaScript credential-like pattern indicators
- Evidence-based findings with severity/confidence
- JSON report download
- Clear tested vs. untested scope
- Authorized Deep Assessment review scaffold
- Offline Risk Simulation Lab (synthetic scenarios, no network activity)

## Run locally (Windows)

\`\`\`powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
\`\`\`

Open http://127.0.0.1:5000

## Deploy to Render

The repository includes \`render.yaml\` and \`Procfile\`. In Render, choose **New → Blueprint** and connect this repository, or create a Web Service with:

- Build: \`pip install -r requirements.txt\`
- Start: \`gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120\`

## Scope and safety

External Assessment checks publicly observable evidence and is not proof that a site is secure. Deep mode provides owner-authorized review scaffolding; it does not attempt authentication bypass, credential guessing, database dumping, destructive exploitation or exploit payload delivery. The simulation lab uses only predefined synthetic scenarios and makes zero network requests.

Before public production deployment, add authentication, per-user rate limits/quotas, isolated scanning workers, outbound egress controls, DNS rebinding protection, request/response size caps, audit logs and durable scan history. Assess only sites you own or are authorized to test.
