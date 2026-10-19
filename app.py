"""
CyberTotalX E1 -- Watchdog
Single-file Flask backend: core scan engine, SQLite persistence + diffing,
DNS-TXT ownership verification, OWASP ZAP integration, continuous watchdog
scheduler, and report export -- all in this one app.py.

Run:
    pip install -r requirements.txt
    python app.py
    -> http://localhost:5000

See README.md for the full API contract and Docker deployment.
"""
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from html import escape
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from bs4 import BeautifulSoup
from flask import Flask, Response, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("e1.watchdog")

TIMEOUT = 8
MAX_PAGES = 20
MAX_JS = 8
MAX_BYTES = 1_000_000
UA = "CyberTotalX-E1-Watchdog/0.3"

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
WEAK_CIPHER_HINTS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")


class ScanError(Exception):
    pass


# ============================================================================
# SECTION 1 -- SSRF-safe URL validation + safe GET
# ============================================================================
def validate_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("URL is required.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ScanError("Only valid HTTP/HTTPS URLs are supported.")
    if p.username or p.password:
        raise ScanError("Credentials in the URL are not allowed.")
    host = p.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"}:
        raise ScanError("Localhost is blocked.")
    try:
        resolved = {x[4][0] for x in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        raise ScanError("Hostname could not be resolved.")
    for value in resolved:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise ScanError("Private, loopback, link-local, reserved or non-public targets are blocked.")
    return raw, host


def safe_get(url, session, method="GET"):
    current = url
    for _ in range(5):
        validate_url(current)
        response = session.request(method, current, allow_redirects=False, timeout=TIMEOUT,
                                    headers={"User-Agent": UA}, stream=True)
        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if not location:
                return response
            nxt = urljoin(current, location)
            response.close()
            current = nxt
            continue
        length = response.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > MAX_BYTES:
            response.close()
            raise ScanError("Target response exceeds the size limit.")
        body = bytearray()
        for chunk in response.iter_content(16384):
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                response.close()
                raise ScanError("Target response exceeds the size limit.")
        response._content = bytes(body)
        response._content_consumed = True
        return response
    raise ScanError("Too many redirects.")


# ============================================================================
# SECTION 2 -- Finding helper (E1.6 Findings & Remediation Engine)
# ============================================================================
def finding(title, severity, category, evidence, impact, fix, confidence="high",
            endpoint=None, request_made=None, priority=None):
    priority = priority or {"critical": "immediate", "high": "this week",
                             "medium": "this sprint", "low": "backlog",
                             "info": "informational"}.get(severity, "backlog")
    return {
        "title": title, "severity": severity, "category": category,
        "evidence": evidence, "impact": impact, "remediation": fix,
        "confidence": confidence, "endpoint": endpoint,
        "reproduction": {
            "request": request_made or (f"GET {endpoint}" if endpoint else None),
            "observed_at": datetime.now(timezone.utc).isoformat(),
        },
        "review_status": "unreviewed",   # unreviewed | confirmed | false_positive
        "remediation_priority": priority,
        "source": "passive",             # passive | zap
    }


# ============================================================================
# SECTION 3 -- E1.2 Security Configuration Analyzer (headers/cookies/CORS)
# ============================================================================
def inspect_headers(resp, url):
    h = {k.lower(): v for k, v in resp.headers.items()}
    out = []
    checks = [
        ("content-security-policy", "Content-Security-Policy missing", "medium",
         "Add and test a policy matching the site's required resources.",
         "Reduces defense-in-depth against some browser-side injection."),
        ("x-content-type-options", "X-Content-Type-Options missing", "low",
         "Send X-Content-Type-Options: nosniff.", "Helps prevent MIME type sniffing."),
        ("referrer-policy", "Referrer-Policy missing", "low",
         "Set an explicit Referrer-Policy, such as strict-origin-when-cross-origin.",
         "May reduce unintended referrer information sharing."),
        ("permissions-policy", "Permissions-Policy missing", "info",
         "Consider a least-privilege Permissions-Policy.", "Browser capabilities are not explicitly constrained."),
        ("x-frame-options", "X-Frame-Options / frame-ancestors missing", "low",
         "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.",
         "Page may be embeddable in a third-party iframe (clickjacking surface)."),
    ]
    for name, title, sev, fix, impact in checks:
        if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", "").lower():
            continue
        if name not in h:
            out.append(finding(title, sev, "Security Headers",
                                f"Header {name} was not present on the inspected response.",
                                impact, fix, endpoint=url, request_made=f"GET {url}"))
    if urlparse(url).scheme == "https" and "strict-transport-security" not in h:
        out.append(finding("HSTS header missing", "low", "Transport Security",
                            "No Strict-Transport-Security header was observed.",
                            "Clients may have weaker downgrade protection on future visits.",
                            "Consider HSTS after confirming HTTPS is supported across the domain.",
                            endpoint=url, request_made=f"GET {url}"))
    if urlparse(url).scheme == "http":
        out.append(finding("Website is served over HTTP", "high", "Transport Security",
                            f"Submitted URL uses HTTP: {url}",
                            "Traffic may be intercepted or modified in transit.",
                            "Serve the site over HTTPS and redirect HTTP to HTTPS.",
                            endpoint=url, request_made=f"GET {url}"))
    disclose = [f"{k}: {h[k]}" for k in ("server", "x-powered-by") if h.get(k)]
    if disclose:
        out.append(finding("Technology disclosure headers observed", "info", "Information Disclosure",
                            "; ".join(disclose), "Technology fingerprints can help adversaries prioritize research.",
                            "Remove unnecessary framework/version disclosure.", endpoint=url,
                            request_made=f"GET {url}"))
    cookie = resp.headers.get("Set-Cookie", "")
    if cookie:
        for flag, sev, fix, impact in [
            ("secure", "medium", "Use Secure on sensitive cookies over HTTPS.",
             "The cookie may be transmitted over an insecure transport."),
            ("httponly", "low", "Use HttpOnly for cookies that do not need JavaScript access.",
             "Client-side scripts may be able to read the cookie."),
            ("samesite", "low", "Set a SameSite value appropriate to the session flow.",
             "Cross-site cookie behavior may be less constrained than intended.")
        ]:
            if flag not in cookie.lower():
                out.append(finding(f"Cookie without {flag.title()} attribute observed", sev,
                                    "Cookie Security", f"Observed Set-Cookie without {flag.title()}.",
                                    impact, fix, endpoint=url, request_made=f"GET {url}"))
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials")
    if acao == "*" and acac and acac.lower() == "true":
        out.append(finding("Overly permissive CORS with credentials", "high", "CORS",
                            "Response advertised Access-Control-Allow-Origin: * together with "
                            "Access-Control-Allow-Credentials: true.",
                            "Any origin could read credentialed responses in a visitor's browser.",
                            "Never combine a wildcard origin with allow-credentials; use an explicit allow-list.",
                            endpoint=url, request_made=f"GET {url}"))
    elif acao == "*":
        out.append(finding("Wildcard CORS origin observed", "low", "CORS",
                            "Response advertised Access-Control-Allow-Origin: *.",
                            "Any site can read this response in a visitor's browser; fine for public data only.",
                            "Confirm the response body is intended to be fully public.",
                            endpoint=url, request_made=f"GET {url}", confidence="medium"))
    return out


# ============================================================================
# SECTION 4 -- E1.3 API & Data Exposure Analyzer (error-disclosure probe)
# A single GET to a non-existent, same-origin path -- indistinguishable from
# an ordinary visitor following a dead link. Not a crafted attack input.
# ============================================================================
STACK_HINTS = re.compile(
    r"(Traceback \(most recent call last\)|at [\w.$]+\(\w+\.java:\d+\)|"
    r"Microsoft\.\w+Exception|ORA-\d{4,5}|PHP (Fatal error|Warning)|"
    r"Unhandled exception|System\.Exception|django\.core|werkzeug\.exceptions|"
    r"NullPointerException|in <module>)", re.I)


def probe_error_disclosure(base_url, session):
    probe_url = urljoin(base_url, "/e1-watchdog-nonexistent-check-39281")
    try:
        resp = safe_get(probe_url, session)
    except Exception:
        return []
    body = resp.text[:20000] if hasattr(resp, "text") else ""
    resp.close()
    out = []
    if STACK_HINTS.search(body):
        out.append(finding(
            "Verbose error / stack trace on a non-existent route", "medium", "Information Disclosure",
            "A request to a non-existent, harmless path returned content matching a framework "
            "stack-trace pattern.",
            "Internal file paths, framework internals or library versions may be exposed to visitors.",
            "Disable debug/verbose error pages in production; return generic error pages.",
            endpoint=probe_url, request_made=f"GET {probe_url}", confidence="medium"))
    elif resp.status_code != 404 and len(body) > 0:
        out.append(finding(
            "Non-standard response for a missing route", "info", "Information Disclosure",
            f"A request to a non-existent path returned HTTP {resp.status_code} instead of 404.",
            "May indicate custom routing behavior worth reviewing; not necessarily a problem.",
            "Confirm the routing/error-handling behavior is intentional.",
            endpoint=probe_url, request_made=f"GET {probe_url}", confidence="low"))
    return out


# ============================================================================
# SECTION 5 -- E1.1 Attack Surface Discovery + API-route classification
# ============================================================================
API_PATTERN = re.compile(r"/(api|graphql|rest|v[0-9]+|internal|admin)(/|$)", re.I)
ID_IN_PATH = re.compile(r"/(\d+)(/|$)")


def discover(start, session):
    origin = urlparse(start)
    queue, seen, endpoints, scripts = [start], set(), [], []
    while queue and len(seen) < MAX_PAGES:
        url = queue.pop(0)
        if url in seen:
            continue
        try:
            resp = safe_get(url, session)
        except Exception:
            continue
        seen.add(url)
        path = urlparse(url).path
        endpoints.append({
            "url": url, "method": "GET", "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""), "source": "crawler",
            "looks_like_api": bool(API_PATTERN.search(path)),
            "has_numeric_id": bool(ID_IN_PATH.search(path)),
        })
        if "text/html" not in resp.headers.get("Content-Type", "").lower():
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            target = urljoin(url, a["href"].strip())
            p = urlparse(target)
            if p.scheme in ("http", "https") and p.netloc.lower() == origin.netloc.lower():
                target = target.split("#", 1)[0]
                if target not in seen and target not in queue:
                    queue.append(target)
        for tag in soup.find_all("script", src=True):
            target = urljoin(url, tag["src"])
            p = urlparse(target)
            if p.scheme in ("http", "https") and p.netloc.lower() == origin.netloc.lower():
                if target not in scripts and len(scripts) < MAX_JS:
                    scripts.append(target)
        resp.close()
    return endpoints, scripts


def classify_access_control_risk(endpoints):
    """IDOR *risk indicator* only -- never requests a different id than the
    one already discovered. Reports the pattern, not an exploit result."""
    out = []
    numeric_routes = [e for e in endpoints if e.get("has_numeric_id") and e["status"] < 400]
    if numeric_routes:
        sample = numeric_routes[0]["url"]
        out.append(finding(
            "Sequential numeric identifiers in routes", "low", "Access Control (indicator)",
            f"{len(numeric_routes)} discovered route(s) use a small sequential numeric id, "
            f"for example {sample}.",
            "If authorization is enforced only by the caller's identity and not re-checked per "
            "object, such routes are commonly associated with IDOR-class issues. This is a pattern "
            "indicator, not a confirmed finding -- no other identifier was requested.",
            "Confirm server-side that every object access re-checks the caller's ownership/role. "
            "Consider non-guessable identifiers (UUIDs) for sensitive resources.",
            confidence="low", endpoint=sample, request_made=f"GET {sample}"))
    return out


# ============================================================================
# SECTION 6 -- JS secret-pattern detection (detection-only, never validated)
# ============================================================================
SECRET_PATTERNS = [
    ("Generic API key assignment", re.compile(
        r"\b(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.I)),
    ("Generic secret/token assignment", re.compile(
        r"\b(?:secret|access[_-]?token|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.I)),
    ("AWS access key ID pattern", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key pattern", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token pattern", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe live key pattern", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("JWT-like token in source", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |)PRIVATE KEY-----")),
]


def inspect_js(urls, session):
    out = []
    for url in urls:
        try:
            resp = safe_get(url, session)
            body = resp.text[:MAX_BYTES]
            resp.close()
        except Exception:
            continue
        for title, pattern in SECRET_PATTERNS:
            if pattern.search(body):
                out.append(finding(
                    title, "high", "Exposure",
                    f"A credential-like pattern matched in public JavaScript at {url}; "
                    f"this confirms a pattern match only, not that the credential is live.",
                    "A real privileged credential in a client bundle may enable unauthorized access.",
                    "Verify ownership and validity, rotate any real exposed credential immediately, "
                    "and move privileged operations server-side.",
                    confidence="medium", endpoint=url, request_made=f"GET {url}"))
    return out


# ============================================================================
# SECTION 7 -- TLS depth (read-only handshake: version, cipher, expiry)
# ============================================================================
def inspect_tls(host):
    tls = {"available": False}
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as secure:
                cipher = secure.cipher()
                cert = secure.getpeercert()
                tls = {"available": True, "version": secure.version(),
                       "cipher": cipher[0] if cipher else None,
                       "certificate_expires": cert.get("notAfter")}
    except Exception as exc:
        return {"available": False, "error": str(exc)[:160]}, []

    out = []
    if tls.get("version") in WEAK_TLS_VERSIONS:
        out.append(finding("Deprecated TLS protocol version negotiated", "high", "Transport Security",
                            f"Handshake negotiated {tls['version']}.",
                            "Deprecated TLS versions carry known protocol-level weaknesses.",
                            "Disable TLS versions below 1.2 on the server.", endpoint=f"https://{host}",
                            request_made=f"TLS handshake https://{host}:443"))
    cipher_name = tls.get("cipher") or ""
    if any(bad in cipher_name.upper() for bad in WEAK_CIPHER_HINTS):
        out.append(finding("Weak cipher suite negotiated", "medium", "Transport Security",
                            f"Negotiated cipher: {cipher_name}.",
                            "Weak ciphers may allow decryption or downgrade attacks.",
                            "Restrict the server to modern AEAD cipher suites.", endpoint=f"https://{host}",
                            request_made=f"TLS handshake https://{host}:443", confidence="medium"))
    expires = tls.get("certificate_expires")
    if expires:
        try:
            exp_dt = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp_dt - datetime.now(timezone.utc)).days
            if days_left < 0:
                out.append(finding("TLS certificate is expired", "critical", "Transport Security",
                                    f"Certificate notAfter: {expires}.",
                                    "Browsers will show hard security warnings or block the site entirely.",
                                    "Renew the certificate immediately.", endpoint=f"https://{host}",
                                    request_made=f"TLS handshake https://{host}:443"))
            elif days_left < 14:
                out.append(finding("TLS certificate expires soon", "medium", "Transport Security",
                                    f"Certificate expires in {days_left} day(s) ({expires}).",
                                    "An expired certificate will break HTTPS access and trigger warnings.",
                                    "Renew the certificate and consider automated renewal.",
                                    endpoint=f"https://{host}", request_made=f"TLS handshake https://{host}:443"))
        except Exception:
            pass
    return tls, out


def score_findings(findings, url):
    deductions = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
    score = 100 - sum(deductions.get(f["severity"], 0) for f in findings)
    if urlparse(url).scheme == "http":
        score -= 15
    return max(0, min(score, 100))


# ============================================================================
# SECTION 8 -- Orchestrator: Mode A (External Assessment)
# ============================================================================
def run_scan(raw):
    url, host = validate_url(raw)
    session, started = requests.Session(), time.time()
    response = safe_get(url, session)

    findings = inspect_headers(response, url)
    tls, tls_findings = inspect_tls(host) if urlparse(url).scheme == "https" else ({"available": False}, [])
    findings.extend(tls_findings)

    endpoints, scripts = discover(url, session)
    findings.extend(inspect_js(scripts, session))
    findings.extend(classify_access_control_risk(endpoints))
    findings.extend(probe_error_disclosure(url, session))

    counts = {key: sum(1 for f in findings if f["severity"] == key)
              for key in ("critical", "high", "medium", "low", "info")}
    api_routes = [e for e in endpoints if e.get("looks_like_api")]

    result = {
        "engine": "CyberTotalX E1 -- Watchdog", "mode": "External Assessment",
        "target": url, "host": host, "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.time() - started) * 1000),
        "score": score_findings(findings, url), "counts": counts,
        "target_response": {"status": response.status_code,
                             "content_type": response.headers.get("Content-Type"),
                             "server": response.headers.get("Server"), "final_url": response.url},
        "tls": tls,
        "discovery": {"endpoints": endpoints, "javascript": scripts,
                      "pages_scanned": len(endpoints), "api_like_routes": len(api_routes)},
        "tested": ["HTTP/HTTPS response", "Common security headers", "CORS header behaviour",
                   "Basic cookie flags", "Redirect target validation", "TLS version / cipher / expiry",
                   "Same-origin public routes", "Credential-like patterns in public JavaScript",
                   "Error-page behaviour on a non-existent route", "Numeric-id route pattern (indicator only)"],
        "not_tested": ["Authentication bypass", "Credential guessing", "SQLi/XSS exploitation",
                       "IDOR exploitation (only pattern indicators are reported)",
                       "Database dumping or inspection", "Private backend source-code inspection"],
        "findings": findings,
        "disclaimer": "External Assessment reports public observations and heuristic indicators, "
                       "not proof a site is secure or insecure.",
    }
    response.close()
    session.close()
    return result


# ============================================================================
# SECTION 9 -- SQLite persistence + change detection (E1.5 Watchdog data layer)
# ============================================================================
DB_PATH = os.environ.get("E1_DB_PATH", "e1_watchdog.db")
_db_lock = threading.Lock()


def _conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock, _conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, host TEXT NOT NULL, target TEXT NOT NULL, mode TEXT NOT NULL,
            created_at TEXT NOT NULL, score INTEGER, counts_json TEXT, report_json TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host, created_at)")
        conn.execute("""CREATE TABLE IF NOT EXISTS watch_targets (
            id TEXT PRIMARY KEY, target TEXT NOT NULL UNIQUE, interval_minutes INTEGER NOT NULL DEFAULT 1440,
            enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, last_run_at TEXT,
            ownership_verified INTEGER NOT NULL DEFAULT 0)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS review_overrides (
            scan_id TEXT NOT NULL, finding_title TEXT NOT NULL, endpoint TEXT, review_status TEXT NOT NULL,
            note TEXT, updated_at TEXT NOT NULL, PRIMARY KEY (scan_id, finding_title, endpoint))""")


def save_scan(report):
    scan_id = str(uuid.uuid4())
    with _db_lock, _conn() as conn:
        conn.execute(
            "INSERT INTO scans (id, host, target, mode, created_at, score, counts_json, report_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, report["host"], report["target"], report.get("mode", "External Assessment"),
             report["timestamp"], report.get("score"), json.dumps(report.get("counts", {})),
             json.dumps(report)))
    return scan_id


def get_scan(scan_id):
    with _db_lock, _conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    report = json.loads(row["report_json"])
    report["scan_id"] = row["id"]
    return report


def history_for_host(host, limit=25):
    with _db_lock, _conn() as conn:
        rows = conn.execute(
            "SELECT id, target, mode, created_at, score, counts_json FROM scans "
            "WHERE host=? ORDER BY created_at DESC LIMIT ?", (host, limit)).fetchall()
    return [{"scan_id": r["id"], "target": r["target"], "mode": r["mode"],
              "created_at": r["created_at"], "score": r["score"],
              "counts": json.loads(r["counts_json"] or "{}")} for r in rows]


def previous_scan_for_host(host):
    with _db_lock, _conn() as conn:
        row = conn.execute("SELECT report_json FROM scans WHERE host=? ORDER BY created_at DESC LIMIT 1",
                            (host,)).fetchone()
    return json.loads(row["report_json"]) if row else None


def add_watch_target(target, interval_minutes=1440):
    wid = str(uuid.uuid4())
    with _db_lock, _conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO watch_targets (id, target, interval_minutes, enabled, created_at) "
            "VALUES (?,?,?,1,?)", (wid, target, interval_minutes, datetime.now(timezone.utc).isoformat()))
    return wid


def list_watch_targets(enabled_only=True):
    with _db_lock, _conn() as conn:
        q = "SELECT * FROM watch_targets" + (" WHERE enabled=1" if enabled_only else "")
        return [dict(r) for r in conn.execute(q).fetchall()]


def mark_watch_run(target_id):
    with _db_lock, _conn() as conn:
        conn.execute("UPDATE watch_targets SET last_run_at=? WHERE id=?",
                      (datetime.now(timezone.utc).isoformat(), target_id))


def set_watch_ownership(target_id, verified):
    with _db_lock, _conn() as conn:
        conn.execute("UPDATE watch_targets SET ownership_verified=? WHERE id=?",
                      (1 if verified else 0, target_id))


def remove_watch_target(target_id):
    with _db_lock, _conn() as conn:
        conn.execute("DELETE FROM watch_targets WHERE id=?", (target_id,))


def diff_reports(previous, current):
    if not previous:
        return {"has_previous": False, "new_findings": [], "resolved_findings": [],
                "new_routes": [], "score_delta": None}

    def key(f):
        return (f["title"], f.get("endpoint"))

    prev_keys = {key(f) for f in previous.get("findings", [])}
    curr_keys = {key(f) for f in current.get("findings", [])}
    new_findings = [f for f in current.get("findings", []) if key(f) not in prev_keys]
    resolved = [f for f in previous.get("findings", []) if key(f) not in curr_keys]
    prev_routes = {e["url"] for e in previous.get("discovery", {}).get("endpoints", [])}
    curr_routes = current.get("discovery", {}).get("endpoints", [])
    new_routes = [e["url"] for e in curr_routes if e["url"] not in prev_routes]
    prev_score, curr_score = previous.get("score"), current.get("score")
    delta = (curr_score - prev_score) if (prev_score is not None and curr_score is not None) else None
    return {"has_previous": True, "previous_scan_at": previous.get("timestamp"),
            "new_findings": new_findings, "resolved_findings": resolved,
            "new_routes": new_routes, "score_delta": delta}


def set_review_status(scan_id, finding_title, endpoint, status, note=None):
    if status not in ("unreviewed", "confirmed", "false_positive"):
        raise ValueError("Invalid review status.")
    with _db_lock, _conn() as conn:
        conn.execute(
            "INSERT INTO review_overrides (scan_id, finding_title, endpoint, review_status, note, updated_at) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(scan_id, finding_title, endpoint) DO UPDATE SET "
            "review_status=excluded.review_status, note=excluded.note, updated_at=excluded.updated_at",
            (scan_id, finding_title, endpoint or "", status, note, datetime.now(timezone.utc).isoformat()))


def apply_review_overrides(scan_id, findings):
    with _db_lock, _conn() as conn:
        rows = conn.execute(
            "SELECT finding_title, endpoint, review_status, note FROM review_overrides WHERE scan_id=?",
            (scan_id,)).fetchall()
    overrides = {(r["finding_title"], r["endpoint"]): (r["review_status"], r["note"]) for r in rows}
    for f in findings:
        k = (f["title"], f.get("endpoint") or "")
        if k in overrides:
            f["review_status"], note = overrides[k]
            if note:
                f["review_note"] = note
    return findings


# ============================================================================
# SECTION 10 -- DNS-TXT ownership verification (real signal, not a checkbox)
# ============================================================================
TOKEN_TTL_SECONDS = 24 * 3600
_pending_tokens = {}  # host -> (token, expires_at)


def issue_token(host):
    token = secrets.token_hex(16)
    _pending_tokens[host] = (token, time.time() + TOKEN_TTL_SECONDS)
    return {
        "host": host, "record_name": f"_e1-watchdog-verify.{host}", "record_type": "TXT",
        "record_value": f"e1-verify={token}", "expires_in_seconds": TOKEN_TTL_SECONDS,
        "instructions": (f"Add a DNS TXT record named _e1-watchdog-verify.{host} with the value "
                          f"e1-verify={token}, then call /api/verify-ownership with this host."),
    }


def verify_ownership(host):
    entry = _pending_tokens.get(host)
    if not entry:
        return False, "No verification token was issued for this host. Call /api/request-ownership-token first."
    token, expires_at = entry
    if time.time() > expires_at:
        del _pending_tokens[host]
        return False, "Verification token expired. Request a new one."
    record_name = f"_e1-watchdog-verify.{host}"
    try:
        answers = dns.resolver.resolve(record_name, "TXT", lifetime=8)
    except Exception as exc:
        return False, f"Could not resolve TXT record: {str(exc)[:160]}"
    expected = f"e1-verify={token}"
    for rdata in answers:
        value = b"".join(rdata.strings).decode("utf-8", "ignore") if hasattr(rdata, "strings") else str(rdata)
        if expected in value:
            del _pending_tokens[host]
            return True, "DNS ownership verified."
    return False, "TXT record found but did not match the expected token."


# ============================================================================
# SECTION 11 -- OWASP ZAP integration (Authorized Deep Assessment only)
# This module contains NO attack payloads. All active testing is delegated
# to a real ZAP instance you run and scope yourself; we only orchestrate it
# and normalize its alerts into E1's finding schema.
# ============================================================================
ZAP_URL = os.environ.get("E1_ZAP_URL", "").rstrip("/")
ZAP_API_KEY = os.environ.get("E1_ZAP_API_KEY", "")
ZAP_POLL_INTERVAL = 3
ZAP_MAX_WAIT = int(os.environ.get("E1_ZAP_MAX_WAIT", "600"))

RISK_TO_SEVERITY = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
CONFIDENCE_MAP = {"High": "high", "Medium": "medium", "Low": "low"}


class ZapUnavailable(Exception):
    pass


def zap_is_configured():
    return bool(ZAP_URL)


def _zap_call(endpoint, **params):
    if not ZAP_URL:
        raise ZapUnavailable("E1_ZAP_URL is not configured on this server.")
    params["apikey"] = ZAP_API_KEY
    resp = requests.get(f"{ZAP_URL}{endpoint}", params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()


def zap_normalize_alerts(alerts):
    findings = []
    for a in alerts:
        severity = RISK_TO_SEVERITY.get(a.get("risk"), "info")
        confidence = CONFIDENCE_MAP.get(a.get("confidence"), "medium")
        findings.append({
            "title": a.get("alert", "ZAP finding"), "severity": severity,
            "category": (a.get("cweid") and f"CWE-{a['cweid']}") or "ZAP Active Scan",
            "evidence": (a.get("evidence") or a.get("description") or "")[:500],
            "impact": (a.get("description") or "")[:500],
            "remediation": (a.get("solution") or "Review the ZAP alert reference for remediation guidance.")[:500],
            "confidence": confidence, "endpoint": a.get("url"),
            "reproduction": {"request": f"{a.get('method', 'GET')} {a.get('url')}",
                              "observed_at": None, "zap_plugin_id": a.get("pluginId")},
            "review_status": "unreviewed",
            "remediation_priority": {"high": "this week", "medium": "this sprint",
                                      "low": "backlog", "info": "informational"}.get(severity, "backlog"),
            "source": "zap",
        })
    return findings


def run_zap_assessment(target_url, max_wait=None):
    """Blocking: spider then active-scan target_url through ZAP, return
    normalized findings. Caller MUST already have verified DNS ownership
    for this host -- enforced in the route handler, not here, so this
    function can't be called to bypass that gate."""
    max_wait = max_wait or ZAP_MAX_WAIT
    started = time.time()

    spider = _zap_call("/JSON/spider/action/scan/", url=target_url, recurse="true")
    spider_id = spider.get("scan")
    while True:
        status = _zap_call("/JSON/spider/view/status/", scanId=spider_id)
        if int(status.get("status", 0)) >= 100:
            break
        if time.time() - started > max_wait:
            raise ZapUnavailable("ZAP spider timed out.")
        time.sleep(ZAP_POLL_INTERVAL)

    ascan = _zap_call("/JSON/ascan/action/scan/", url=target_url, recurse="true", inScopeOnly="false")
    ascan_id = ascan.get("scan")
    while True:
        status = _zap_call("/JSON/ascan/view/status/", scanId=ascan_id)
        if int(status.get("status", 0)) >= 100:
            break
        if time.time() - started > max_wait:
            raise ZapUnavailable("ZAP active scan timed out (consider raising E1_ZAP_MAX_WAIT).")
        time.sleep(ZAP_POLL_INTERVAL)

    alerts = _zap_call("/JSON/core/view/alerts/", baseurl=target_url)
    return zap_normalize_alerts(alerts.get("alerts", []))


# ============================================================================
# SECTION 12 -- E1.5 Continuous Watchdog scheduler
# ============================================================================
_scheduler = BackgroundScheduler(daemon=True)


def _watchdog_run_one(target_row):
    try:
        report = run_scan(target_row["target"])
        report["watch_target_id"] = target_row["id"]
        previous = previous_scan_for_host(report["host"])
        diff = diff_reports(previous, report)
        report["change_since_last_scan"] = diff
        save_scan(report)
        mark_watch_run(target_row["id"])
        if diff["has_previous"] and (diff["new_findings"] or diff["new_routes"]):
            log.warning("Watchdog: %s has %d new finding(s), %d new route(s)",
                        report["host"], len(diff["new_findings"]), len(diff["new_routes"]))
    except Exception:
        log.exception("Watchdog run failed for %s", target_row.get("target"))


def _watchdog_tick():
    now = datetime.now(timezone.utc)
    for row in list_watch_targets(enabled_only=True):
        last = row.get("last_run_at")
        due = True
        if last:
            try:
                due = (now - datetime.fromisoformat(last)).total_seconds() >= row["interval_minutes"] * 60
            except Exception:
                due = True
        if due:
            _watchdog_run_one(row)


def start_watchdog(poll_minutes=5):
    if _scheduler.running:
        return
    _scheduler.add_job(_watchdog_tick, "interval", minutes=poll_minutes,
                        id="e1-watchdog-tick", replace_existing=True)
    _scheduler.start()
    log.info("E1 Watchdog scheduler started (checks every %s minute(s)).", poll_minutes)


# ============================================================================
# SECTION 13 -- Report export (downloadable HTML + E4-compatible schema)
# ============================================================================
E4_SCHEMA_VERSION = "1.0"


def to_e4_event(report):
    return {
        "schema_version": E4_SCHEMA_VERSION, "event_type": "website_security_assessment",
        "source_engine": "E1-Watchdog", "generated_at": datetime.now(timezone.utc).isoformat(),
        "subject": {"host": report.get("host"), "target": report.get("target")},
        "assessment": {"mode": report.get("mode"), "scan_id": report.get("scan_id"),
                        "timestamp": report.get("timestamp"), "score": report.get("score"),
                        "severity_counts": report.get("counts")},
        "findings": [{
            "id": f.get("endpoint", "") + "|" + f.get("title", ""), "title": f.get("title"),
            "severity": f.get("severity"), "confidence": f.get("confidence"),
            "review_status": f.get("review_status"), "category": f.get("category"),
            "endpoint": f.get("endpoint"), "evidence": f.get("evidence"), "impact": f.get("impact"),
            "remediation": f.get("remediation"), "remediation_priority": f.get("remediation_priority"),
            "source": f.get("source", "passive"),
        } for f in report.get("findings", [])],
        "change_since_last_scan": report.get("change_since_last_scan"),
    }


SEV_COLOR = {"critical": "#a3122a", "high": "#c2410c", "medium": "#a16207",
             "low": "#2563a8", "info": "#64748b"}


def to_html_report(report):
    rows = []
    for f in report.get("findings", []):
        color = SEV_COLOR.get(f.get("severity"), "#64748b")
        rows.append(f"""
        <div style="border:1px solid #d7dee5;border-left:4px solid {color};border-radius:6px;
                    padding:12px 14px;margin-bottom:10px">
          <div style="font-weight:600">
            <span style="background:{color};color:#fff;font-size:12px;padding:1px 8px;
                         border-radius:99px;margin-right:8px">{escape(f.get('severity','').upper())}</span>
            {escape(f.get('title',''))}
            <span style="float:right;font-size:12px;color:#64768a">{escape(f.get('confidence',''))}
             · {escape(f.get('review_status',''))}</span>
          </div>
          <p style="margin:6px 0;color:#334"><b>Evidence:</b> {escape(f.get('evidence',''))}</p>
          <p style="margin:6px 0;color:#334"><b>Impact:</b> {escape(f.get('impact',''))}</p>
          <p style="margin:6px 0;color:#334"><b>Fix:</b> {escape(f.get('remediation',''))}</p>
          <p style="margin:6px 0;color:#889">Priority: {escape(f.get('remediation_priority',''))}
             · Source: {escape(f.get('source','passive'))}</p>
        </div>""")
    counts = report.get("counts", {})
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>E1 Watchdog report -- {escape(report.get('host',''))}</title></head>
<body style="font-family:system-ui,sans-serif;max-width:760px;margin:30px auto;color:#10202f">
<h1 style="margin-bottom:4px">{escape(report.get('host',''))}</h1>
<p style="color:#64768a">{escape(report.get('mode',''))} · {escape(report.get('timestamp',''))}</p>
<h2 style="font-size:40px;margin:14px 0">{report.get('score','?')}<span style="font-size:18px;color:#64768a">/100</span></h2>
<p>Critical {counts.get('critical',0)} · High {counts.get('high',0)} · Medium {counts.get('medium',0)}
   · Low {counts.get('low',0)} · Info {counts.get('info',0)}</p>
<h3>Findings</h3>
{''.join(rows) if rows else '<p>No findings recorded.</p>'}
<p style="color:#889;font-size:13px;margin-top:24px">{escape(report.get('disclaimer',''))}</p>
</body></html>"""


# ============================================================================
# SECTION 14 -- Offline lab simulation (zero network calls to any target)
# ============================================================================
LAB = {
    "auth_bypass": ("Authentication / Authorization Bypass", "high",
        "Synthetic fixture: protected resource is missing a server-side role check.",
        "Enforce server-side authorization for each resource and action; deny by default.",
        "Compare two owner-controlled test roles in staging. No bypass is attempted."),
    "credential_guessing": ("Credential Guessing Defense", "medium",
        "Synthetic fixture: login throttling and alerts are unconfigured.",
        "Use per-account/source rate limits, MFA, progressive delays and alerting.",
        "Review control configuration; no passwords are guessed or submitted."),
    "database_exposure": ("Database Exposure Risk", "high",
        "Synthetic fixture: application DB role has over-broad privileges.",
        "Use least-privilege roles, restricted network access and audited grants.",
        "Review sanitized grants/schema metadata; no database connection is made."),
    "destructive_exploitation": ("Destructive Test Safeguard", "info",
        "Dry-run only: destructive operation is blocked and no request is sent.",
        "Use non-destructive tests; require isolated disposable labs and rollback plans.",
        "No modification, deletion, denial-of-service or payload delivery occurs."),
}


# ============================================================================
# SECTION 15 -- Flask app + routes
# ============================================================================
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per hour"], storage_uri="memory://")
init_db()
if os.environ.get("E1_ENABLE_WATCHDOG", "1") == "1":
    start_watchdog(poll_minutes=int(os.environ.get("E1_WATCHDOG_POLL_MINUTES", "5")))


@app.post("/api/scan")
@limiter.limit("10 per minute")
def api_scan():
    try:
        data = request.get_json(silent=True) or {}
        report = run_scan(data.get("url", ""))
        previous = previous_scan_for_host(report["host"])
        report["change_since_last_scan"] = diff_reports(previous, report)
        scan_id = save_scan(report)
        report["scan_id"] = scan_id
        return jsonify(report)
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.RequestException as exc:
        return jsonify({"error": f"Target request failed: {str(exc)[:160]}"}), 502
    except Exception:
        app.logger.exception("External assessment failed")
        return jsonify({"error": "Assessment failed. Check server logs."}), 500


@app.get("/api/history")
@limiter.limit("30 per minute")
def api_history():
    host = request.args.get("host", "").strip().lower()
    if not host:
        return jsonify({"error": "host query parameter is required."}), 400
    return jsonify({"host": host, "scans": history_for_host(host)})


@app.get("/api/report/<scan_id>")
def api_report_json(scan_id):
    report = get_scan(scan_id)
    if not report:
        return jsonify({"error": "Scan not found."}), 404
    report["findings"] = apply_review_overrides(scan_id, report["findings"])
    return jsonify(report)


@app.get("/api/report/<scan_id>.html")
def api_report_html(scan_id):
    report = get_scan(scan_id)
    if not report:
        return Response("Scan not found.", status=404)
    report["findings"] = apply_review_overrides(scan_id, report["findings"])
    return Response(to_html_report(report), mimetype="text/html")


@app.get("/api/report/<scan_id>/e4")
def api_report_e4(scan_id):
    report = get_scan(scan_id)
    if not report:
        return jsonify({"error": "Scan not found."}), 404
    report["findings"] = apply_review_overrides(scan_id, report["findings"])
    return jsonify(to_e4_event(report))


@app.post("/api/report/<scan_id>/review")
@limiter.limit("60 per minute")
def api_set_review(scan_id):
    data = request.get_json(silent=True) or {}
    try:
        set_review_status(scan_id, data.get("finding_title", ""), data.get("endpoint"),
                           data.get("status", ""), data.get("note"))
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/request-ownership-token")
@limiter.limit("10 per hour")
def api_request_token():
    data = request.get_json(silent=True) or {}
    try:
        _, host = validate_url(data.get("url", ""))
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(issue_token(host))


@app.post("/api/verify-ownership")
@limiter.limit("10 per hour")
def api_verify_ownership():
    data = request.get_json(silent=True) or {}
    try:
        _, host = validate_url(data.get("url", ""))
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400
    ok, message = verify_ownership(host)
    return jsonify({"host": host, "verified": ok, "message": message})


@app.post("/api/deep-assessment")
@limiter.limit("3 per hour")
def api_deep_assessment():
    data = request.get_json(silent=True) or {}
    try:
        url, host = validate_url(data.get("target", data.get("url", "")))
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400

    verified, message = verify_ownership(host)
    if not verified:
        return jsonify({
            "error": "Ownership not verified for this host.", "detail": message,
            "next_step": "POST /api/request-ownership-token with this url, add the DNS TXT "
                         "record, then POST /api/verify-ownership before retrying.",
        }), 403

    passive_report = run_scan(url)
    zap_findings, zap_status = [], "not_configured"
    if zap_is_configured():
        try:
            zap_findings = run_zap_assessment(url)
            zap_status = "completed"
        except ZapUnavailable as exc:
            zap_status = f"failed: {exc}"
    else:
        zap_status = "not_configured -- set E1_ZAP_URL / E1_ZAP_API_KEY to enable active scanning"

    findings = passive_report["findings"] + zap_findings
    counts = {k: sum(1 for f in findings if f["severity"] == k)
              for k in ("critical", "high", "medium", "low", "info")}
    result = {
        "engine": "CyberTotalX E1 -- Watchdog", "mode": "Authorized Deep Assessment",
        "target": url, "host": host, "timestamp": passive_report["timestamp"],
        "ownership_verification": {"verified": True, "method": "dns_txt"},
        "zap_status": zap_status, "score": score_findings(findings, url), "counts": counts,
        "discovery": passive_report["discovery"], "findings": findings,
        "security_boundary": {
            "blocked_actions": ["credential guessing", "database dumping", "destructive exploitation",
                                "manual payload crafting outside ZAP's scope"],
            "note": "All active testing (SQLi/XSS/auth/session) is performed exclusively by a "
                    "separately-run OWASP ZAP instance you control and scope; this service never "
                    "constructs attack payloads itself.",
        },
    }
    scan_id = save_scan(result)
    result["scan_id"] = scan_id
    return jsonify(result)


@app.post("/api/watch")
@limiter.limit("20 per hour")
def api_add_watch():
    data = request.get_json(silent=True) or {}
    try:
        url, host = validate_url(data.get("url", ""))
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400
    interval = int(data.get("interval_minutes", 1440))
    if interval < 15:
        return jsonify({"error": "interval_minutes must be at least 15."}), 400
    wid = add_watch_target(url, interval)
    verified, _ = verify_ownership(host)
    set_watch_ownership(wid, verified)
    return jsonify({"id": wid, "target": url, "interval_minutes": interval, "ownership_verified": verified})


@app.get("/api/watch")
def api_list_watch():
    return jsonify({"targets": list_watch_targets(enabled_only=False)})


@app.delete("/api/watch/<target_id>")
def api_remove_watch(target_id):
    remove_watch_target(target_id)
    return jsonify({"ok": True})


@app.post("/api/lab-simulation")
def api_lab_simulation():
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario")
    if scenario not in LAB:
        return jsonify({"error": "Choose one of the predefined offline scenarios.",
                         "choices": list(LAB.keys())}), 400
    title, severity, evidence, remediation, validation = LAB[scenario]
    return jsonify({"engine": "CyberTotalX E1 -- Watchdog", "mode": "Local Simulation Lab",
        "network_requests": 0, "target_accessed": False, "scenario": scenario,
        "result": {"title": title, "severity": severity, "status": "synthetic_simulation",
                   "evidence": evidence, "impact": "Illustrative risk only; not a finding about a real website.",
                   "remediation": remediation, "safe_validation": validation},
        "notice": "Synthetic demonstration only; no real target was accessed."})


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "zap_configured": zap_is_configured()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
