import ipaddress
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
TIMEOUT = 8
MAX_PAGES = 20
MAX_JS = 8
MAX_BYTES = 1_000_000
UA = "CyberTotalX-E1-Watchdog/0.2"


class ScanError(Exception):
    pass


def validate_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("URL is required.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ScanError("Only valid HTTP/HTTPS URLs are supported.")
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


def safe_get(url, session):
    current = url
    for _ in range(5):
        validate_url(current)
        response = session.get(current, allow_redirects=False, timeout=TIMEOUT,
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
            raise ScanError("Target response exceeds the MVP size limit.")
        body = bytearray()
        try:
            for chunk in response.iter_content(16384):
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    response.close()
                    raise ScanError("Target response exceeds the MVP size limit.")
        except Exception:
            response.close()
            raise
        response._content = bytes(body)
        response._content_consumed = True
        return response
    raise ScanError("Too many redirects.")


def finding(title, severity, category, evidence, impact, fix, confidence="high", endpoint=None):
    return {"title": title, "severity": severity, "category": category,
            "evidence": evidence, "impact": impact, "remediation": fix,
            "confidence": confidence, "endpoint": endpoint}


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
         "Consider a least-privilege Permissions-Policy.", "Browser capabilities are not explicitly constrained.")
    ]
    for name, title, sev, fix, impact in checks:
        if name not in h:
            out.append(finding(title, sev, "Security Headers",
                               f"Header {name} was not present on the inspected response.",
                               impact, fix, endpoint=url))
    if urlparse(url).scheme == "https" and "strict-transport-security" not in h:
        out.append(finding("HSTS header missing", "low", "Transport Security",
                           "No Strict-Transport-Security header was observed.",
                           "Clients may have weaker downgrade protection on future visits.",
                           "Consider HSTS after confirming HTTPS is supported across the domain.",
                           endpoint=url))
    if urlparse(url).scheme == "http":
        out.append(finding("Website is served over HTTP", "high", "Transport Security",
                           f"Submitted URL uses HTTP: {url}",
                           "Traffic may be intercepted or modified in transit.",
                           "Serve the site over HTTPS and redirect HTTP to HTTPS.", endpoint=url))
    disclose = [f"{k}: {h[k]}" for k in ("server", "x-powered-by") if h.get(k)]
    if disclose:
        out.append(finding("Technology disclosure headers observed", "info", "Information Disclosure",
                           "; ".join(disclose), "Technology fingerprints can help adversaries prioritize research.",
                           "Remove unnecessary framework/version disclosure.", endpoint=url))
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
                                   impact, fix, endpoint=url))
    return out


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
        endpoints.append({"url": url, "method": "GET", "status": resp.status_code,
                          "content_type": resp.headers.get("Content-Type", ""), "source": "crawler"})
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


def inspect_js(urls, session):
    out = []
    patterns = [
        ("Potential API key pattern", re.compile(r"\b(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_-]{16,}['\"]", re.I)),
        ("Potential token/secret pattern", re.compile(r"\b(?:secret|access[_-]?token|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_-]{20,}['\"]", re.I))
    ]
    for url in urls:
        try:
            resp = safe_get(url, session)
            body = resp.text[:MAX_BYTES]
            resp.close()
        except Exception:
            continue
        for title, pattern in patterns:
            if pattern.search(body):
                out.append(finding(title, "high", "Exposure",
                    f"A credential-like assignment pattern matched in public JavaScript at {url}; this is not proof of a live secret.",
                    "A real privileged credential in a client bundle may enable unauthorized access.",
                    "Verify ownership and validity, rotate real exposed credentials, and move privileged operations server-side.",
                    "medium", url))
    return out


def score_findings(findings, url):
    deductions = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
    score = 100 - sum(deductions.get(f["severity"], 0) for f in findings)
    if urlparse(url).scheme == "http":
        score -= 15
    return max(0, min(score, 100))


def run_scan(raw):
    url, host = validate_url(raw)
    session, started = requests.Session(), time.time()
    response = safe_get(url, session)
    findings = inspect_headers(response, url)
    tls = {"available": False}
    if urlparse(url).scheme == "https":
        try:
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as secure:
                    cipher = secure.cipher()
                    tls = {"available": True, "version": secure.version(),
                           "cipher": cipher[0] if cipher else None,
                           "certificate_expires": secure.getpeercert().get("notAfter")}
        except Exception as exc:
            tls = {"available": False, "error": str(exc)[:120]}
    endpoints, scripts = discover(url, session)
    findings.extend(inspect_js(scripts, session))
    counts = {key: sum(1 for f in findings if f["severity"] == key)
              for key in ("critical", "high", "medium", "low", "info")}
    result = {
        "engine": "CyberTotalX E1 — Watchdog", "mode": "External Assessment",
        "target": url, "host": host, "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.time() - started) * 1000),
        "score": score_findings(findings, url), "counts": counts,
        "target_response": {"status": response.status_code,
                            "content_type": response.headers.get("Content-Type"),
                            "server": response.headers.get("Server"), "final_url": response.url},
        "tls": tls, "discovery": {"endpoints": endpoints, "javascript": scripts,
                                  "pages_scanned": len(endpoints)},
        "tested": ["HTTP/HTTPS response", "Common security headers", "Basic cookie flags",
                   "Redirect target validation", "Same-origin public routes",
                   "Credential-like patterns in public JavaScript"],
        "not_tested": ["Authentication bypass", "Credential guessing", "SQLi/XSS exploitation",
                       "Database dumping or inspection", "Private backend source-code inspection"],
        "findings": findings,
        "disclaimer": "External Assessment reports public observations and heuristic indicators, not proof a site is secure."
    }
    response.close()
    session.close()
    return result


ALLOWED_DEEP_CHECKS = {"api_inventory", "auth_session_review", "authorization_review",
                       "sqli_safe_validation", "xss_safe_validation", "data_exposure_review"}


def run_deep(data):
    if data.get("authorization") is not True:
        raise ScanError("Authorized Deep Assessment requires authorization confirmation.")
    url, host = validate_url(data.get("target", ""))
    checks = data.get("checks") or []
    if not isinstance(checks, list) or set(checks) - ALLOWED_DEEP_CHECKS:
        raise ScanError("One or more deep assessment check names are invalid.")
    session = requests.Session()
    response = safe_get(url, session)
    endpoints, scripts = discover(url, session)
    reviews = []
    for key in checks:
        details = {
            "api_inventory": ("API inventory", "completed", f"{sum(1 for e in endpoints if re.search(r'/(api|graphql|rest|v[0-9]+)(/|$)', urlparse(e['url']).path, re.I))} API-like routes identified from discovered pages."),
            "auth_session_review": ("Authentication/session review", "evidence_collected", "Review cookies and use owner-provided test accounts for full validation."),
            "authorization_review": ("Authorization review", "requires_test_accounts", "Compare two owner-controlled roles in staging; no bypass is attempted."),
            "sqli_safe_validation": ("SQL injection safe validation", "safe_validation_only", "Inventory input routes and review parameterized query use; no exploit payload is sent."),
            "xss_safe_validation": ("XSS safe validation", "safe_validation_only", "Review input/output encoding with safe canaries in staging; no exploit payload is executed."),
            "data_exposure_review": ("Data exposure review", "evidence_collected", "Public response metadata is collected; private database access needs an owner-provided integration.")
        }[key]
        reviews.append({"check": details[0], "status": details[1], "evidence": details[2]})
    response.close()
    session.close()
    return {"engine": "CyberTotalX E1 — Watchdog", "mode": "Authorized Deep Assessment",
            "target": url, "host": host, "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_response": {"status": response.status_code,
                                "content_type": response.headers.get("Content-Type")},
            "discovery": {"endpoints": endpoints, "javascript": scripts},
            "findings": inspect_headers(response, url), "deep_review": reviews,
            "security_boundary": {"blocked_actions": ["authentication bypass", "credential guessing",
                "database dumping", "destructive exploitation"]},
            "note": "Owner-authorized review scaffold. Use test accounts and a dedicated staging environment."}


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
        "Use non-destructive tests; require isolated disposable labs and rollback plans for approved destructive tests.",
        "No modification, deletion, denial-of-service or payload delivery occurs.")
}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    try:
        data = request.get_json(silent=True) or {}
        return jsonify(run_scan(data.get("url", "")))
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.RequestException as exc:
        return jsonify({"error": f"Target request failed: {str(exc)[:160]}"}), 502
    except Exception:
        app.logger.exception("External assessment failed")
        return jsonify({"error": "Assessment failed. Check server logs."}), 500


@app.post("/api/deep-assessment")
def api_deep_assessment():
    try:
        return jsonify(run_deep(request.get_json(silent=True) or {}))
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.RequestException as exc:
        return jsonify({"error": f"Target request failed: {str(exc)[:160]}"}), 502
    except Exception:
        app.logger.exception("Deep assessment failed")
        return jsonify({"error": "Deep assessment failed. Check server logs."}), 500


@app.post("/api/lab-simulation")
def api_lab_simulation():
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario")
    if scenario not in LAB:
        return jsonify({"error": "Choose one of the predefined offline scenarios."}), 400
    title, severity, evidence, remediation, validation = LAB[scenario]
    return jsonify({"engine": "CyberTotalX E1 — Watchdog", "mode": "Local Simulation Lab",
        "network_requests": 0, "target_accessed": False, "scenario": scenario,
        "result": {"title": title, "severity": severity, "status": "synthetic_simulation",
                   "evidence": evidence, "impact": "Illustrative risk only; not a finding about a real website.",
                   "remediation": remediation, "safe_validation": validation},
        "notice": "Synthetic demonstration only; no real target was accessed."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
