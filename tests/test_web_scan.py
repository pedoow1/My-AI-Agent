import os
import tempfile
import pytest
from cybersentinel.agents.web_scan import WebVulnScanAgent
from cybersentinel.agents.master import CyberSentinelMaster
from cybersentinel.models import Severity

def test_web_scan_sqli_and_xss():
    agent = WebVulnScanAgent()
    with tempfile.TemporaryDirectory() as tmpdir:
        app_file = os.path.join(tmpdir, "app.py")
        with open(app_file, "w") as f:
            f.write("cursor.execute(f'SELECT * FROM users WHERE id = {request.args.get(\"id\")}')\n")
            f.write("return render_template_string(request.args.get('input'))\n")

        findings = agent.run(tmpdir, {})
        assert len(findings) >= 2
        titles = [f.title for f in findings]
        assert any("SQL Injection" in t for t in titles)
        assert any("Cross-Site Scripting" in t for t in titles)

def test_web_scan_ssrf_and_jwt():
    agent = WebVulnScanAgent()
    with tempfile.TemporaryDirectory() as tmpdir:
        api_file = os.path.join(tmpdir, "api.js")
        with open(api_file, "w") as f:
            f.write("const res = await axios.get(req.query.url);\n")
            f.write("const token = jwt.sign({sub: user.id}, 'secret');\n")

        findings = agent.run(tmpdir, {})
        assert len(findings) >= 2
        titles = [f.title for f in findings]
        assert any("Server-Side Request Forgery" in t for t in titles)
        assert any("JWT" in t for t in titles)

def test_master_with_web_scan():
    master = CyberSentinelMaster()
    with tempfile.TemporaryDirectory() as tmpdir:
        vuln_file = os.path.join(vuln_path := os.path.join(tmpdir, "server.js"), "")
        # wait, write to server.js
        server_path = os.path.join(tmpdir, "server.js")
        with open(server_path, "w") as f:
            f.write("db.query('SELECT * FROM accounts WHERE user = ' + req.body.user);\n")

        result = master.scan(tmpdir)
        assert "WebVulnScanAgent" in result.metadata["scanned_agents"]
        assert len(result.findings) > 0
        assert any(f.agent == "WebVulnScanAgent" for f in result.findings)

def test_web_audit_url_missing_headers(monkeypatch):
    agent = WebVulnScanAgent()

    class MockResponse:
        def __init__(self):
            self.headers = {
                "content-type": "text/html",
                "server": "nginx/1.18.0"
            }
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=5: MockResponse())

    findings = agent.run("https://example.com", {})
    titles = [f.title for f in findings]
    assert any("Permissions-Policy" in t for t in titles)
    assert any("Referrer-Policy" in t for t in titles)
    assert any("Server Software Version Disclosure" in t for t in titles)


def test_url_target_without_active_finds_no_critical():
    """A plain URL scan (no --active) can only ever surface header/cookie
    issues (LOW/MEDIUM) — it must never claim CRITICAL/HIGH without having
    actually tested anything."""
    agent = WebVulnScanAgent()

    class MockResponse:
        headers = {"content-type": "text/html"}
        def read(self, n):
            return b"<html>hello</html>"
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    import urllib.request
    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda req, timeout=5: MockResponse()
    try:
        findings = agent.run("http://vulnerable-test-site.local", {"active": False})
    finally:
        urllib.request.urlopen = orig

    assert findings, "passive header checks should still fire"
    assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)


def test_active_probe_detects_sqli_and_xss_via_mocked_network():
    """With --active, a vulnerable param (error-based SQLi + reflected XSS)
    must be confirmed as CRITICAL/HIGH. No real network traffic is sent;
    the HTTP layer is fully mocked."""
    agent = WebVulnScanAgent()

    def fake_fetch(self, url, method="GET", data=None):
        from urllib.parse import urlparse, parse_qs
        values = []
        for v in parse_qs(urlparse(url).query).values():
            values.extend(v)
        if data:
            for v in parse_qs(data.decode()).values():
                values.extend(v)
        joined = " ".join(values)
        if "'" in joined:
            return "Error: you have an error in your SQL syntax near '''", 500
        if "<zz" in joined:
            return f"<html>{joined}</html>", 200
        return "<html><a href='/x'>x</a></html>", 200

    agent._fetch = fake_fetch.__get__(agent, WebVulnScanAgent)
    findings = agent._active_probe(
        "http://vulnerable-test-site.local/search?q=test",
        "<html><a href='/x'>x</a></html>",
    )
    titles = [f.title for f in findings]
    assert any("SQL Injection" in t for t in titles)
    assert any("Cross-Site Scripting" in t for t in titles)
    assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
