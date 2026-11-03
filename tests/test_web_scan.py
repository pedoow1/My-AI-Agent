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

