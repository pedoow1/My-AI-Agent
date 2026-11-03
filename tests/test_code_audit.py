import os
import tempfile
import pytest
from cybersentinel.agents.code_audit import CodeAuditAgent
from cybersentinel.models import Severity

def test_code_audit_secret_detection():
    agent = CodeAuditAgent()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "config.py")
        with open(test_file, "w") as f:
            f.write("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
            f.write("API_SECRET = 'secret_key = \"1234567890abcdef1234567890abcdef\"'\n")

        findings = agent.run(tmpdir, {})
        assert len(findings) > 0
        severities = [f.severity for f in findings]
        assert Severity.CRITICAL in severities

def test_code_audit_unsafe_constructs():
    agent = CodeAuditAgent()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "app.py")
        with open(test_file, "w") as f:
            f.write("user_input = 'ls'\n")
            f.write("subprocess.run(user_input, shell=True)\n")
            f.write("eval('print(1)')\n")

        findings = agent.run(tmpdir, {})
        assert len(findings) >= 2
        titles = [f.title for f in findings]
        assert any("shell=True" in t for t in titles)
        assert any("eval" in t for t in titles)
