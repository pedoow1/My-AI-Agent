import os
import tempfile
import pytest
from cybersentinel.agents.master import CyberSentinelMaster
from cybersentinel.agents.code_audit import CodeAuditAgent
from cybersentinel.agents.infra_scan import InfraScanAgent
from cybersentinel.agents.web_scan import WebVulnScanAgent
from cybersentinel.models import Severity

def test_advanced_resilience_multi_vuln_fuzzing():
    """
    Advanced test case to verify that the master and subagents can simultaneously
    catch complex multi-vector vulnerabilities (eval, hardcoded secrets, unsafe docker, sql i).
    This upgrades future test suite robustness and coverage.
    """
    master = CyberSentinelMaster()
    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Unsafe Python code (eval, shell=True)
        py_file = os.path.join(tmpdir, "processor.py")
        with open(py_file, "w") as f:
            f.write("import os\n")
            f.write("eval(user_input)\n")
            f.write("os.system('rm -rf /')\n")
            f.write("API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

        # 2. Unsafe Dockerfile
        docker_file = os.path.join(tmpdir, "Dockerfile")
        with open(docker_file, "w") as f:
            f.write("FROM ubuntu:latest\n")
            f.write("USER root\n")
            f.write("RUN apt-get update && apt-get install -y curl\n")

        # 3. Unsafe JS web route
        js_file = os.path.join(tmpdir, "app.js")
        with open(js_file, "w") as f:
            f.write("connection.query(`SELECT * FROM records WHERE id = ${req.query.id}`);\n")

        result = master.scan(tmpdir)
        
        # Assertions for comprehensive multi-agent coverage
        assert len(result.findings) >= 4
        
        severities = [f.severity for f in result.findings]
        assert Severity.CRITICAL in severities or Severity.HIGH in severities

        # Verify summary counts
        summary = result.summary()
        assert sum(summary.values()) == len(result.findings)

        # Verify agent metadata attribution
        assert "CodeAuditAgent" in result.metadata["scanned_agents"]
        assert "InfraScanAgent" in result.metadata["scanned_agents"]
        assert "WebVulnScanAgent" in result.metadata["scanned_agents"]

def test_empty_and_malformed_target_resilience():
    """
    Verify agent resilience against empty directories or missing files without crashing.
    """
    master = CyberSentinelMaster()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = master.scan(tmpdir)
        assert result is not None
        assert isinstance(result.findings, list)
