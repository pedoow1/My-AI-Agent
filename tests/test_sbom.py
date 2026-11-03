import os
import tempfile
import pytest
from cybersentinel.agents.sbom import SbomAgent
from cybersentinel.agents.master import CyberSentinelMaster

def test_sbom_agent_requirements():
    agent = SbomAgent()
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = os.path.join(tmpdir, "requirements.txt")
        with open(req_file, "w") as f:
            f.write("requests==2.28.0\n")

        findings = agent.run(tmpdir, {})
        # SbomAgent runs successfully (and gracefully handles API success/failure)
        assert isinstance(findings, list)

def test_master_with_sbom():
    master = CyberSentinelMaster()
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = os.path.join(tmpdir, "requirements.txt")
        with open(req_file, "w") as f:
            f.write("flask==2.1.0\n")

        result = master.scan(tmpdir)
        assert "SbomAgent" in result.metadata["scanned_agents"]
