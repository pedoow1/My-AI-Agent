import os
import tempfile
import pytest
from cybersentinel.agents.infra_scan import InfraScanAgent
from cybersentinel.models import Severity

def test_infra_scan_dockerfile():
    agent = InfraScanAgent()
    with tempfile.TemporaryDirectory() as tmpdir:
        dockerfile = os.path.join(tmpdir, "Dockerfile")
        with open(dockerfile, "w") as f:
            f.write("FROM python:latest\n")
            f.write("RUN apt-get update && apt-get install -y curl\n")

        findings = agent.run(tmpdir, {})
        assert len(findings) > 0
        titles = [f.title for f in findings]
        assert any("Container Runs as Root User" in t for t in titles)
        assert any("Unpinned or Latest Base Image Tag" in t for t in titles)

def test_infra_scan_k8s():
    agent = InfraScanAgent()
    with tempfile.TemporaryDirectory() as tmpdir:
        k8s_file = os.path.join(tmpdir, "deployment.yaml")
        with open(k8s_file, "w") as f:
            f.write("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n")

        findings = agent.run(tmpdir, {})
        assert len(findings) > 0
        titles = [f.title for f in findings]
        assert any("Privileged Kubernetes Container" in t for t in titles)
