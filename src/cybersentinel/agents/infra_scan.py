import os
from typing import List, Dict, Any
from .base import Agent
from ..models import Finding, Severity

class InfraScanAgent(Agent):
    def __init__(self):
        super().__init__(
            name="InfraScanAgent",
            description="Audits infrastructure configurations (Dockerfiles, Kubernetes manifests, docker-compose) for security misconfigurations."
        )

    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(target):
            return findings

        if os.path.isfile(target):
            findings.extend(self._audit_file(target))
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                if any(part.startswith('.') for part in root.split(os.sep)):
                    continue
                for file in files:
                    file_path = os.path.join(root, file)
                    findings.extend(self._audit_file(file_path))

        return findings

    def _audit_file(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        basename = os.path.basename(file_path).lower()

        try:
            if "dockerfile" in basename:
                findings.extend(self._audit_dockerfile(file_path))
            elif basename.endswith((".yml", ".yaml")) and ("deployment" in basename or "pod" in basename or "k8s" in basename or "service" in basename):
                findings.extend(self._audit_k8s_manifest(file_path))
        except Exception:
            pass

        return findings

    def _audit_dockerfile(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        has_user = False
        has_latest_tag = False

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                upper = stripped.upper()

                if upper.startswith("FROM"):
                    if ":" not in upper or ":LATEST" in upper:
                        has_latest_tag = True
                        findings.append(Finding(
                            id=f"INFRA-DOCKER-TAG-{idx}",
                            title="Unpinned or Latest Base Image Tag",
                            severity=Severity.MEDIUM,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Dockerfile uses an unpinned or ':latest' tag on line {idx}.",
                            remediation="Use specific immutable image digests or version tags instead of 'latest'.",
                            cvss_score=5.3
                        ))

                if upper.startswith("USER"):
                    parts = stripped.split()
                    if len(parts) > 1 and parts[1] not in ["0", "root"]:
                        has_user = True

                if "apt-get install" in stripped and "-y" in stripped and "--no-install-recommends" not in stripped:
                    findings.append(Finding(
                        id=f"INFRA-DOCKER-REC-{idx}",
                        title="Missing --no-install-recommends in apt-get",
                        severity=Severity.LOW,
                        agent=self.name,
                        file_path=file_path,
                        line_number=idx,
                        description=f"Package manager installs packages without '--no-install-recommends' on line {idx}.",
                        remediation="Add '--no-install-recommends' to reduce container image attack surface.",
                        cvss_score=3.5
                    ))

        if not has_user:
            findings.append(Finding(
                id="INFRA-DOCKER-ROOT",
                title="Container Runs as Root User",
                severity=Severity.HIGH,
                agent=self.name,
                file_path=file_path,
                description="Dockerfile does not switch to a non-root user via 'USER' directive. Containers running as root risk host compromise if container isolation is breached.",
                remediation="Create and switch to a non-root user (e.g., 'RUN useradd -u 1000 appuser && USER appuser').",
                cvss_score=7.8
            ))

        return findings

    def _audit_k8s_manifest(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if "privileged: true" in content:
                findings.append(Finding(
                    id="INFRA-K8S-PRIV",
                    title="Privileged Kubernetes Container",
                    severity=Severity.CRITICAL,
                    agent=self.name,
                    file_path=file_path,
                    description="Kubernetes manifest specifies 'privileged: true', granting the container full access to host kernel and devices.",
                    remediation="Remove 'privileged: true' or restrict securityContext capabilities strictly to required minimums.",
                    cvss_score=9.0
                ))
            if "runAsRoot: true" in content or "runAsUser: 0" in content:
                findings.append(Finding(
                    id="INFRA-K8S-ROOT",
                    title="Kubernetes Pod Running as Root",
                    severity=Severity.HIGH,
                    agent=self.name,
                    file_path=file_path,
                    description="Kubernetes manifest explicitly configures pod/container to run as root.",
                    remediation="Set 'securityContext.runAsNonRoot: true' and specify a non-zero 'runAsUser'.",
                    cvss_score=7.5
                ))

        return findings
