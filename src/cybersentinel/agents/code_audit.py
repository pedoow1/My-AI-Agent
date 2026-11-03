import os
import re
from typing import List, Dict, Any
from .base import Agent
from ..models import Finding, Severity

class CodeAuditAgent(Agent):
    def __init__(self):
        super().__init__(
            name="CodeAuditAgent",
            description="Performs static application security testing (SAST), secret detection, and dependency vulnerability checks."
        )
        # Regex patterns for secrets
        self.secret_patterns = [
            ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
            ("GitHub Personal Access Token", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
            ("Private RSA Key", re.compile(r"-----BEGIN PRIVATE KEY-----")),
            ("Generic API Key / Secret", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"'][a-zA-Z0-9_\-\.]{16,64}['\"']")),
        ]
        # Known vulnerable dependency patterns
        self.vulnerable_deps = {
            "requests": ["<2.31.0"],
            "flask": ["<2.2.5", "<3.0.3"],
            "django": ["<4.2.11", "<5.0.3"],
            "lodash": ["<4.17.21"],
            "axios": ["<1.6.0"],
        }

    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(target):
            return findings

        if os.path.isfile(target):
            findings.extend(self._audit_file(target))
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                # Skip hidden directories like .git
                if any(part.startswith('.') for part in root.split(os.sep)):
                    continue
                for file in files:
                    file_path = os.path.join(root, file)
                    findings.extend(self._audit_file(file_path))

        return findings

    def _audit_file(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            # Check for dependency files
            basename = os.path.basename(file_path).lower()
            if basename in ["requirements.txt", "package.json", "setup.py"]:
                findings.extend(self._audit_dependency_file(file_path, basename))

            # Read source code files for secrets / unsafe code
            if basename.endswith((".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".sh", ".go")):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    for idx, line in enumerate(lines, start=1):
                        # Check secrets
                        for sec_name, pattern in self.secret_patterns:
                            if pattern.search(line):
                                findings.append(Finding(
                                    id=f"CODE-SEC-{idx}",
                                    title=f"Hardcoded {sec_name} Detected",
                                    severity=Severity.CRITICAL,
                                    agent=self.name,
                                    file_path=file_path,
                                    line_number=idx,
                                    description=f"Found potential hardcoded secret matching pattern '{sec_name}' on line {idx}.",
                                    remediation="Remove hardcoded secrets from source code and use environment variables or a secure secret manager (e.g. AWS Secrets Manager, HashiCorp Vault).",
                                    cvss_score=9.8
                                ))
                        # Check unsafe constructs (e.g. eval, exec, shell=True)
                        if "eval(" in line or "exec(" in line:
                            findings.append(Finding(
                                id=f"CODE-UNSAFE-{idx}",
                                title="Use of Unsafe Dynamic Evaluation (eval/exec)",
                                severity=Severity.HIGH,
                                agent=self.name,
                                file_path=file_path,
                                line_number=idx,
                                description=f"Found use of `eval()` or `exec()` on line {idx}, which can lead to Remote Code Execution (RCE).",
                                remediation="Avoid dynamic code execution. Refactor logic to use safe parsers or structured control flow.",
                                cvss_score=8.5
                            ))
                        if "shell=True" in line:
                            findings.append(Finding(
                                id=f"CODE-SHELL-{idx}",
                                title="Command Injection Risk (shell=True)",
                                severity=Severity.HIGH,
                                agent=self.name,
                                file_path=file_path,
                                line_number=idx,
                                description=f"Found subprocess call with `shell=True` on line {idx}.",
                                remediation="Pass arguments as a list with `shell=False` to prevent OS command injection vulnerabilities.",
                                cvss_score=8.2
                            ))
        except Exception:
            pass
        return findings

    def _audit_dependency_file(self, file_path: str, basename: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for dep, vuln_versions in self.vulnerable_deps.items():
                    if dep in content.lower():
                        findings.append(Finding(
                            id=f"DEP-{dep.upper()}",
                            title=f"Potentially Vulnerable Dependency: {dep}",
                            severity=Severity.MEDIUM,
                            agent=self.name,
                            file_path=file_path,
                            description=f"Dependency '{dep}' was detected in {basename}. Ensure it is updated to patched versions.",
                            remediation=f"Upgrade {dep} to the latest secure version.",
                            cvss_score=6.5
                        ))
        except Exception:
            pass
        return findings
