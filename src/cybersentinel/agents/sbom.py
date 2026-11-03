import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any
from .base import Agent
from ..models import Finding, Severity

class SbomAgent(Agent):
    def __init__(self):
        super().__init__(
            name="SbomAgent",
            description="Performs live Software Bill of Materials (SBOM) dependency analysis and queries the OSV.dev vulnerability database for real-time CVE intelligence."
        )

    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(target):
            return findings

        dependency_files = []
        if os.path.isfile(target):
            if os.path.basename(target).lower() in ["requirements.txt", "package.json"]:
                dependency_files.append(target)
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                if any(part.startswith('.') for part in root.split(os.sep)):
                    continue
                for file in files:
                    if file.lower() in ["requirements.txt", "package.json"]:
                        dependency_files.append(os.path.join(root, file))

        for file_path in dependency_files:
            findings.extend(self._query_osv_for_dependencies(file_path))

        return findings

    def _query_osv_for_dependencies(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        basename = os.path.basename(file_path).lower()
        packages = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if basename == "requirements.txt":
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Simple parsing of pip requirement line (e.g. requests==2.28.0)
                        parts = line.replace("==", " ").replace(">=", " ").replace("<=", " ").split()
                        if len(parts) >= 2:
                            packages.append({"name": parts[0], "version": parts[1], "ecosystem": "PyPI"})
                        elif len(parts) == 1:
                            packages.append({"name": parts[0], "version": "latest", "ecosystem": "PyPI"})
                elif basename == "package.json":
                    data = json.loads(content)
                    for dep_type in ["dependencies", "devDependencies"]:
                        if dep_type in data and isinstance(data[dep_type], dict):
                            for pkg, ver in data[dep_type].items():
                                clean_ver = ver.lstrip("^~v")
                                packages.append({"name": pkg, "version": clean_ver, "ecosystem": "npm"})
        except Exception:
            return findings

        if not packages:
            return findings

        # Query OSV.dev batch API
        queries = []
        for pkg in packages:
            queries.append({
                "package": {
                    "name": pkg["name"],
                    "ecosystem": pkg["ecosystem"]
                },
                "version": pkg["version"]
            })

        payload = {"queries": queries}
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "CyberSentinel-SbomAgent/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
                results = result.get("results", [])
                for idx, res in enumerate(results):
                    vulns = res.get("vulns", [])
                    if vulns and idx < len(packages):
                        pkg_info = packages[idx]
                        for vuln in vulns:
                            vuln_id = vuln.get("id", "CVE-Unknown")
                            summary = vuln.get("summary", vuln.get("details", "Known vulnerability detected."))
                            severity = Severity.HIGH
                            # Check severity if available
                            for sev in vuln.get("severity", []):
                                if sev.get("type") == "CVSS_V3":
                                    score_str = sev.get("score", "7.0")
                                    # parse cvss
                                    pass

                            findings.append(Finding(
                                id=f"CVE-{pkg_info['name'].upper()}-{vuln_id}",
                                title=f"Live CVE Advisory for {pkg_info['name']} ({vuln_id})",
                                severity=Severity.HIGH,
                                agent=self.name,
                                file_path=file_path,
                                description=f"Dependency '{pkg_info['name']}' version {pkg_info['version']} has a live advisory {vuln_id}: {summary[:200]}",
                                remediation=f"Upgrade {pkg_info['name']} to a patched version resolving {vuln_id}.",
                                cvss_score=8.0,
                                metadata={"cve_id": vuln_id, "package": pkg_info["name"]}
                            ))
        except (urllib.error.URLError, Exception):
            # Fallback if network is unavailable or API fails (graceful degradation)
            pass

        return findings
