from typing import List, Dict, Any
from ..models import Finding, ScanResult
from .code_audit import CodeAuditAgent
from .infra_scan import InfraScanAgent
from .web_scan import WebVulnScanAgent
from .sbom import SbomAgent
from .report import ReportAgent
from .ai_remediation import AiRemediationAgent

class CyberSentinelMaster:
    def __init__(self):
        self.code_audit_agent = CodeAuditAgent()
        self.infra_scan_agent = InfraScanAgent()
        self.web_scan_agent = WebVulnScanAgent()
        self.sbom_agent = SbomAgent()
        self.ai_remediation_agent = AiRemediationAgent()
        self.report_agent = ReportAgent()

    def scan(self, target: str, ai: bool = False, active: bool = False) -> ScanResult:
        all_findings: List[Finding] = []
        is_url = target.startswith(("http://", "https://"))

        # 1. Run Code Audit Agent (no-op on a bare URL target: needs local source)
        code_findings = self.code_audit_agent.run(target, {})
        all_findings.extend(code_findings)

        # 2. Run Infrastructure Scan Agent (no-op on a bare URL target: needs local Dockerfile/K8s files)
        infra_findings = self.infra_scan_agent.run(target, {})
        all_findings.extend(infra_findings)

        # 3. Run Web Vulnerability Scan Agent. `active=True` makes it crawl
        # same-origin pages/forms and inject SQLi/XSS test payloads instead of
        # only auditing response headers/cookies — required to find
        # CRITICAL/HIGH issues like SQLi on a live URL target.
        web_findings = self.web_scan_agent.run(target, {"active": active})
        all_findings.extend(web_findings)

        # 4. Run SBOM Agent (Live CVE Intelligence)
        sbom_findings = self.sbom_agent.run(target, {})
        all_findings.extend(sbom_findings)

        scanned_agents = [
            self.code_audit_agent.name,
            self.infra_scan_agent.name,
            self.web_scan_agent.name,
            self.sbom_agent.name
        ]

        # 5. Run AI Remediation Agent if requested and configured
        if ai and self.ai_remediation_agent.client:
            ai_findings = self.ai_remediation_agent.run(target, {"findings": all_findings})
            # Findings are enhanced in place, but let's ensure all_findings is updated
            all_findings = ai_findings
            scanned_agents.append(self.ai_remediation_agent.name)

        # 6. Construct ScanResult
        metadata: Dict[str, Any] = {"scanned_agents": scanned_agents}
        if is_url:
            metadata["note"] = (
                "Target is a URL: CodeAuditAgent, InfraScanAgent and SbomAgent need a local "
                "checkout (source files, Dockerfiles/K8s manifests, dependency manifests) and "
                "produced no findings for that reason, not because nothing was found."
            )
            if not active:
                metadata["note"] += (
                    " WebVulnScanAgent ran passive header/cookie checks only; pass --active "
                    "to crawl pages/forms and test for SQLi/XSS."
                )
        result = ScanResult(
            target=target,
            findings=all_findings,
            metadata=metadata
        )

        return result
