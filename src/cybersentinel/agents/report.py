import json
from typing import List, Dict, Any
from .base import Agent
from ..models import Finding, ScanResult, Severity

class ReportAgent(Agent):
    def __init__(self):
        super().__init__(
            name="ReportAgent",
            description="Aggregates security findings, calculates risk posture, and generates professional Markdown and JSON reports."
        )

    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        # ReportAgent acts on existing findings in context rather than scanning files directly
        return context.get("findings", [])

    def generate_markdown_report(self, result: ScanResult) -> str:
        summary = result.summary()
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        
        # Sort findings by severity order
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99
        )

        md = []
        md.append("# CyberSentinel Security Assessment Report\n")
        md.append(f"**Target:** `{result.target}`\n")
        md.append(f"**Total Findings:** {len(result.findings)}\n")
        
        md.append("## Executive Summary\n")
        md.append("| Severity | Count |")
        md.append("|----------|-------|")
        for sev in severity_order:
            count = summary.get(sev.value, 0)
            md.append(f"| {sev.value} | {count} |")
        md.append("\n---")

        md.append("## Detailed Findings\n")
        if not sorted_findings:
            md.append("No security vulnerabilities or misconfigurations detected! 🎉\n")
        else:
            for idx, finding in enumerate(sorted_findings, start=1):
                md.append(f"### {idx}. [{finding.severity.value}] {finding.title}")
                md.append(f"- **ID:** `{finding.id}`")
                md.append(f"- **Agent:** `{finding.agent}`")
                if finding.file_path:
                    loc = f"`{finding.file_path}`"
                    if finding.line_number:
                        loc += f" (Line {finding.line_number})"
                    md.append(f"- **Location:** {loc}")
                md.append(f"- **CVSS Score:** `{finding.cvss_score}`")
                md.append(f"\n**Description:**\n{finding.description}\n")
                md.append(f"\n**Remediation:**\n{finding.remediation}\n")
                md.append("---\n")

        return "\n".join(md)

    def generate_json_report(self, result: ScanResult) -> str:
        data = {
            "target": result.target,
            "summary": result.summary(),
            "total_findings": len(result.findings),
            "findings": [f.to_dict() for f in result.findings]
        }
        return json.dumps(data, indent=2)
