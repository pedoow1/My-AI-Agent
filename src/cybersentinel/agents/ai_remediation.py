import os
from typing import List, Dict, Any
from .base import Agent
from ..models import Finding, Severity

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

class AiRemediationAgent(Agent):
    def __init__(self):
        super().__init__(
            name="AiRemediationAgent",
            description="Leverages Gemini AI to generate intelligent threat analysis and production-ready remediation code patches for security findings."
        )
        self.api_key = os.environ.get("GEMINI_API_KEY")
        self.client = None
        if HAS_GENAI and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None

    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        """
        Enhances existing findings or produces AI remediation recommendations.
        Context can pass existing findings under 'findings'.
        """
        findings: List[Finding] = context.get("findings", [])
        if not self.client or not findings:
            return []

        enhanced_findings: List[Finding] = []
        for finding in findings:
            try:
                prompt = (
                    f"You are a senior cybersecurity expert and secure coding advisor.\n"
                    f"Analyze the following security vulnerability finding and provide a production-ready code patch and secure remediation guidance.\n\n"
                    f"Vulnerability: {finding.title}\n"
                    f"Severity: {finding.severity.value}\n"
                    f"File/Target: {finding.file_path or target}\n"
                    f"Line: {finding.line_number or 'N/A'}\n"
                    f"Description: {finding.description}\n\n"
                    f"Provide a concise, highly secure code fix and explanation."
                )

                response = self.client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                )
                if response and response.text:
                    finding.remediation += f"\n\n[Gemini AI Advisor Patch]:\n{response.text.strip()}"
            except Exception as e:
                # Fallback gracefully if API rate limits or network issues occur
                finding.remediation += f"\n\n[Gemini AI Advisor Note]: Could not generate AI patch due to API error: {e}"

            enhanced_findings.append(finding)

        return enhanced_findings
