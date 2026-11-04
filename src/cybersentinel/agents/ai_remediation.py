import os
from typing import List, Dict, Any, Optional, Tuple
from .base import Agent
from ..models import Finding, Severity

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

DEFAULT_MODEL = "gemini-2.5-flash"

SYSTEM_INSTRUCTION = (
    "You are a world-class senior security engineer reviewing the output of a dumb "
    "regex-based scanner. The scanner's title/description/remediation are only a LEAD, "
    "not a fact — they are often wrong. You are given the ACTUAL surrounding source "
    "code for the flagged line. First, judge for yourself, from that real code, whether "
    "this is a genuine vulnerability or a false positive (e.g. input already validated "
    "upstream, dead/test code, a safe library call that merely matches the pattern). "
    "If it is a false positive, say so clearly and explain why, and do not invent a fix "
    "for a non-issue. If it is genuine, you MUST use Google Search to find the CURRENT "
    "recommended remediation for this exact language/framework (official docs, OWASP, "
    "CWE, vendor advisories, changelogs) — do not rely on memory alone or on the "
    "scanner's canned remediation text. Give a minimal, correct, production-ready patch "
    "and a short explanation grounded in what you found. If you are not sure, say so "
    "instead of guessing."
)

CONTEXT_LINES = 15


def _read_code_context(file_path: Optional[str], line_number: Optional[int]) -> str:
    """Pull real surrounding source so the model judges the actual code, not a label."""
    if not file_path or not line_number or not os.path.isfile(file_path):
        return "(no source file available to inspect)"
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, line_number - 1 - CONTEXT_LINES)
        end = min(len(lines), line_number + CONTEXT_LINES)
        numbered = [
            f"{i + 1:>5}{'>>' if i + 1 == line_number else '  '} {lines[i].rstrip()}"
            for i in range(start, end)
        ]
        return "\n".join(numbered) if numbered else "(file is empty)"
    except Exception as e:
        return f"(could not read source: {e})"


class AiRemediationAgent(Agent):
    def __init__(self):
        super().__init__(
            name="AiRemediationAgent",
            description="Leverages Gemini AI, grounded with live Google Search, to generate threat analysis and production-ready remediation patches for security findings."
        )
        self.api_key = os.environ.get("GEMINI_API_KEY")
        self.model = os.environ.get("CYBERSENTINEL_MODEL", DEFAULT_MODEL)
        self.client = None
        if HAS_GENAI and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None

    @staticmethod
    def _build_prompt(finding: Finding, target: str) -> str:
        code_context = _read_code_context(finding.file_path, finding.line_number)
        return (
            "A regex-based scanner flagged the line below (marked >>). Its label is only "
            "a lead — verify it yourself against the real code before trusting it.\n\n"
            f"Scanner's label: {finding.title} (severity: {finding.severity.value})\n"
            f"Scanner's description: {finding.description}\n"
            f"File/Target: {finding.file_path or target}\n"
            f"Line: {finding.line_number or 'N/A'}\n\n"
            "Actual surrounding source code:\n"
            f"```\n{code_context}\n```\n\n"
            "Answer with:\n"
            "1. Is this a real vulnerability or a false positive, based on the actual code "
            "above? Say which, and why.\n"
            "2. If real: the root cause, then search the web for the current recommended "
            "fix for this exact language/framework, and give a minimal production-ready "
            "patch with a short explanation grounded in that research.\n"
            "3. If a false positive: say so plainly and give no patch.\n"
            "Be concise."
        )

    def _config(self, grounded: bool):
        kwargs: Dict[str, Any] = {
            "system_instruction": SYSTEM_INSTRUCTION,
            "temperature": 0.2,
        }
        if grounded:
            kwargs["tools"] = [types.Tool(google_search=types.GoogleSearch())]
        return types.GenerateContentConfig(**kwargs)

    @staticmethod
    def _extract_sources(response) -> List[str]:
        """Collect web sources the answer was grounded on (if any)."""
        sources: List[str] = []
        try:
            candidates = getattr(response, "candidates", None) or []
            meta = getattr(candidates[0], "grounding_metadata", None) if candidates else None
            for chunk in (getattr(meta, "grounding_chunks", None) or []):
                web = getattr(chunk, "web", None)
                uri = getattr(web, "uri", None)
                if uri:
                    title = getattr(web, "title", None) or uri
                    entry = f"{title}: {uri}"
                    if entry not in sources:
                        sources.append(entry)
        except Exception:
            pass
        return sources

    def _generate(self, prompt: str) -> Tuple[Optional[str], List[str], bool]:
        """Try a search-grounded call first; fall back to ungrounded if it fails."""
        try:
            response = self.client.models.generate_content(
                model=self.model, contents=prompt, config=self._config(grounded=True)
            )
            text = (response.text or "").strip() if response else ""
            return text or None, self._extract_sources(response), True
        except Exception:
            response = self.client.models.generate_content(
                model=self.model, contents=prompt, config=self._config(grounded=False)
            )
            text = (response.text or "").strip() if response else ""
            return text or None, [], False

    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        """
        Enhances existing findings with search-grounded remediation advice.
        Context can pass existing findings under 'findings'.
        """
        findings: List[Finding] = context.get("findings", [])
        if not self.client or not findings:
            return []

        enhanced_findings: List[Finding] = []
        for finding in findings:
            try:
                text, sources, grounded = self._generate(self._build_prompt(finding, target))
                if text:
                    label = "Gemini AI Advisor Patch" if grounded else "Gemini AI Advisor Patch (NOT web-verified)"
                    finding.remediation += f"\n\n[{label}]:\n{text}"
                    if sources:
                        finding.remediation += "\n\nSources:\n" + "\n".join(f"- {s}" for s in sources[:5])
            except Exception as e:
                # Fallback gracefully if API rate limits or network issues occur
                finding.remediation += f"\n\n[Gemini AI Advisor Note]: Could not generate AI patch due to API error: {e}"

            enhanced_findings.append(finding)

        return enhanced_findings
