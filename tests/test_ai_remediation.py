import pytest
from cybersentinel.agents.ai_remediation import AiRemediationAgent
from cybersentinel.models import Finding, Severity

def test_ai_remediation_agent_without_client():
    agent = AiRemediationAgent()
    # Without API key/client, run returns empty or untouched findings if no client
    finding = Finding(
        id="TEST-1",
        title="SQL Injection",
        severity=Severity.CRITICAL,
        agent="CodeAuditAgent",
        description="Raw SQL",
        remediation="Use params."
    )
    res = agent.run(".", {"findings": [finding]})
    # Since client is None (no GEMINI_API_KEY in test environment), it returns [] or handles gracefully
    assert isinstance(res, list)


def test_prompt_and_sources_helpers():
    finding = Finding(
        id="TEST-2",
        title="XSS",
        severity=Severity.HIGH,
        agent="WebVulnScanAgent",
        description="Unescaped output",
        remediation="Escape output.",
    )
    prompt = AiRemediationAgent._build_prompt(finding, "http://localhost")
    assert "false positive" in prompt and "XSS" in prompt
    # No real file/line given -> must say so rather than inventing code context
    assert "no source file available" in prompt

    class _Web:  # minimal stand-ins for the google-genai grounding metadata
        uri = "https://owasp.org/xss"
        title = "OWASP XSS"

    class _Chunk:
        web = _Web()

    class _Meta:
        grounding_chunks = [_Chunk(), _Chunk()]

    class _Cand:
        grounding_metadata = _Meta()

    class _Resp:
        candidates = [_Cand()]

    assert AiRemediationAgent._extract_sources(_Resp()) == ["OWASP XSS: https://owasp.org/xss"]
    assert AiRemediationAgent._extract_sources(object()) == []
