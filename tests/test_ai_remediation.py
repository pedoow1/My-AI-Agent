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
