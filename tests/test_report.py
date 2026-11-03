import pytest
from cybersentinel.models import ScanResult, Finding, Severity
from cybersentinel.agents.report import ReportAgent

def test_report_generation():
    agent = ReportAgent()
    finding = Finding(
        id="TEST-1",
        title="Test Finding",
        severity=Severity.HIGH,
        agent="TestAgent",
        file_path="test.py",
        line_number=10,
        description="A test vulnerability description",
        remediation="Fix it by doing X.",
        cvss_score=7.5
    )
    result = ScanResult(target="test_target", findings=[finding])

    md_report = agent.generate_markdown_report(result)
    assert "# CyberSentinel Security Assessment Report" in md_report
    assert "Test Finding" in md_report
    assert "HIGH" in md_report

    json_report = agent.generate_json_report(result)
    assert "test_target" in json_report
    assert "TEST-1" in json_report
