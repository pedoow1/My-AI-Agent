from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    agent: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    description: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "agent": self.agent,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "metadata": self.metadata
        }

@dataclass
class ScanResult:
    target: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
