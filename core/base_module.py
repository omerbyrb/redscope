from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime

from core.logger import setup_logger


@dataclass
class Finding:
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss: Optional[float] = None
    cve: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss": self.cvss,
            "cve": self.cve,
            "tags": self.tags,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    module: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)

    def finish(self) -> None:
        self.finished_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class BaseModule(ABC):
    name: str = "base"
    description: str = ""
    author: str = ""
    version: str = "1.0.0"

    def __init__(self, config: dict):
        self.config = config
        self.log = setup_logger(f"redscope.{self.name}")

    @abstractmethod
    def run(self, target: str, **kwargs) -> ScanResult:
        pass

    def validate_target(self, target: str) -> bool:
        return bool(target and target.strip())

    def __repr__(self) -> str:
        return f"<Module: {self.name} v{self.version}>"
