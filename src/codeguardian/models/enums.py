"""Enumerations used across the system."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding severity levels aligned with CVSS / industry standards."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_score(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 1.0:
            return cls.LOW
        return cls.INFO

    @property
    def weight(self) -> float:
        return {
            self.CRITICAL: 20.0,
            self.HIGH: 12.0,
            self.MEDIUM: 6.0,
            self.LOW: 2.0,
            self.INFO: 0.5,
        }[self]


class Confidence(str, Enum):
    """Detection confidence level."""

    HIGH = "high"       # Rule-based / deterministic
    MEDIUM = "medium"   # Heuristic / pattern-match
    LOW = "low"         # AI-inferred / needs verification


class RiskPriority(str, Enum):
    """Action priority for findings."""

    MUST_FIX = "must-fix"
    SHOULD_FIX = "should-fix"
    CAN_FIX = "can-fix"


class FindingCategory(str, Enum):
    """High-level category for a finding."""

    DEFECT = "defect"
    SECURITY = "security"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    ARCHITECTURE = "architecture"
    TESTING = "testing"
    CONFIG_RISK = "config_risk"


class Dimension(str, Enum):
    """Analysis dimension identifiers."""

    SCALE = "scale"
    COMPLEXITY = "complexity"
    OO_DESIGN = "oo_design"
    MAINTAINABILITY = "maintainability"
    DEFECTS = "defects"
    TESTING = "testing"
    DEPENDENCIES = "dependencies"
    EVOLUTION = "evolution"
    PERFORMANCE = "performance"
    SECURITY = "security"
    CONFIG_RISK = "config_risk"


class ExecutionMode(str, Enum):
    """Scan execution mode."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ReportFormat(str, Enum):
    TERMINAL = "terminal"
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"
    PDF = "pdf"
