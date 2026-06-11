"""Custom exceptions for the CodeGuardian system."""


class CodeGuardianError(Exception):
    """Base exception for all CodeGuardian errors."""


class ConfigError(CodeGuardianError):
    """Configuration loading or validation error."""


class DetectorError(CodeGuardianError):
    """Project detection failure."""


class EngineError(CodeGuardianError):
    """Analyzer engine execution error."""


class NormalizerError(CodeGuardianError):
    """Result normalization error."""


class RiskEngineError(CodeGuardianError):
    """Risk scoring or gate evaluation error."""


class ReportError(CodeGuardianError):
    """Report generation error."""


class AIError(CodeGuardianError):
    """AI provider or inference error."""


class StorageError(CodeGuardianError):
    """Snapshot or cache I/O error."""
