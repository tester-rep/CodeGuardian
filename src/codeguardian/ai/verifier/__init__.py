"""AI Verifier — second-pass true/false verification for engine-produced findings.

This package runs an additional AI judgment over findings already produced by
static engines (Semgrep, security_engine, defect_engine, ...). Goal: lower the
false-positive rate without silently dropping findings.

Two-stage flow:
  Pass 1 — lightweight prompt + minimal context (cheap)
  Pass 2 — heavier prompt + richer context, only for "uncertain" Pass-1 verdicts

Outputs (per finding):
  - verification_status: ai-verified-true / ai-verified-fp / ai-uncertain /
                         ai-skipped-{budget,error,disabled}
  - severity downgraded to ``info`` when judged FP (kept, never silently dropped)
  - tags + verification_summary annotated for traceability
"""

from codeguardian.ai.verifier.verifier import AIVerifier, VerifyOutcome

__all__ = ["AIVerifier", "VerifyOutcome"]
