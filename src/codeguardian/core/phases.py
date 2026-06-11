"""Execution phase definitions."""

PHASES = [
    ("preflight", "Load config, check environment, initialize logging"),
    ("detection", "Detect languages, frameworks, build systems"),
    ("planning", "Generate analysis plan, select engines"),
    ("analysis", "Run analyzer engines in parallel"),
    ("normalization", "Normalize engine outputs into unified model"),
    ("risk", "Deduplicate, cluster, score findings, evaluate gates"),
    ("ai_enhancement", "AI summarization, suggestions, release review"),
    ("reporting", "Generate reports, save snapshot, terminal summary"),
]
