"""Tests for Scout phase (free_review) and two-phase review."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from codeguardian.ai.deep_review.budget import TokenBudgetManager
from codeguardian.ai.deep_review.context_builder import ContextPackBuilder
from codeguardian.ai.deep_review.models import AIFindingRaw, CodeChunk, ReviewResult
from codeguardian.ai.deep_review.project_index import ProjectIndex
from codeguardian.ai.deep_review.reviewer import AIReviewer
from codeguardian.ai.deep_review.suspicion_queue import Suspicion, build_suspicions, save_suspicion_queue
from codeguardian.ai.prompts.deep_review import SCOUT_SYSTEM_MESSAGE, build_scout_prompt


# ---------------------------------------------------------------------------
# Scout Phase Tests
# ---------------------------------------------------------------------------


class TestBuildSuspicions:
    """Tests for build_suspicions()."""

    def test_empty_results(self):
        """Empty results → empty suspicions."""
        result = build_suspicions([], min_confidence=3)
        assert result == []

    def test_filters_low_confidence(self):
        """Findings below min_confidence should be filtered."""
        high = AIFindingRaw(
            title="High confidence",
            category="security",
            severity="high",
            confidence=8,
            line_start=20,
            line_end=20,
        )
        low = AIFindingRaw(
            title="Low confidence",
            category="logic",
            severity="low",
            confidence=2,
            line_start=10,
            line_end=10,
        )

        result = ReviewResult(
            chunk_file_path="app.py",
            findings=[low, high],
            status="done",
        )

        suspicions = build_suspicions([result], min_confidence=3)
        assert len(suspicions) == 1
        assert suspicions[0].title == "High confidence"

    def test_dedup_same_finding(self):
        """Same finding in the same file should be deduped."""
        finding = AIFindingRaw(
            title="Dup",
            category="logic",
            severity="medium",
            confidence=5,
            line_start=10,
            line_end=10,
        )

        # Same file → should dedup
        r1 = ReviewResult(chunk_file_path="a.py", findings=[finding], status="done")
        r2 = ReviewResult(chunk_file_path="a.py", findings=[finding], status="done")

        suspicions = build_suspicions([r1, r2], min_confidence=3)
        assert len(suspicions) == 1

    def test_no_dedup_different_file(self):
        """Same finding title in different files should NOT be deduped."""
        finding = AIFindingRaw(
            title="Dup",
            category="logic",
            severity="medium",
            confidence=5,
            line_start=10,
            line_end=10,
        )

        r1 = ReviewResult(chunk_file_path="a.py", findings=[finding], status="done")
        r2 = ReviewResult(chunk_file_path="b.py", findings=[finding], status="done")

        suspicions = build_suspicions([r1, r2], min_confidence=3)
        assert len(suspicions) == 2

    def test_max_cap(self):
        """Should cap at max_suspicions."""
        results = [
            ReviewResult(
                chunk_file_path=f"f{i}.py",
                findings=[AIFindingRaw(
                    title=f"I{i}",
                    category="logic",
                    severity="medium",
                    confidence=5,
                    line_start=i,
                    line_end=i,
                )],
                status="done",
            )
            for i in range(10)
        ]

        suspicions = build_suspicions(results, min_confidence=3, max_suspicions=5)
        assert len(suspicions) == 5

    def test_priority_score_ordering(self):
        """Higher severity + confidence → higher priority score."""
        results = [
            ReviewResult(
                chunk_file_path="a.py",
                findings=[AIFindingRaw(
                    title="Critical",
                    category="security",
                    severity="critical",
                    confidence=9,
                    line_start=1,
                    line_end=1,
                )],
                status="done",
            ),
            ReviewResult(
                chunk_file_path="b.py",
                findings=[AIFindingRaw(
                    title="Low",
                    category="logic",
                    severity="low",
                    confidence=3,
                    line_start=2,
                    line_end=2,
                )],
                status="done",
            ),
        ]

        suspicions = build_suspicions(results, min_confidence=1, max_suspicions=10)
        assert len(suspicions) == 2
        assert suspicions[0].title == "Critical"
        assert suspicions[0].priority_score > suspicions[1].priority_score

    def test_suspicion_fields(self):
        """Suspicion dataclass should preserve finding fields."""
        finding = AIFindingRaw(
            title="SQL Injection",
            category="security",
            severity="high",
            confidence=8,
            line_start=5,
            line_end=5,
            description="User input in query",
            evidence="Line 5: query = f'...'",
            fix_suggestion="Use params",
        )

        result = ReviewResult(
            chunk_file_path="app.py",
            findings=[finding],
            status="done",
        )

        suspicions = build_suspicions([result], min_confidence=3)
        assert len(suspicions) == 1
        s = suspicions[0]
        assert s.file_path == "app.py"
        assert s.line_start == 5
        assert s.category == "security"
        assert s.severity == "high"
        assert s.confidence == 8
        assert s.description == "User input in query"


class TestSaveSuspicionQueue:
    """Tests for save_suspicion_queue()."""

    def test_save_jsonl(self, tmp_path):
        """Suspicion queue should be saved as JSONL."""
        suspicions = [
            Suspicion(
                file_path="app.py",
                line_start=10,
                line_end=20,
                title="Test issue",
                category="security",
                severity="high",
                confidence=8,
            ),
        ]

        project_root = tmp_path / "project"
        queue_path = save_suspicion_queue(project_root, suspicions)

        assert queue_path.exists()
        content = queue_path.read_text(encoding="utf-8")
        assert "Test issue" in content
        assert content.count("\n") <= 2

    def test_save_multiple(self, tmp_path):
        """Multiple suspicions → multiple JSONL lines."""
        suspicions = [
            Suspicion(
                file_path=f"f{i}.py",
                line_start=i * 10,
                line_end=i * 10,
                title=f"Issue {i}",
                category="logic",
                severity="medium",
                confidence=5,
            )
            for i in range(3)
        ]

        project_root = tmp_path / "project"
        queue_path = save_suspicion_queue(project_root, suspicions)

        content = queue_path.read_text(encoding="utf-8")
        lines = [l for l in content.strip().split("\n") if l]
        assert len(lines) == 3


class TestScoutReviewer:
    """Tests for AIReviewer with scout config."""

    @pytest.mark.asyncio
    async def test_scout_reviewer_basic(self):
        """AIReviewer should work with scout system_message and prompt_builder."""
        from codeguardian.ai.models import GenerateResult

        mock_provider = AsyncMock()
        mock_provider.generate_with_usage.return_value = GenerateResult(
            text=json.dumps({
                "findings": [
                    {
                        "title": "Scout found issue",
                        "category": "security",
                        "severity": "high",
                        "confidence": 7,
                        "line_start": 5,
                        "line_end": 5,
                        "description": "Potential issue",
                        "evidence": "Line 5",
                        "fix_suggestion": "Fix it",
                        "self_reflection": "Confirmed",
                    }
                ],
                "summary": "Found 1 issue",
                "verified_local_findings": [],
            })
        )

        reviewer = AIReviewer(
            provider=mock_provider,
            context_builder=ContextPackBuilder(project_index=ProjectIndex()),
            budget=TokenBudgetManager(max_tokens=100_000),
            system_message=SCOUT_SYSTEM_MESSAGE,
            prompt_builder=build_scout_prompt,
        )

        chunk = CodeChunk(
            file_path="app.py",
            source_code="user_input = request.GET['q']",
            language="python",
            line_start=1,
            line_end=5,
        )

        results = await reviewer.review_chunks([chunk])
        assert len(results) == 1
        assert results[0].status == "done"
        assert len(results[0].findings) == 1
        assert results[0].findings[0].title == "Scout found issue"

    @pytest.mark.asyncio
    async def test_scout_reviewer_empty(self):
        """Scout reviewer with no findings."""
        from codeguardian.ai.models import GenerateResult

        mock_provider = AsyncMock()
        mock_provider.generate_with_usage.return_value = GenerateResult(
            text=json.dumps({
                "findings": [],
                "summary": "No issues",
                "verified_local_findings": [],
            })
        )

        reviewer = AIReviewer(
            provider=mock_provider,
            context_builder=ContextPackBuilder(project_index=ProjectIndex()),
            budget=TokenBudgetManager(max_tokens=100_000),
            system_message=SCOUT_SYSTEM_MESSAGE,
            prompt_builder=build_scout_prompt,
        )

        chunk = CodeChunk(
            file_path="clean.py",
            source_code="x = 1",
            language="python",
            line_start=1,
            line_end=1,
        )

        results = await reviewer.review_chunks([chunk])
        assert results[0].status == "done"
        assert len(results[0].findings) == 0


# ---------------------------------------------------------------------------
# Two-Phase Review Integration Tests
# ---------------------------------------------------------------------------


class TestTwoPhaseReview:
    """Integration tests for two-phase review (scout + professional)."""

    @pytest.mark.asyncio
    async def test_scout_then_professional(self):
        """Mock two-phase: scout finds suspicions → professional review."""
        from codeguardian.ai.models import GenerateResult

        # Phase 1: Scout finds an issue
        scout_mock = AsyncMock()
        scout_mock.generate_with_usage.return_value = GenerateResult(
            text=json.dumps({
                "findings": [
                    {
                        "title": "Scout: SQL injection",
                        "category": "security",
                        "severity": "high",
                        "confidence": 7,
                        "line_start": 5,
                        "line_end": 5,
                        "description": "Unsanitized input",
                        "evidence": "Line 5",
                        "fix_suggestion": "Use params",
                        "self_reflection": "No sanitization",
                    }
                ],
                "summary": "Found 1 issue",
                "verified_local_findings": [],
            })
        )

        index = ProjectIndex()
        ctx_builder = ContextPackBuilder(project_index=index)
        scout_budget = TokenBudgetManager(max_tokens=100_000)

        scout_reviewer = AIReviewer(
            provider=scout_mock,
            context_builder=ctx_builder,
            budget=scout_budget,
            system_message=SCOUT_SYSTEM_MESSAGE,
            prompt_builder=build_scout_prompt,
        )

        chunk = CodeChunk(
            file_path="app.py",
            source_code="query = f'SELECT * FROM t WHERE id = {user_input}'",
            language="python",
            line_start=1,
            line_end=5,
        )

        # Phase 1: Scout review
        scout_results = await scout_reviewer.review_chunks([chunk])
        suspicions = build_suspicions(scout_results, min_confidence=3)

        assert len(suspicions) == 1
        assert suspicions[0].title == "Scout: SQL injection"

    def test_suspicion_to_context_injection(self):
        """Test suspicions are correctly formatted for context injection."""
        suspicions = [
            Suspicion(
                file_path="app.py",
                line_start=10,
                line_end=20,
                title="Bad function",
                category="security",
                severity="high",
                confidence=8,
                description="SQL injection here",
            ),
        ]

        # Simulate what pipeline.py does
        by_file: dict[str, list[str]] = {}
        for s in suspicions:
            note = (
                f"[Scout 可疑点] {s.title} (confidence={s.confidence}, "
                f"severity={s.severity}) L{s.line_start}: {s.description[:120]}"
            )
            by_file.setdefault(s.file_path, []).append(note)

        assert "app.py" in by_file
        assert len(by_file["app.py"]) == 1
        assert "Scout 可疑点" in by_file["app.py"][0]
        assert "Bad function" in by_file["app.py"][0]

    def test_context_builder_with_suspicions(self):
        """ContextPackBuilder should include suspicion notes."""
        suspicions = [
            Suspicion(
                file_path="app.py",
                line_start=10,
                line_end=20,
                title="Suspicious code",
                category="security",
                severity="high",
                confidence=8,
            ),
        ]

        by_file = {}
        for s in suspicions:
            note = f"[Scout] {s.title}"
            by_file.setdefault(s.file_path, []).append(note)

        builder = ContextPackBuilder(
            project_index=ProjectIndex(),
            extra_notes_by_file=by_file,
        )

        chunk = CodeChunk(
            file_path="app.py",
            source_code="pass",
            language="python",
            line_start=10,
            line_end=20,
        )

        pack = builder.build(chunk)
        notes_text = "\n".join(pack.notes)
        assert "[Scout]" in notes_text
        assert "Suspicious code" in notes_text


# ---------------------------------------------------------------------------
# ProjectIndex Python Parser Fix Tests
# ---------------------------------------------------------------------------


class TestProjectIndexPython:
    """Verify that ProjectIndex correctly indexes Python files after the fix."""

    def test_get_parser_python_not_none(self):
        """After fix: get_parser('python') should return a working parser."""
        from codeguardian.parsers.factory import get_parser

        parser = get_parser("python")
        assert parser is not None, "get_parser('python') should return a parser after fix"

    def test_python_parsing_and_indexing(self):
        """Test that Python files can be parsed and indexed."""
        import tempfile
        import os

        from codeguardian.parsers.factory import get_parser
        from codeguardian.ai.deep_review.project_index import ProjectIndex

        parser = get_parser("python")
        assert parser is not None

        # Write a test Python file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("def hello():\n    return 'world'\n\ndef add(a, b):\n    return a + b\n")
            temp_path = f.name

        try:
            structure = parser.parse_file(Path(temp_path), Path(os.path.dirname(temp_path)))
            assert structure is not None
            assert len(structure.functions) == 2
            assert structure.functions[0].name == "hello"
            assert structure.functions[1].name == "add"

            # Build index
            index = ProjectIndex()
            index.build_from_structures({temp_path: structure})
            assert index.function_count == 2
        finally:
            os.unlink(temp_path)

    def test_real_python_file_indexing(self):
        """Test indexing a real Python file from the project."""
        from codeguardian.parsers.factory import get_parser
        from codeguardian.ai.deep_review.project_index import ProjectIndex

        parser = get_parser("python")
        if parser is None:
            pytest.skip("No Python parser available")

        test_file = Path("src/codeguardian/core/orchestrator.py")
        if not test_file.exists():
            pytest.skip("Test file not found")

        structure = parser.parse_file(test_file, test_file.parent)
        assert structure is not None
        # Should find multiple functions
        assert len(structure.functions) > 0

        index = ProjectIndex()
        index.build_from_structures({"orchestrator.py": structure})
        # At least "run" or "orchestrate" should be in signatures
        sigs = index.get_file_signatures("orchestrator.py")
        assert len(sigs) > 0
