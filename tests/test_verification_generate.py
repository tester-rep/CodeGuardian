"""Tests for verification asset generation and syntax checks."""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch


from codeguardian.models.common import Location

from codeguardian.models.enums import Confidence, Severity
from codeguardian.models.finding import Finding
from codeguardian.verification import VerificationEngine


def test_generate_mode_attaches_non_executed_artifact() -> None:
    finding = Finding(
        id="DEF-001",
        title="division by zero",
        category="defect",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="app.py", line_start=10, line_end=10),
        source_engine="defect",
        rule_id="DIVISION-BY-ZERO-RISK",
    )

    VerificationEngine().apply([finding], Path("/readonly/project"), mode="generate")

    assert finding.verification_status == "test-generated"
    assert finding.verification_artifacts
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is False
    assert artifact["modified_project"] is False
    assert artifact["network"] == "not-used"
    assert artifact["cleanup"] == "no-files-created"
    assert "pytest.raises" in str(artifact["code"])


def test_syntax_mode_checks_python_asset_in_temporary_sandbox() -> None:
    finding = Finding(
        id="DEF-003",
        title="bounds",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="app.py", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="COLLECTION-INDEX-OUT-OF-BOUNDS",
    )

    VerificationEngine().apply([finding], Path("/readonly/project"), mode="syntax")

    assert finding.verification_status == "syntax-checked"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is True
    assert artifact["modified_project"] is False
    assert artifact["network"] == "not-used"
    assert artifact["cleanup"] == "temporary-directory-deleted"
    assert artifact["conclusion"] == "syntax-ok"
    assert artifact["cwd"] == "<temporary-sandbox>"
    assert artifact["exit_code"] == 0



def test_safe_mode_runs_self_contained_python_test() -> None:
    finding = Finding(
        id="DEF-005",
        title="division by zero",
        category="defect",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="app.py", line_start=10, line_end=10),
        source_engine="defect",
        rule_id="DIVISION-BY-ZERO-RISK",
    )

    VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.evidence_level == "test-confirmed"
    assert finding.verification_status == "test-confirmed"
    assert finding.confidence == Confidence.HIGH
    artifact = finding.verification_artifacts[0]

    assert artifact["executed"] is True
    assert artifact["modified_project"] is False
    assert artifact["network"] == "not-used"
    assert artifact["cleanup"] == "temporary-directory-deleted"
    assert artifact["conclusion"] == "test-confirmed"
    assert artifact["exit_code"] == 0



def test_safe_mode_runs_self_contained_go_test() -> None:
    finding = Finding(
        id="DEF-006",
        title="go bounds",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="main.go", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="COLLECTION-INDEX-OUT-OF-BOUNDS",
    )

    with patch("codeguardian.verification.shutil.which", return_value="go"), patch(
        "codeguardian.verification.subprocess.run",
        return_value=CompletedProcess(args=["go"], returncode=0, stdout="ok", stderr=""),
    ) as run_mock:
        VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.evidence_level == "test-confirmed"
    assert finding.verification_status == "test-confirmed"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is True
    assert artifact["modified_project"] is False
    assert artifact["network"] == "not-used"
    assert artifact["cleanup"] == "temporary-directory-deleted"
    assert artifact["conclusion"] == "test-confirmed"
    assert artifact["command"] == ["go", "test", "-run", "TestGenerated", "-count=1", "."]
    env = run_mock.call_args.kwargs["env"]
    assert env["GOPROXY"] == "off"
    assert env["GOSUMDB"] == "off"



def test_safe_mode_runs_self_contained_java_main_repro() -> None:
    finding = Finding(
        id="DEF-007",
        title="java null deref",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="App.java", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="POSSIBLE-NONE-DEREF",
    )
    results = [
        CompletedProcess(args=["javac"], returncode=0, stdout="", stderr=""),
        CompletedProcess(args=["java"], returncode=1, stdout="", stderr="Exception in thread \\\"main\\\" java.lang.NullPointerException"),
    ]

    with patch("codeguardian.verification.shutil.which", side_effect=lambda name: name), patch(
        "codeguardian.verification.subprocess.run",
        side_effect=results,
    ) as run_mock:
        VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.evidence_level == "test-confirmed"
    assert finding.verification_status == "test-confirmed"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is True
    assert artifact["modified_project"] is False
    assert artifact["network"] == "not-used"
    assert artifact["cleanup"] == "temporary-directory-deleted"
    assert artifact["conclusion"] == "test-confirmed"
    assert artifact["expected_exception"] == "NullPointerException"
    assert artifact["command"] == [["javac", "-Xlint:all", "GeneratedNullDerefRepro.java"], ["java", "-cp", ".", "GeneratedNullDerefRepro"]]
    assert run_mock.call_count == 2



def test_safe_mode_skips_java_assets_without_self_contained_main() -> None:
    finding = Finding(
        id="DEF-009",
        title="java resource close",
        category="defect",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="App.java", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="RESOURCE-CLOSE-NOT-GUARANTEED",
    )

    VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.verification_status == "skipped-unsafe"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is False
    assert artifact["modified_project"] is False
    assert artifact["conclusion"] == "skipped-unsafe"



def test_safe_mode_skips_java_when_runner_missing() -> None:
    finding = Finding(
        id="DEF-010",
        title="java null deref",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="App.java", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="POSSIBLE-NONE-DEREF",
    )

    with patch("codeguardian.verification.shutil.which", return_value=None):
        VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.verification_status == "skipped-no-runner"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is False
    assert artifact["conclusion"] == "skipped-no-runner"



def test_safe_mode_runs_self_contained_cpp_main_repro() -> None:
    finding = Finding(
        id="DEF-011",
        title="cpp bounds",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="main.cpp", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="COLLECTION-INDEX-OUT-OF-BOUNDS",
    )
    results = [
        CompletedProcess(args=["g++"], returncode=0, stdout="", stderr=""),
        CompletedProcess(args=["generated_repro"], returncode=0, stdout="", stderr=""),
    ]

    with patch("codeguardian.verification.shutil.which", return_value="g++"), patch(
        "codeguardian.verification.subprocess.run",
        side_effect=results,
    ) as run_mock:
        VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.evidence_level == "test-confirmed"
    assert finding.verification_status == "test-confirmed"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is True
    assert artifact["modified_project"] is False
    assert artifact["network"] == "not-used"
    assert artifact["cleanup"] == "temporary-directory-deleted"
    assert artifact["conclusion"] == "test-confirmed"
    assert artifact["command"][0][:3] == ["g++", "-std=c++17", "generated_repro.cpp"]
    assert run_mock.call_count == 2



def test_safe_mode_skips_cpp_assets_without_safe_main() -> None:
    finding = Finding(
        id="DEF-012",
        title="cpp null deref",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="main.cpp", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="POSSIBLE-NONE-DEREF",
    )

    VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.verification_status == "skipped-unsafe"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is False
    assert artifact["conclusion"] == "skipped-unsafe"



def test_safe_mode_skips_cpp_when_runner_missing() -> None:
    finding = Finding(
        id="DEF-013",
        title="cpp bounds",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="main.cpp", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="COLLECTION-INDEX-OUT-OF-BOUNDS",
    )

    with patch("codeguardian.verification.shutil.which", return_value=None):
        VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.verification_status == "skipped-no-runner"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is False
    assert artifact["conclusion"] == "skipped-no-runner"



def test_safe_mode_skips_go_when_runner_missing() -> None:


    finding = Finding(
        id="DEF-008",
        title="go bounds",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="main.go", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="COLLECTION-INDEX-OUT-OF-BOUNDS",
    )

    with patch("codeguardian.verification.shutil.which", return_value=None):
        VerificationEngine().apply([finding], Path("/readonly/project"), mode="safe")

    assert finding.verification_status == "skipped-no-runner"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is False
    assert artifact["conclusion"] == "skipped-no-runner"



def test_syntax_mode_skips_when_runner_missing() -> None:


    finding = Finding(
        id="DEF-004",
        title="java null deref",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="App.java", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="POSSIBLE-NONE-DEREF",
    )

    with patch("codeguardian.verification.shutil.which", return_value=None):
        VerificationEngine().apply([finding], Path("/readonly/project"), mode="syntax")

    assert finding.verification_status == "skipped-no-runner"
    artifact = finding.verification_artifacts[0]
    assert artifact["executed"] is False
    assert artifact["modified_project"] is False
    assert artifact["conclusion"] == "skipped-no-runner"



def test_off_mode_leaves_findings_unchanged() -> None:

    finding = Finding(
        id="DEF-002",
        title="bounds",
        category="defect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="app.py", line_start=1, line_end=1),
        source_engine="defect",
        rule_id="COLLECTION-INDEX-OUT-OF-BOUNDS",
    )

    VerificationEngine().apply([finding], Path("/readonly/project"), mode="off")

    assert finding.verification_status == "unverified"
    assert finding.verification_artifacts == []
