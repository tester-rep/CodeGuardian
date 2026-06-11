"""Verification asset generation for findings.

Phase 1 is intentionally non-executing: it only creates reviewable repro/test
assets in memory and never writes to or runs code from the target project.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.models.enums import Confidence
from codeguardian.models.finding import Finding


_GENERATE_ONLY_SUMMARY = (
    "已生成验证资产但未执行。该模式不会修改原始项目、不会写入目标目录、不会联网、不会运行目标代码。"
)
_SYNTAX_CHECK_SUMMARY = (
    "已在临时沙箱中生成验证资产并执行语法/编译检查；未运行目标项目代码，未写入原始目录。"
)
_SAFE_CONFIRMED_SUMMARY = (
    "已在临时沙箱中执行生成的自包含验证测试并复现预期失败；未运行目标项目代码，未写入原始目录。"
)
_SAFE_INCONCLUSIVE_SUMMARY = (
    "已尝试在临时沙箱执行生成的自包含验证测试，但结果不确定；未运行目标项目代码，未写入原始目录。"
)




class VerificationEngine:
    """Attach verification artifacts to verifiable findings.

    ``generate`` never touches disk. ``syntax`` writes generated assets only to a
    temporary sandbox, runs whitelisted syntax/compile commands, and cleans up.
    ``safe`` runs only self-contained generated tests in the sandbox. No mode
    writes to the target project.
    """

    SUPPORTED_MODES = {"off", "generate", "syntax", "safe"}


    def apply(self, findings: list[Finding], project_root: Path, mode: str = "off") -> None:
        normalized_mode = (mode or "off").strip().lower()
        if normalized_mode == "off":
            return
        if normalized_mode not in self.SUPPORTED_MODES:
            raise ValueError(f"Unsupported verification mode: {mode}")

        for finding in findings:
            artifact = self._build_artifact(finding, project_root)
            if artifact is None:
                continue
            if normalized_mode == "syntax":
                self._syntax_check_artifact(artifact)
            elif normalized_mode == "safe":
                self._safe_execute_artifact(artifact)
            finding.verification_artifacts.append(artifact)
            self._apply_verification_result(finding, artifact, normalized_mode)



    def _build_artifact(self, finding: Finding, project_root: Path) -> dict[str, object] | None:
        language = self._language_from_path(finding.location.file_path)
        rule_id = finding.rule_id or ""
        code = self._code_for(rule_id, language, finding)
        if not code:
            return None
        return {
            "kind": "generated-test",
            "language": language,
            "framework": self._framework_for(language),
            "code": code,
            "command": [],
            "cwd": None,
            "executed": False,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "sandboxed": True,
            "network": "not-used",
            "modified_project": False,
            "cleanup": "no-files-created",
            "conclusion": "not-run",
            "skip_reason": "generate-only mode",
            "target_file": finding.location.file_path,
            "target_line": finding.location.line_start or 1,
            "project_root_readonly": str(project_root),
        }

    def _apply_verification_result(self, finding: Finding, artifact: dict[str, object], mode: str) -> None:
        if mode == "generate":
            if finding.verification_status in {"unverified", "skipped"}:
                finding.verification_status = "test-generated"
            finding.verification_summary = _GENERATE_ONLY_SUMMARY
            return

        conclusion = str(artifact.get("conclusion", "inconclusive"))
        if conclusion == "syntax-ok":
            finding.verification_status = "syntax-checked"
            finding.verification_summary = _SYNTAX_CHECK_SUMMARY
        elif conclusion == "test-confirmed":
            finding.evidence_level = "test-confirmed"
            finding.verification_status = "test-confirmed"
            finding.confidence = Confidence.HIGH
            finding.verification_summary = _SAFE_CONFIRMED_SUMMARY

        elif conclusion == "not-reproduced":
            finding.verification_status = "not-reproduced"
            finding.verification_summary = "生成的自包含验证测试已执行，但未复现预期失败；建议人工复核。"
        elif conclusion == "skipped-no-runner":
            finding.verification_status = "skipped-no-runner"
            finding.verification_summary = "已生成验证资产，但当前环境缺少对应语言的检查/测试工具；未执行目标代码。"
        elif conclusion == "skipped-unsafe":
            finding.verification_status = "skipped-unsafe"
            finding.verification_summary = "已生成验证资产，但当前 safe 模式不支持安全执行该语言或该资产；未执行。"
        else:
            finding.verification_status = "inconclusive"
            finding.verification_summary = _SAFE_INCONCLUSIVE_SUMMARY if mode == "safe" else "已在临时沙箱执行语法/编译检查，但结果不确定；未运行目标项目代码。"

    def _syntax_check_artifact(self, artifact: dict[str, object]) -> None:

        language = str(artifact.get("language", "unknown"))
        code = str(artifact.get("code", ""))
        plan = self._syntax_plan(language, code)
        if plan is None:
            artifact.update({
                "conclusion": "skipped-no-runner",
                "skip_reason": f"No syntax checker configured for language: {language}",
                "cleanup": "no-files-created",
            })
            return

        filename, command_builder = plan
        with TemporaryDirectory(prefix="codeguardian-verify-") as tmpdir:
            sandbox = Path(tmpdir)
            source_path = sandbox / filename
            source_path.write_text(code, encoding="utf-8")
            command = command_builder(source_path)
            if command is None:
                artifact.update({
                    "conclusion": "skipped-no-runner",
                    "skip_reason": f"Required syntax checker not found for language: {language}",
                    "cwd": "<temporary-sandbox>",
                    "cleanup": "temporary-directory-deleted",
                })
                return
            artifact.update({
                "command": [Path(command[0]).name, *command[1:]],
                "cwd": "<temporary-sandbox>",
                "executed": True,
                "network": "not-used",
                "modified_project": False,
                "cleanup": "temporary-directory-deleted",
                "skip_reason": None,
            })
            try:
                completed = subprocess.run(
                    command,
                    cwd=sandbox,
                    env=self._sanitized_env(language),
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                artifact.update({
                    "exit_code": completed.returncode,
                    "stdout": completed.stdout[-4000:],
                    "stderr": completed.stderr[-4000:],
                    "conclusion": "syntax-ok" if completed.returncode == 0 else "syntax-failed",
                })
            except subprocess.TimeoutExpired as exc:
                artifact.update({
                    "exit_code": None,
                    "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
                    "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
                    "conclusion": "inconclusive",
                    "skip_reason": "syntax check timed out",
                })

    def _safe_execute_artifact(self, artifact: dict[str, object]) -> None:
        language = str(artifact.get("language", "unknown"))
        code = str(artifact.get("code", ""))
        if language == "go":
            self._safe_execute_go_artifact(artifact, code)
            return
        if language == "java":
            self._safe_execute_java_artifact(artifact, code)
            return
        if language == "cpp":
            self._safe_execute_cpp_artifact(artifact, code)
            return
        if language != "python":
            artifact.update({
                "conclusion": "skipped-unsafe",
                "skip_reason": "safe execution currently supports only self-contained Python/Go/Java/C++ generated tests",
                "cleanup": "no-files-created",
            })
            return


        if "def test_" not in code:
            artifact.update({
                "conclusion": "skipped-unsafe",
                "skip_reason": "generated asset has no self-contained test function",
                "cleanup": "no-files-created",
            })
            return

        with TemporaryDirectory(prefix="codeguardian-verify-") as tmpdir:

            sandbox = Path(tmpdir)
            source_path = sandbox / "generated_repro_test.py"
            source_path.write_text(code, encoding="utf-8")
            (sandbox / "pytest.py").write_text(self._pytest_shim(), encoding="utf-8")
            (sandbox / "run_generated_tests.py").write_text(self._python_test_runner(), encoding="utf-8")
            command = [sys.executable, "run_generated_tests.py"]

            artifact.update({
                "command": [Path(command[0]).name, *command[1:]],
                "cwd": "<temporary-sandbox>",
                "executed": True,
                "network": "not-used",
                "modified_project": False,
                "cleanup": "temporary-directory-deleted",
                "skip_reason": None,
            })
            try:
                completed = subprocess.run(
                    command,
                    cwd=sandbox,
                    env=self._sanitized_env(language),
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                conclusion = "test-confirmed" if completed.returncode == 0 else "not-reproduced" if completed.returncode == 1 else "inconclusive"
                artifact.update({
                    "exit_code": completed.returncode,
                    "stdout": completed.stdout[-4000:],
                    "stderr": completed.stderr[-4000:],
                    "conclusion": conclusion,
                })
            except subprocess.TimeoutExpired as exc:
                artifact.update({
                    "exit_code": None,
                    "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
                    "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
                    "conclusion": "inconclusive",
                    "skip_reason": "safe test timed out",
                })

    def _safe_execute_java_artifact(self, artifact: dict[str, object], code: str) -> None:
        class_name = self._java_public_class_name(code)
        expected_exception = self._java_expected_exception(code)
        if not class_name or "public static void main" not in code or not expected_exception:
            artifact.update({
                "conclusion": "skipped-unsafe",
                "skip_reason": "generated Java asset has no self-contained public main repro with expected exception",
                "cleanup": "no-files-created",
            })
            return
        javac = shutil.which("javac")
        java = shutil.which("java")
        if not javac or not java:
            artifact.update({
                "conclusion": "skipped-no-runner",
                "skip_reason": "javac/java command is not available in the current environment",
                "cleanup": "no-files-created",
            })
            return

        with TemporaryDirectory(prefix="codeguardian-verify-") as tmpdir:
            sandbox = Path(tmpdir)
            source_name = f"{class_name}.java"
            (sandbox / source_name).write_text(code, encoding="utf-8")
            compile_command = [javac, "-Xlint:all", source_name]
            run_command = [java, "-cp", ".", class_name]
            artifact.update({
                "command": [
                    [Path(compile_command[0]).name, *compile_command[1:]],
                    [Path(run_command[0]).name, *run_command[1:]],
                ],
                "cwd": "<temporary-sandbox>",
                "executed": True,
                "network": "not-used",
                "modified_project": False,
                "cleanup": "temporary-directory-deleted",
                "skip_reason": None,
                "expected_exception": expected_exception,
            })
            try:
                compile_result = subprocess.run(
                    compile_command,
                    cwd=sandbox,
                    env=self._sanitized_env("java"),
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                if compile_result.returncode != 0:
                    artifact.update({
                        "exit_code": compile_result.returncode,
                        "stdout": compile_result.stdout[-4000:],
                        "stderr": compile_result.stderr[-4000:],
                        "conclusion": "inconclusive",
                        "skip_reason": "javac failed for generated self-contained repro",
                    })
                    return
                run_result = subprocess.run(
                    run_command,
                    cwd=sandbox,
                    env=self._sanitized_env("java"),
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                output = f"{run_result.stdout}\n{run_result.stderr}"
                if run_result.returncode != 0 and expected_exception in output:
                    conclusion = "test-confirmed"
                elif run_result.returncode == 0:
                    conclusion = "not-reproduced"
                else:
                    conclusion = "inconclusive"
                artifact.update({
                    "exit_code": run_result.returncode,
                    "stdout": run_result.stdout[-4000:],
                    "stderr": run_result.stderr[-4000:],
                    "conclusion": conclusion,
                })
            except subprocess.TimeoutExpired as exc:
                artifact.update({
                    "exit_code": None,
                    "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
                    "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
                    "conclusion": "inconclusive",
                    "skip_reason": "safe java repro timed out",
                })

    def _safe_execute_cpp_artifact(self, artifact: dict[str, object], code: str) -> None:
        if "int main" not in code or "Generated C++ safe repro" not in code:
            artifact.update({
                "conclusion": "skipped-unsafe",
                "skip_reason": "generated C++ asset has no self-contained safe main repro",
                "cleanup": "no-files-created",
            })
            return
        compiler = shutil.which("g++") or shutil.which("clang++")
        if not compiler:
            artifact.update({
                "conclusion": "skipped-no-runner",
                "skip_reason": "g++/clang++ command is not available in the current environment",
                "cleanup": "no-files-created",
            })
            return

        with TemporaryDirectory(prefix="codeguardian-verify-") as tmpdir:
            sandbox = Path(tmpdir)
            source_name = "generated_repro.cpp"
            binary_name = "generated_repro.exe" if os.name == "nt" else "generated_repro"
            binary_path = sandbox / binary_name
            (sandbox / source_name).write_text(code, encoding="utf-8")
            compile_command = [compiler, "-std=c++17", source_name, "-o", binary_name]
            run_command = [str(binary_path)]
            artifact.update({
                "command": [
                    [Path(compile_command[0]).name, *compile_command[1:]],
                    [Path(run_command[0]).name],
                ],
                "cwd": "<temporary-sandbox>",
                "executed": True,
                "network": "not-used",
                "modified_project": False,
                "cleanup": "temporary-directory-deleted",
                "skip_reason": None,
            })
            try:
                compile_result = subprocess.run(
                    compile_command,
                    cwd=sandbox,
                    env=self._sanitized_env("cpp"),
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                if compile_result.returncode != 0:
                    artifact.update({
                        "exit_code": compile_result.returncode,
                        "stdout": compile_result.stdout[-4000:],
                        "stderr": compile_result.stderr[-4000:],
                        "conclusion": "inconclusive",
                        "skip_reason": "C++ compile failed for generated self-contained repro",
                    })
                    return
                run_result = subprocess.run(
                    run_command,
                    cwd=sandbox,
                    env=self._sanitized_env("cpp"),
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                artifact.update({
                    "exit_code": run_result.returncode,
                    "stdout": run_result.stdout[-4000:],
                    "stderr": run_result.stderr[-4000:],
                    "conclusion": "test-confirmed" if run_result.returncode == 0 else "not-reproduced",
                })
            except subprocess.TimeoutExpired as exc:
                artifact.update({
                    "exit_code": None,
                    "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
                    "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
                    "conclusion": "inconclusive",
                    "skip_reason": "safe C++ repro timed out",
                })

    def _safe_execute_go_artifact(self, artifact: dict[str, object], code: str) -> None:
        if "func Test" not in code:


            artifact.update({
                "conclusion": "skipped-unsafe",
                "skip_reason": "generated Go asset has no self-contained Test function",
                "cleanup": "no-files-created",
            })
            return
        go = shutil.which("go")
        if not go:
            artifact.update({
                "conclusion": "skipped-no-runner",
                "skip_reason": "go command is not available in the current environment",
                "cleanup": "no-files-created",
            })
            return

        with TemporaryDirectory(prefix="codeguardian-verify-") as tmpdir:
            sandbox = Path(tmpdir)
            (sandbox / "generated_repro_test.go").write_text(code, encoding="utf-8")
            command = [go, "test", "-run", "TestGenerated", "-count=1", "."]
            artifact.update({
                "command": [Path(command[0]).name, *command[1:]],
                "cwd": "<temporary-sandbox>",
                "executed": True,
                "network": "not-used",
                "modified_project": False,
                "cleanup": "temporary-directory-deleted",
                "skip_reason": None,
            })
            try:
                completed = subprocess.run(
                    command,
                    cwd=sandbox,
                    env=self._sanitized_env("go"),
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                artifact.update({
                    "exit_code": completed.returncode,
                    "stdout": completed.stdout[-4000:],
                    "stderr": completed.stderr[-4000:],
                    "conclusion": "test-confirmed" if completed.returncode == 0 else "not-reproduced",
                })
            except subprocess.TimeoutExpired as exc:
                artifact.update({
                    "exit_code": None,
                    "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
                    "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
                    "conclusion": "inconclusive",
                    "skip_reason": "safe go test timed out",
                })

    @staticmethod
    def _pytest_shim() -> str:

        return '''class raises:\n    def __init__(self, expected):\n        self.expected = expected\n\n    def __enter__(self):\n        return self\n\n    def __exit__(self, exc_type, exc, tb):\n        if exc_type is None:\n            raise AssertionError(f"expected {self.expected.__name__} to be raised")\n        return issubclass(exc_type, self.expected)\n'''

    @staticmethod
    def _python_test_runner() -> str:
        return '''import importlib.util\nimport sys\n\nspec = importlib.util.spec_from_file_location("generated_repro_test", "generated_repro_test.py")\nmodule = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\ncount = 0\nfor name in sorted(dir(module)):\n    if name.startswith("test_") and callable(getattr(module, name)):\n        getattr(module, name)()\n        count += 1\nif count == 0:\n    print("NO_TESTS")\n    sys.exit(5)\nprint(f"PASS {count}")\n'''

    def _syntax_plan(self, language: str, code: str):
        if language == "python":

            return "generated_repro.py", lambda path: [sys.executable, "-m", "py_compile", path.name]

        if language == "java":
            javac = shutil.which("javac")
            class_name = self._java_public_class_name(code) or "GeneratedRepro"
            return f"{class_name}.java", (lambda path: [javac, "-Xlint:all", path.name] if javac else None)
        if language == "cpp":
            compiler = shutil.which("g++") or shutil.which("clang++")
            return "generated_repro.cpp", (lambda path: [compiler, "-fsyntax-only", path.name] if compiler else None)
        if language == "go":
            go = shutil.which("go")
            return "generated_repro_test.go", (lambda path: [go, "test", "-c", "."] if go else None)
        return None

    @staticmethod
    def _java_public_class_name(code: str) -> str | None:
        import re

        match = re.search(r"public\s+class\s+([A-Za-z_$][\w$]*)", code)
        return match.group(1) if match else None

    @staticmethod
    def _java_expected_exception(code: str) -> str | None:
        if "/ denominator" in code or " / denominator" in code:
            return "ArithmeticException"
        if "items.get(i)" in code:
            return "IndexOutOfBoundsException"
        if "value.trim()" in code and "String value = null" in code:
            return "NullPointerException"
        return None

    @staticmethod
    def _sanitized_env(language: str) -> dict[str, str]:

        allowed = {"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "JAVA_HOME", "HOME", "USERPROFILE"}
        env = {key: value for key, value in os.environ.items() if key in allowed}
        if language == "go":
            env.update({"GO111MODULE": "off", "GOPROXY": "off", "GOSUMDB": "off"})
        return env

    @staticmethod

    def _language_from_path(file_path: str) -> str:
        suffix = Path(file_path).suffix.lower()
        return {
            ".py": "python",
            ".java": "java",
            ".go": "go",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c": "cpp",
            ".h": "cpp",
            ".hpp": "cpp",
            ".js": "javascript",
            ".ts": "typescript",
        }.get(suffix, "unknown")

    @staticmethod
    def _framework_for(language: str) -> str | None:
        return {
            "python": "pytest-style repro snippet",
            "java": "self-contained main repro snippet",
            "go": "go test-style repro snippet",
            "cpp": "standalone repro snippet",
        }.get(language)

    def _code_for(self, rule_id: str, language: str, finding: Finding) -> str:
        if rule_id == "DIVISION-BY-ZERO-RISK":
            return self._division_by_zero(language)
        if rule_id == "COLLECTION-INDEX-OUT-OF-BOUNDS":
            return self._bounds(language)
        if rule_id == "POSSIBLE-NONE-DEREF":
            return self._null_deref(language)
        if rule_id == "RESOURCE-CLOSE-NOT-GUARANTEED":
            return self._resource_close(language)
        if rule_id == "SWALLOWED-EXCEPTION-FLOW":
            return self._swallowed_exception(language)
        if rule_id == "SUSPICIOUS-BOOLEAN-BITWISE":
            return self._boolean_bitwise(language)
        return self._manual_guide(finding)

    @staticmethod
    def _division_by_zero(language: str) -> str:
        snippets = {
            "python": """# Generated verification asset; not executed by CodeGuardian in generate mode.
import pytest


def generated_target(total, denominator):
    return total / denominator


def test_generated_division_by_zero_repro():
    with pytest.raises(ZeroDivisionError):
        generated_target(10, 0)
""",
            "java": """// Generated verification asset; not executed by CodeGuardian in generate mode.
public class GeneratedDivisionByZeroRepro {
    public static void main(String[] args) {
        int denominator = Integer.parseInt("0");
        int result = 10 / denominator;
        System.out.println(result);
    }
}
""",
            "go": """// Generated verification asset; not executed by CodeGuardian in generate mode.
package generatedrepro

import "testing"

func TestGeneratedDivisionByZeroRepro(t *testing.T) {
    defer func() {
        if recover() == nil {
            t.Fatal("expected divide-by-zero panic")
        }
    }()
    denominator := 0
    _ = 10 / denominator
}
""",
            "cpp": """// Generated verification asset; not executed by CodeGuardian in generate mode.
int generated_division_by_zero_repro() {
    int denominator = 0;
    return 10 / denominator;
}
""",
        }
        return snippets.get(language, "")

    @staticmethod
    def _bounds(language: str) -> str:
        snippets = {
            "python": """# Generated verification asset; not executed by CodeGuardian in generate mode.
import pytest


def generated_target(items):
    for i in range(len(items) + 1):
        _ = items[i]


def test_generated_bounds_repro():
    with pytest.raises(IndexError):
        generated_target(["only"])
""",
            "java": """// Generated verification asset; not executed by CodeGuardian in generate mode.
import java.util.List;

public class GeneratedBoundsRepro {
    public static void main(String[] args) {
        List<String> items = java.util.Collections.singletonList("only");
        for (int i = 0; i <= items.size(); i++) {
            items.get(i);
        }
    }
}
""",
            "go": """// Generated verification asset; not executed by CodeGuardian in generate mode.
package generatedrepro

import "testing"

func TestGeneratedBoundsRepro(t *testing.T) {
    defer func() {
        if recover() == nil {
            t.Fatal("expected index out of range panic")
        }
    }()
    items := []string{"only"}
    for i := 0; i <= len(items); i++ {
        _ = items[i]
    }
}
""",
            "cpp": """// Generated verification asset; not executed by CodeGuardian in generate mode.
// Generated C++ safe repro: self-contained and does not access files/network.
#include <stdexcept>
#include <vector>

int main() {
    std::vector<int> values{1};
    try {
        for (int i = 0; i <= static_cast<int>(values.size()); ++i) {
            (void)values.at(i);
        }
    } catch (const std::out_of_range&) {
        return 0;
    }
    return 1;
}
""",

        }
        return snippets.get(language, "")

    @staticmethod
    def _null_deref(language: str) -> str:
        snippets = {
            "python": """# Generated verification asset; not executed by CodeGuardian in generate mode.
import pytest


def test_generated_none_deref_repro():
    value = None
    with pytest.raises(AttributeError):
        value.strip()
""",
            "java": """// Generated verification asset; not executed by CodeGuardian in generate mode.
public class GeneratedNullDerefRepro {
    public static void main(String[] args) {
        String value = null;
        value.trim();
    }
}
""",
            "go": """// Generated verification asset; not executed by CodeGuardian in generate mode.
package generatedrepro

import "testing"

type demo struct{ value string }

func TestGeneratedNilDerefRepro(t *testing.T) {
    defer func() {
        if recover() == nil {
            t.Fatal("expected nil pointer panic")
        }
    }()
    var item *demo
    _ = item.value
}
""",
            "cpp": """// Generated verification asset; not executed by CodeGuardian in generate mode.
int generated_null_deref_repro() {
    int* value = nullptr;
    return *value;
}
""",
        }
        return snippets.get(language, "")

    @staticmethod
    def _resource_close(language: str) -> str:
        snippets = {
            "python": """# Generated verification asset; not executed by CodeGuardian in generate mode.
# Demonstrates the risky shape: manual close can be skipped if read() raises.
def generated_resource_close_repro(path):
    f = open(path)
    data = f.read()
    f.close()
    return data

# Safer shape:
# with open(path) as f:
#     return f.read()
""",
            "java": """// Generated verification asset; not executed by CodeGuardian in generate mode.
// Demonstrates the risky shape: close() can be skipped if read() throws.
class GeneratedResourceCloseRepro {
    int read(String path) throws Exception {
        java.io.FileInputStream in = new java.io.FileInputStream(path);
        int value = in.read();
        in.close();
        return value;
    }
}
""",
            "go": """// Generated verification asset; not executed by CodeGuardian in generate mode.
package generatedrepro

// Risky shape: Close can be skipped by early returns between Open and Close.
// Prefer: defer f.Close() immediately after successful open.
""",
            "cpp": """// Generated verification asset; not executed by CodeGuardian in generate mode.
// Risky shape: cleanup can be skipped by early returns/exceptions.
#include <cstdio>

int generated_resource_close_repro(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    int ch = fgetc(f);
    fclose(f);
    return ch;
}
""",
        }
        return snippets.get(language, "")

    @staticmethod
    def _swallowed_exception(language: str) -> str:
        snippets = {
            "python": """# Generated verification asset; not executed by CodeGuardian in generate mode.
def generated_swallowed_exception_repro(loader, logger):
    try:
        return loader()
    except Exception:
        logger.exception("load failed")
        return None

# Expected concern: caller cannot distinguish valid None from failure.
""",
            "java": """// Generated verification asset; not executed by CodeGuardian in generate mode.
class GeneratedSwallowedExceptionRepro {
    String load() {
        try {
            throw new RuntimeException("boom");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return null;
        }
    }
}
""",
            "go": """// Generated verification asset; not executed by CodeGuardian in generate mode.
package generatedrepro

// Risky shape: error is logged but not propagated to caller.
""",
            "cpp": """// Generated verification asset; not executed by CodeGuardian in generate mode.
#include <cstdio>

int generated_swallowed_exception_repro() {
    try {
        throw 1;
    } catch (...) {
        std::fprintf(stderr, "failed");
        return 0;
    }
}
""",
        }
        return snippets.get(language, "")

    @staticmethod
    def _boolean_bitwise(language: str) -> str:
        if language != "java":
            return ""
        return """// Generated verification asset; not executed by CodeGuardian in generate mode.
class GeneratedBooleanBitwiseRepro {
    boolean risky(String value) {
        // Single & evaluates both sides; value.trim() still runs when value == null.
        return value != null & value.trim().length() > 0;
    }
}
"""

    @staticmethod
    def _manual_guide(finding: Finding) -> str:
        return (
            "# Generated manual verification guide; not executed by CodeGuardian in generate mode.\n"
            f"# Finding: {finding.id} {finding.title}\n"
            f"# Location: {finding.location.file_path}:{finding.location.line_start or 1}\n"
            "# Suggested next step: construct a minimal input/configuration that reaches this line and assert the expected failure or safe behavior.\n"
        )
