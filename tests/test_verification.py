from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from securefix.models import Finding
from securefix.patching import PatchManager, PatchValidationError
from securefix.verification.evaluation import evaluate_strategies
from securefix.verification.isolated_workspace import IsolatedWorkspace, WorkspaceError
from securefix.verification.sandbox import (
    BubblewrapSandbox,
    SandboxResult,
    SandboxUnavailableError,
)
from securefix.verification.security_rescan import (
    SecurityRescanResult,
    SecurityScanner,
    compare_findings,
    run_security_rescan,
)
from securefix.verification.test_runner import (
    FunctionalTestResult,
    PytestRunner,
    TestExecutionStatus,
)
from securefix.verification.validation import (
    ValidationStatus,
    validate_candidate,
)
from securefix.verification.workflow import RepairWorkflow


ORIGINAL_SOURCE = "def run(value):\n    eval(value)\n    return True\n"
ORIGINAL_SCAN = {
    "results": [
        {
            "check_id": "python.security.test",
            "path": "app.py",
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {
                "message": "Unsafe evaluation",
                "severity": "ERROR",
                "lines": "eval(value)",
            },
        }
    ]
}
FIXED_SCAN = {
    "results": [
        {
            "check_id": "python.security.other",
            "path": "app.py",
            "start": {"line": 3},
            "end": {"line": 3},
            "extra": {
                "message": "New issue",
                "severity": "WARNING",
                "lines": "return True",
            },
        }
    ]
}


def _candidate(target: Path, replacement: str = "    int(value)"):
    finding = Finding(
        rule_id="python.security.test",
        file_path="app.py",
        start_line=2,
        end_line=2,
    )
    proposal = _proposal(replacement)
    return PatchManager().prepare(
        target,
        finding,
        proposal,
        context_start_line=1,
        context_end_line=3,
    )


def _proposal(replacement: str):
    from securefix.models import RepairAnalysis, RepairChange, RepairDetails, RepairProposal

    return RepairProposal(
        vulnerability_id="python.security.test",
        analysis=RepairAnalysis(
            vulnerability_type="unsafe evaluation",
            explanation="The shown call evaluates the supplied value.",
            security_impact="May execute unintended code.",
            assumptions=[],
        ),
        repair=RepairDetails(
            summary="Use restricted conversion.",
            file_path="app.py",
            changes=[
                RepairChange(
                    start_line=2,
                    end_line=2,
                    original_code="    eval(value)",
                    replacement_code=replacement,
                )
            ],
        ),
        reasoning_summary="Restricts the operation.",
        limitations=[],
    )


def _make_target(directory: Path) -> Path:
    directory.mkdir()
    (directory / "app.py").write_text(ORIGINAL_SOURCE, encoding="utf-8")
    (directory / "tests").mkdir()
    (directory / "tests" / "test_app.py").write_text(
        "def test_placeholder(): assert True\n",
        encoding="utf-8",
    )
    return directory


def test_isolated_workspace_applies_only_to_copy_and_discards_on_close(
    tmp_path: Path,
) -> None:
    target = _make_target(tmp_path / "target")
    candidate = _candidate(target)

    with IsolatedWorkspace(target) as workspace:
        original_copy = workspace.working_copy / "app.py"
        assert original_copy.read_text(encoding="utf-8") == ORIGINAL_SOURCE
        audit = workspace.apply(candidate)
        assert audit.applied
        assert "int(value)" in original_copy.read_text(encoding="utf-8")
        assert target.joinpath("app.py").read_text(encoding="utf-8") == ORIGINAL_SOURCE
        assert workspace.audit_record()["changes"][0]["original_sha256"]
        work_copy = workspace.working_copy

    assert not work_copy.exists()
    assert target.joinpath("app.py").read_text(encoding="utf-8") == ORIGINAL_SOURCE


def test_isolated_workspace_revalidates_source_and_rejects_bad_candidate(
    tmp_path: Path,
) -> None:
    target = _make_target(tmp_path / "target")
    candidate = _candidate(target)

    with IsolatedWorkspace(target) as workspace:
        (workspace.working_copy / "app.py").write_text("changed\n", encoding="utf-8")
        with pytest.raises(WorkspaceError, match="does not match"):
            workspace.apply(candidate)


def test_isolated_workspace_rejects_escaping_symlink(tmp_path: Path) -> None:
    target = _make_target(tmp_path / "target")
    outside = tmp_path / "outside.py"
    outside.write_text("outside\n", encoding="utf-8")
    (target / "escape.py").symlink_to(outside)

    with pytest.raises(WorkspaceError, match="outside"):
        IsolatedWorkspace(target)


def test_pytest_runner_executes_in_real_bubblewrap_sandbox(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("Bubblewrap is not installed")
    target = tmp_path / "copy"
    (target / "tests").mkdir(parents=True)
    (target / "tests" / "test_example.py").write_text(
        "def test_ok(): assert 1 + 1 == 2\n",
        encoding="utf-8",
    )

    result = PytestRunner(timeout_seconds=20).run(target)

    assert result.status == TestExecutionStatus.PASSED
    assert result.passed == 1
    assert result.sandbox.startswith("bubblewrap")


def test_sandbox_can_import_pytest_and_pygments(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("Bubblewrap is not installed")
    target = tmp_path / "copy"
    target.mkdir()
    sandbox = BubblewrapSandbox()

    result = sandbox.run(
        [
            str(Path(sys.executable).resolve()),
            "-c",
            "import pytest, pygments; print('pytest=' + pytest.__version__); "
            "print('pygments=' + pygments.__version__)",
        ],
        working_copy=target,
        timeout_seconds=20,
    )

    assert result.returncode == 0, result.stderr
    assert "pytest=" in result.stdout
    assert "pygments=" in result.stdout


def test_sandbox_hides_host_files_network_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("Bubblewrap is not installed")
    target = tmp_path / "copy"
    target.mkdir()
    host_marker = tmp_path / "host-only.txt"
    host_marker.write_text("must not be visible", encoding="utf-8")
    monkeypatch.setenv("GEMINI_API_KEY", "securefix-test-only-secret")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    script = (
        "import json, os, socket\n"
        f"marker = {str(host_marker)!r}\n"
        "readable = os.path.exists(marker)\n"
        "writable = False\n"
        "try:\n"
        "    open(marker, 'w').close()\n"
        "    writable = True\n"
        "except OSError:\n"
        "    pass\n"
        "connected = False\n"
        "try:\n"
        f"    socket.create_connection(('127.0.0.1', {port}), timeout=0.5).close()\n"
        "    connected = True\n"
        "except OSError:\n"
        "    pass\n"
        "print(json.dumps({'readable': readable, 'writable': writable, "
        "'connected_to_host': connected, "
        "'api_key_visible': bool(os.getenv('GEMINI_API_KEY'))}))\n"
    )
    try:
        result = BubblewrapSandbox().run(
            [str(Path(sys.executable).resolve()), "-c", script],
            working_copy=target,
            timeout_seconds=10,
        )
    finally:
        listener.close()

    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed == {
        "readable": False,
        "writable": False,
        "connected_to_host": False,
        "api_key_visible": False,
    }


def test_pytest_runner_reports_missing_python_dependency() -> None:
    class MissingDependencySandbox:
        def run(self, command, *, working_copy, timeout_seconds):
            return SandboxResult(
                command=list(command),
                returncode=1,
                stdout="",
                stderr="ModuleNotFoundError: No module named 'pygments'\n",
                timed_out=False,
                duration_seconds=0.01,
                output_truncated=False,
                sandbox="bubblewrap (test double)",
            )

    result = PytestRunner(sandbox=MissingDependencySandbox()).run(".")

    assert result.status == TestExecutionStatus.EXECUTION_ERROR
    assert result.passed is None
    assert result.failed is None
    assert "pygments" in result.error
    assert "ModuleNotFoundError" in result.stderr


def test_pytest_runner_distinguishes_test_failures(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("Bubblewrap is not installed")
    target = tmp_path / "copy"
    (target / "tests").mkdir(parents=True)
    (target / "tests" / "test_example.py").write_text(
        "def test_fails(): assert False\n",
        encoding="utf-8",
    )

    result = PytestRunner(timeout_seconds=20).run(target)

    assert result.status == TestExecutionStatus.FAILED
    assert result.failed == 1
    assert "FAILED tests/test_example.py" in result.stdout


def test_pytest_runner_timeout_is_bounded() -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("Bubblewrap is not installed")
    target = Path(tempfile.mkdtemp(prefix="securefix-timeout-test-"))
    sandbox = BubblewrapSandbox(cpu_limit_seconds=20)
    try:
        result = sandbox.run(
            [str(Path(sys.executable).resolve()), "-c", "import time; time.sleep(5)"],
            working_copy=target,
            timeout_seconds=1,
        )
    finally:
        shutil.rmtree(target)

    assert result.timed_out


def test_sandbox_fails_closed_when_bubblewrap_is_missing() -> None:
    with pytest.raises(SandboxUnavailableError):
        BubblewrapSandbox(executable="securefix-no-such-sandbox")


def test_security_comparison_detects_original_and_new_findings(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    original = [
        Finding(rule_id="original.rule", file_path="app.py", severity="ERROR"),
    ]
    current = [
        Finding(rule_id="original.rule", file_path="app.py", severity="WARNING"),
        Finding(rule_id="new.rule", file_path="app.py", severity="ERROR"),
    ]

    comparison = compare_findings(
        original,
        current,
        original_target=root,
        current_target=root,
        selected_finding=original[0],
    )

    assert comparison.original_finding_remains is True
    assert [item["rule_id"] for item in comparison.introduced_findings] == ["new.rule"]
    assert comparison.severity_changes[0]["current_severities"] == ["WARNING"]


class SequenceScanner(SecurityScanner):
    def __init__(self, results: list[dict[str, object]]) -> None:
        self.results = list(results)

    def scan(self, target):
        result = self.results.pop(0)
        from securefix.detection import parse_findings

        return result, parse_findings(result)


def test_security_rescan_failure_is_explicit() -> None:
    from securefix.scanner import ScannerExecutionError

    class FailedScanner:
        def scan(self, target):
            raise ScannerExecutionError("scanner unavailable")

    result = run_security_rescan(
        FailedScanner(),
        ".",
        original_target=".",
        original_findings=[],
        selected_finding=Finding(rule_id="rule"),
    )

    assert result.status == "ERROR"
    assert result.original_finding_remains is None


def _test_result(status: str, *, failed: int = 0) -> FunctionalTestResult:
    return FunctionalTestResult(
        status=status,
        exit_code=0 if status == "PASSED" else 1,
        passed=1 if status == "PASSED" else 0,
        failed=failed,
        skipped=0,
        stdout="1 passed in 0.01s" if status == "PASSED" else "FAILED tests/test.py",
        stderr="",
        duration_seconds=0.1,
        timed_out=False,
        output_truncated=False,
        error=None,
        sandbox="bubblewrap",
    )


@pytest.mark.parametrize(
    ("test_status", "security_results", "expected"),
    [
        (TestExecutionStatus.PASSED, [], ValidationStatus.VALIDATED),
        (TestExecutionStatus.FAILED, [], ValidationStatus.FAILED_TESTS),
        (TestExecutionStatus.PASSED, [Finding(rule_id="new")], ValidationStatus.NEW_SECURITY_FINDINGS),
        (TestExecutionStatus.PASSED, [Finding(rule_id="original")], ValidationStatus.SECURITY_FINDING_REMAINS),
    ],
)
def test_validation_decision_statuses(
    test_status: str,
    security_results: list[Finding],
    expected: ValidationStatus,
) -> None:
    from securefix.verification.security_rescan import SecurityRescanResult

    security = SecurityRescanResult(
        status="COMPLETED",
        original_finding_remains=bool(security_results and security_results[0].rule_id == "original"),
        original_findings=[],
        remaining_original_findings=[],
        introduced_findings=[
            item for item in security_results if item.rule_id != "original"
        ],
        severity_changes=[],
        scanner_errors=[],
        scan_results=None,
        error=None,
    )
    if security_results and security_results[0].rule_id == "original":
        security = SecurityRescanResult(
            **{
                **security.__dict__,
                "introduced_findings": [],
                "original_finding_remains": True,
            }
        )
    tests = _test_result(test_status, failed=1 if test_status == TestExecutionStatus.FAILED else 0)

    result = validate_candidate(
        patch_applied=True,
        tests=tests,
        security=security,
        original_source_preserved=True,
    )

    assert result.status == expected


def test_validation_never_succeeds_when_a_required_check_failed_or_was_skipped() -> None:
    clean_security = SecurityRescanResult(
        status="COMPLETED",
        original_finding_remains=False,
        original_findings=[],
        remaining_original_findings=[],
        introduced_findings=[],
        severity_changes=[],
        scanner_errors=[],
        scan_results=None,
        error=None,
    )
    failed_rescan = SecurityRescanResult(
        **{
            **clean_security.__dict__,
            "status": "ERROR",
            "original_finding_remains": None,
            "error": "scanner unavailable",
        }
    )
    rescan_with_errors = SecurityRescanResult(
        **{**clean_security.__dict__, "scanner_errors": ["partial scan"]}
    )
    cases = [
        {
            "patch_applied": True,
            "tests": None,
            "security": clean_security,
            "original_source_preserved": True,
        },
        {
            "patch_applied": True,
            "tests": _test_result("SKIPPED"),
            "security": clean_security,
            "original_source_preserved": True,
        },
        {
            "patch_applied": True,
            "tests": _test_result(TestExecutionStatus.EXECUTION_ERROR),
            "security": clean_security,
            "original_source_preserved": True,
        },
        {
            "patch_applied": True,
            "tests": _test_result(TestExecutionStatus.PASSED),
            "security": None,
            "original_source_preserved": True,
        },
        {
            "patch_applied": True,
            "tests": _test_result(TestExecutionStatus.PASSED),
            "security": failed_rescan,
            "original_source_preserved": True,
        },
        {
            "patch_applied": True,
            "tests": _test_result(TestExecutionStatus.PASSED),
            "security": rescan_with_errors,
            "original_source_preserved": True,
        },
        {
            "patch_applied": True,
            "tests": _test_result(TestExecutionStatus.PASSED),
            "security": clean_security,
            "original_source_preserved": None,
        },
        {
            "patch_applied": True,
            "tests": _test_result(TestExecutionStatus.PASSED),
            "security": clean_security,
            "original_source_preserved": False,
        },
        {
            "patch_applied": False,
            "tests": _test_result(TestExecutionStatus.PASSED),
            "security": clean_security,
            "original_source_preserved": True,
        },
    ]

    for evidence in cases:
        assert validate_candidate(**evidence).status != ValidationStatus.VALIDATED


class Provider:
    model = "test-model"

    def __init__(self, replacements: list[str] | None = None) -> None:
        self.replacements = replacements or ["    int(value)"]
        self.calls = 0
        self.last_usage = None
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        replacement = self.replacements[min(self.calls, len(self.replacements) - 1)]
        self.calls += 1
        return json.dumps(_proposal(replacement).to_dict())


class StubTests:
    def __init__(self, statuses: list[str]) -> None:
        self.statuses = statuses
        self.calls = 0

    def run(self, working_copy):
        status = self.statuses[min(self.calls, len(self.statuses) - 1)]
        self.calls += 1
        return _test_result(status, failed=1 if status == TestExecutionStatus.FAILED else 0)


def _original_finding() -> Finding:
    return Finding(
        rule_id="python.security.test",
        severity="ERROR",
        file_path="app.py",
        start_line=2,
        end_line=2,
        message="Unsafe evaluation",
        matched_code="eval(value)",
    )


def _scan_document(findings: list[Finding]) -> dict[str, object]:
    records = []
    for finding in findings:
        records.append(
            {
                "check_id": finding.rule_id,
                "path": finding.file_path,
                "start": {"line": finding.start_line},
                "end": {"line": finding.end_line},
                "extra": {
                    "message": finding.message or "finding",
                    "severity": finding.severity or "ERROR",
                    "lines": finding.matched_code or "source",
                },
            }
        )
    return {"results": records}


def test_workflow_stops_after_success_and_preserves_every_artifact(
    tmp_path: Path,
) -> None:
    target = _make_target(tmp_path / "project")
    provider = Provider()
    scanner = SequenceScanner(
        [
            _scan_document([_original_finding()]),
            _scan_document([]),
        ]
    )
    workflow = RepairWorkflow(
        provider,
        scanner=scanner,
        test_runner=StubTests([TestExecutionStatus.PASSED]),
        output_directory=tmp_path / "reports",
    )

    result = workflow.run(target, strategy="structured", maximum_attempts=3)

    assert result.final_status == ValidationStatus.VALIDATED.value
    assert len(result.attempts) == 1
    assert (Path(result.report_directory) / "original-scan.json").exists()
    assert (Path(result.report_directory) / "attempt-01" / "candidate.diff").exists()
    assert (Path(result.report_directory) / "workflow-report.json").exists()
    assert (target / "app.py").read_text(encoding="utf-8") == ORIGINAL_SOURCE


def test_workflow_refines_once_with_feedback_then_stops_on_success(
    tmp_path: Path,
) -> None:
    target = _make_target(tmp_path / "project")
    provider = Provider(["    int(value)", "    str(value)"])
    scanner = SequenceScanner(
        [
            _scan_document([_original_finding()]),
            _scan_document([_original_finding()]),
            _scan_document([]),
        ]
    )
    workflow = RepairWorkflow(
        provider,
        scanner=scanner,
        test_runner=StubTests(
            [TestExecutionStatus.FAILED, TestExecutionStatus.PASSED]
        ),
        output_directory=tmp_path / "reports",
    )

    result = workflow.run(target, strategy="basic", maximum_attempts=3)

    assert result.final_status == ValidationStatus.VALIDATED.value
    assert len(result.attempts) == 2
    assert "Prior attempt and feedback" in provider.prompts[1]
    assert "FAILED_TESTS" in provider.prompts[1]
    assert (Path(result.report_directory) / "attempt-01" / "attempt-report.json").exists()
    assert (Path(result.report_directory) / "attempt-02" / "attempt-report.json").exists()
    assert (target / "app.py").read_text(encoding="utf-8") == ORIGINAL_SOURCE


def test_workflow_enforces_attempt_limit_and_records_failed_history(
    tmp_path: Path,
) -> None:
    target = _make_target(tmp_path / "project")
    provider = Provider()
    scanner = SequenceScanner(
        [
            _scan_document([_original_finding()]),
            _scan_document([_original_finding()]),
            _scan_document([_original_finding()]),
            _scan_document([_original_finding()]),
        ]
    )
    workflow = RepairWorkflow(
        provider,
        scanner=scanner,
        test_runner=StubTests([TestExecutionStatus.FAILED]),
        output_directory=tmp_path / "reports",
    )

    result = workflow.run(target, strategy="structured", maximum_attempts=3)

    assert result.final_status == ValidationStatus.FAILED_TESTS.value
    assert len(result.attempts) == 3
    assert provider.calls == 3
    assert (target / "app.py").read_text(encoding="utf-8") == ORIGINAL_SOURCE


def test_workflow_never_claims_validation_without_security_rescan(
    tmp_path: Path,
) -> None:
    target = _make_target(tmp_path / "project")
    provider = Provider()
    scanner = SequenceScanner(
        [
            _scan_document([_original_finding()]),
            _scan_document([_original_finding()]),
        ]
    )
    workflow = RepairWorkflow(
        provider,
        scanner=scanner,
        test_runner=StubTests([TestExecutionStatus.PASSED]),
        output_directory=tmp_path / "reports",
    )

    result = workflow.run(target, strategy="basic", maximum_attempts=1)

    assert result.final_status == ValidationStatus.SECURITY_FINDING_REMAINS.value


def test_evaluation_metrics_and_json_report_are_reproducible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securefix.verification import evaluation

    dataset = tmp_path / "dataset"
    case = dataset / "sql-injection"
    case.mkdir(parents=True)
    (case / "case.json").write_text(
        json.dumps(
            {
                "case_id": "sql-demo",
                "category": "sql_injection",
                "expected_secure_behavior": "Return only the requested user.",
                "semgrep_support": "not_assessed",
            }
        ),
        encoding="utf-8",
    )

    class StubWorkflow:
        def __init__(self, provider, **kwargs):
            self.strategy = None

        def run(self, target, *, strategy, maximum_attempts):
            return SimpleNamespace(
                to_dict=lambda: {
                    "final_status": "VALIDATED",
                    "attempts": [
                        {
                            "generation": "completed",
                            "patch_application": {"applied": True},
                            "tests": {"status": "PASSED"},
                            "security_rescan": {
                                "status": "COMPLETED",
                                "scanner_errors": [],
                                "original_finding_remains": False,
                                "introduced_findings": [],
                            },
                            "validation": {"status": "VALIDATED"},
                        }
                    ],
                    "original_findings": [],
                    "token_usage": {
                        "input_tokens": None,
                        "output_tokens": None,
                        "total_tokens": None,
                    },
                    "report_directory": "mock-run",
                    "model": "mock-model",
                }
            )

    monkeypatch.setattr(evaluation, "RepairWorkflow", StubWorkflow)
    output = tmp_path / "evaluation-results"
    report = evaluate_strategies(
        dataset,
        strategies=["basic", "structured", "context_feedback"],
        provider_factory=lambda: object(),
        output_directory=output,
    )

    assert len(report["strategies"]) == 3
    metrics = report["strategies"][0]["metrics"]
    assert metrics["candidate_patches_generated"] == 1
    assert metrics["validated_repair_rate"] == 1.0
    assert metrics["input_tokens"] is None
    assert (output / "evaluation-report.json").exists()
    assert (output / "evaluation-summary.txt").exists()
