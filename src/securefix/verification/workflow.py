"""Bounded candidate generation, isolated validation, and feedback refinement."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

from securefix.analysis import RepairAnalyzer
from securefix.context import collect_context, resolve_target_file
from securefix.detection import parse_findings
from securefix.llm.gemini_provider import LLMError
from securefix.llm.prompts import PromptStrategy
from securefix.models import Finding, RepairProposal
from securefix.patching import CandidatePatch, PatchManager, PatchValidationError
from securefix.sanitization import redact_nested, redact_sensitive_text
from securefix.scanner import SemgrepError, SemgrepScanner
from securefix.verification.integrity import snapshot_tree, verify_tree_snapshot
from securefix.verification.isolated_workspace import IsolatedWorkspace, WorkspaceError
from securefix.verification.security_rescan import (
    SecurityRescanResult,
    SecurityScanner,
    run_security_rescan,
)
from securefix.verification.test_runner import FunctionalTestResult, PytestRunner
from securefix.verification.validation import (
    ValidationResult,
    ValidationStatus,
    validate_candidate,
)


class RepairWorkflowError(RuntimeError):
    """Raised when a complete repair workflow cannot be initialized."""


class ProposalProvider(Protocol):
    @property
    def last_usage(self) -> Any: ...


@dataclass(frozen=True)
class RepairWorkflowResult:
    run_id: str
    report_directory: str
    original_scan: dict[str, Any] | None
    original_findings: list[dict[str, Any]]
    selected_finding: dict[str, Any] | None
    strategy: str
    model: str | None
    maximum_attempts: int
    attempts: list[dict[str, Any]]
    final_status: str
    integrity: dict[str, Any]
    limitations: list[str]
    processing_time_seconds: float
    token_usage: dict[str, int | None]

    def to_dict(self) -> dict[str, Any]:
        return redact_nested(asdict(self))


class RepairWorkflow:
    DEFAULT_MAXIMUM_ATTEMPTS = 3
    ABSOLUTE_MAXIMUM_ATTEMPTS = 10
    DEFAULT_TEST_TIMEOUT_SECONDS = 180

    def __init__(
        self,
        provider: ProposalProvider,
        *,
        scanner: SecurityScanner | None = None,
        test_runner: PytestRunner | None = None,
        patch_manager: PatchManager | None = None,
        output_directory: str | Path = "reports/verification",
        scanner_config: str | Sequence[str] = "auto",
        scanner_timeout_seconds: int = 120,
        test_timeout_seconds: int = DEFAULT_TEST_TIMEOUT_SECONDS,
        context_lines: int = 5,
    ) -> None:
        if not 0 <= context_lines <= 100:
            raise ValueError("context_lines must be between 0 and 100")
        if scanner_timeout_seconds <= 0 or test_timeout_seconds <= 0:
            raise ValueError("Scanner and test timeouts must be positive")
        self.provider = provider
        self.scanner = scanner or SecurityScanner(
            config=scanner_config,
            timeout_seconds=scanner_timeout_seconds,
        )
        self.test_runner = test_runner or PytestRunner(
            timeout_seconds=test_timeout_seconds
        )
        self.patch_manager = patch_manager or PatchManager()
        self.output_directory = Path(output_directory)
        self.scanner_config = scanner_config
        self.scanner_timeout_seconds = scanner_timeout_seconds
        self.test_timeout_seconds = test_timeout_seconds
        self.context_lines = context_lines

    def run(
        self,
        target_directory: str | Path,
        *,
        strategy: PromptStrategy | str,
        finding_index: int = 1,
        maximum_attempts: int = DEFAULT_MAXIMUM_ATTEMPTS,
    ) -> RepairWorkflowResult:
        started = time.monotonic()
        target = Path(target_directory).resolve(strict=True)
        if not target.is_dir():
            raise RepairWorkflowError("Project target is not a directory")
        try:
            selected_strategy = PromptStrategy(strategy)
        except ValueError as exc:
            raise RepairWorkflowError(f"Unknown strategy: {strategy}") from exc
        if not 1 <= maximum_attempts <= self.ABSOLUTE_MAXIMUM_ATTEMPTS:
            raise RepairWorkflowError(
                f"maximum_attempts must be between 1 and {self.ABSOLUTE_MAXIMUM_ATTEMPTS}"
            )
        if finding_index < 1:
            raise RepairWorkflowError("finding_index must be at least 1")

        report_directory = self._create_run_directory(target)
        run_id = report_directory.name
        original_integrity = snapshot_tree(target)
        original_results: dict[str, Any] | None = None
        original_findings: list[Finding] = []
        attempt_history: list[dict[str, Any]] = []
        token_calls: list[dict[str, int | None]] = []
        selected_finding: Finding | None = None
        baseline_errors: list[Any] = []
        try:
            original_results, original_findings = self.scanner.scan(target)
            baseline_errors = original_results.get("errors", [])
            if not isinstance(baseline_errors, list):
                raise RepairWorkflowError("Original Semgrep report contains malformed errors")
        except (SemgrepError, OSError, ValueError, RepairWorkflowError) as exc:
            self._write_json(
                report_directory / "workflow-report.json",
                self._incomplete_report(
                    run_id,
                    report_directory,
                    selected_strategy.value,
                    maximum_attempts,
                    f"Original security scan failed: {exc}",
                    target,
                    original_integrity,
                    started,
                ),
            )
            raise RepairWorkflowError(
                f"Original security scan failed: {exc}; report: {report_directory}"
            ) from exc

        self._write_json(
            report_directory / "original-scan.json",
            {
                "scanner": "semgrep",
                "target": str(target),
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "scan_results": redact_nested(original_results),
                "findings": [self._finding_data(item, target) for item in original_findings],
            },
        )
        if baseline_errors:
            self._write_json(
                report_directory / "workflow-report.json",
                self._incomplete_report(
                    run_id,
                    report_directory,
                    selected_strategy.value,
                    maximum_attempts,
                    "Original Semgrep scan reported errors; before-and-after comparison is inconclusive.",
                    target,
                    original_integrity,
                    started,
                ),
            )
            raise RepairWorkflowError(
                "Original Semgrep scan reported errors; safe before-and-after validation "
                f"cannot proceed. The original scan is preserved in {report_directory}."
            )
        if finding_index > len(original_findings):
            self._write_json(
                report_directory / "workflow-report.json",
                self._incomplete_report(
                    run_id,
                    report_directory,
                    selected_strategy.value,
                    maximum_attempts,
                    f"Finding index {finding_index} is unavailable "
                    f"({len(original_findings)} finding(s) found)",
                    target,
                    original_integrity,
                    started,
                ),
            )
            raise RepairWorkflowError(
                f"Finding index {finding_index} is unavailable "
                f"({len(original_findings)} finding(s) found); report: {report_directory}"
            )

        selected_finding = original_findings[finding_index - 1]
        if not selected_finding.file_path or selected_finding.start_line is None:
            raise RepairWorkflowError("Selected finding has no source path or start line")
        target_root, source_path = resolve_target_file(target, selected_finding.file_path)
        relative_path = source_path.relative_to(target_root).as_posix()
        context = collect_context(
            target,
            selected_finding.file_path,
            selected_finding.start_line,
            selected_finding.end_line or selected_finding.start_line,
            self.context_lines,
        ).to_dict()

        previous_proposal: RepairProposal | None = None
        feedback: str | None = None
        final_status = ValidationStatus.INCONCLUSIVE.value
        for attempt_number in range(1, maximum_attempts + 1):
            attempt_started = time.monotonic()
            attempt_directory = report_directory / f"attempt-{attempt_number:02d}"
            attempt_directory.mkdir(mode=0o700)
            attempt_record: dict[str, Any] = {
                "attempt": attempt_number,
                "strategy": (
                    selected_strategy.value
                    if attempt_number == 1
                    else PromptStrategy.CONTEXT_FEEDBACK.value
                ),
                "started_at": datetime.now(timezone.utc).isoformat(),
                "generation": "pending",
                "candidate_files": None,
                "patch_application": {"applied": False},
                "tests": None,
                "security_rescan": None,
                "validation": None,
                "token_usage": None,
            }
            proposal: RepairProposal | None = None
            candidate: CandidatePatch | None = None
            try:
                attempt_strategy = (
                    selected_strategy
                    if attempt_number == 1
                    else PromptStrategy.CONTEXT_FEEDBACK
                )
                previous_text = (
                    json.dumps(redact_nested(previous_proposal.to_dict()), ensure_ascii=False)
                    if previous_proposal is not None
                    else None
                )
                call_started = time.monotonic()
                try:
                    proposal = RepairAnalyzer(self.provider).generate(
                        selected_finding,
                        context,
                        strategy=attempt_strategy,
                        target_relative_path=relative_path,
                        previous_repair=previous_text,
                        validation_failure=feedback,
                    )
                finally:
                    usage = _usage_data(getattr(self.provider, "last_usage", None))
                    token_calls.append(usage)
                    attempt_record["generation_seconds"] = round(
                        time.monotonic() - call_started, 6
                    )
                    attempt_record["token_usage"] = usage

                candidate = self.patch_manager.prepare(
                    target,
                    selected_finding,
                    proposal,
                    context_start_line=context["start_line"],
                    context_end_line=context["end_line"],
                )
                self._save_candidate(candidate, attempt_directory)
                attempt_record["candidate_files"] = {
                    "proposal": "candidate.json",
                    "unified_diff": "candidate.diff",
                    "redacted": True,
                }
                attempt_record["generation"] = "completed"
                previous_proposal = proposal
            except (LLMError, PatchValidationError, ValueError, OSError) as exc:
                attempt_record["generation"] = "failed"
                attempt_record["generation_error"] = _safe_error(exc)
                attempt_record["validation"] = validate_candidate(
                    patch_applied=False,
                    tests=None,
                    security=None,
                    original_source_preserved=True,
                    patch_error=f"Candidate generation/validation failed: {_safe_error(exc)}",
                ).to_dict()
                final_status = attempt_record["validation"]["status"]
                attempt_record["duration_seconds"] = round(
                    time.monotonic() - attempt_started, 6
                )
                self._write_json(attempt_directory / "attempt-report.json", attempt_record)
                attempt_history.append(attempt_record)
                feedback = _safe_error(exc)
                continue

            tests: FunctionalTestResult | None = None
            security: SecurityRescanResult | None = None
            patch_applied = False
            patch_error: str | None = None
            try:
                with IsolatedWorkspace(target) as workspace:
                    try:
                        applied = workspace.apply(candidate)
                        patch_applied = True
                        attempt_record["patch_application"] = redact_nested(asdict(applied))
                    except (WorkspaceError, OSError, ValueError) as exc:
                        patch_error = _safe_error(exc)
                        attempt_record["patch_application"] = {
                            "applied": False,
                            "error": patch_error,
                        }

                    if patch_applied:
                        tests = self.test_runner.run(workspace.working_copy)
                        security = run_security_rescan(
                            self.scanner,
                            workspace.working_copy,
                            original_target=target,
                            original_findings=original_findings,
                            selected_finding=selected_finding,
                        )
                        if baseline_errors:
                            security = _rescan_with_baseline_error(security)

                    attempt_record["tests"] = tests.to_dict() if tests else None
                    attempt_record["security_rescan"] = (
                        security.to_dict() if security else None
                    )
                    attempt_record["workspace_audit"] = workspace.audit_record()
            except (WorkspaceError, OSError, ValueError) as exc:
                patch_error = _safe_error(exc)
                attempt_record["patch_application"] = {
                    "applied": False,
                    "error": patch_error,
                }

            integrity = verify_tree_snapshot(target, original_integrity)
            attempt_record["original_integrity"] = integrity
            validation = validate_candidate(
                patch_applied=patch_applied,
                tests=tests,
                security=security,
                original_source_preserved=integrity["preserved"],
                patch_error=patch_error,
            )
            attempt_record["validation"] = validation.to_dict()
            attempt_record["duration_seconds"] = round(
                time.monotonic() - attempt_started, 6
            )
            self._write_json(attempt_directory / "attempt-report.json", attempt_record)
            attempt_history.append(attempt_record)
            final_status = validation.status.value

            if validation.status == ValidationStatus.VALIDATED:
                break
            if attempt_number == maximum_attempts or not _is_refinable(validation.status):
                break
            feedback = _make_feedback(validation)

        integrity = verify_tree_snapshot(target, original_integrity)
        workflow_result = RepairWorkflowResult(
            run_id=run_id,
            report_directory=str(report_directory),
            original_scan={
                "file": "original-scan.json",
                "finding_count": len(original_findings),
                "scanner_config": self.scanner_config,
            },
            original_findings=[self._finding_data(item, target) for item in original_findings],
            selected_finding=(
                self._finding_data(selected_finding, target) if selected_finding else None
            ),
            strategy=selected_strategy.value,
            model=getattr(self.provider, "model", None),
            maximum_attempts=maximum_attempts,
            attempts=attempt_history,
            final_status=final_status,
            integrity=integrity,
            limitations=[
                "Semgrep disappearance is not proof that the vulnerability is eliminated.",
                "Bubblewrap isolates test processes, filesystem writes, and networking, "
                "but does not guarantee protection from every kernel or sandbox escape.",
                "Tests are project-controlled and therefore are evidence, not proof of "
                "behavioral correctness.",
            ],
            processing_time_seconds=round(time.monotonic() - started, 6),
            token_usage=_aggregate_usage(token_calls),
        )
        self._write_json(report_directory / "workflow-report.json", workflow_result.to_dict())
        self._write_summary(report_directory / "summary.txt", workflow_result)
        return workflow_result

    def _create_run_directory(self, target: Path) -> Path:
        base = self.output_directory.resolve()
        if base == target or base.is_relative_to(target):
            raise RepairWorkflowError("Workflow reports must be stored outside the target project")
        base.mkdir(parents=True, exist_ok=True)
        run_directory = base / f"securefix-run-{uuid.uuid4().hex}"
        run_directory.mkdir(mode=0o700)
        return run_directory

    def _save_candidate(self, candidate: CandidatePatch, directory: Path) -> None:
        proposal = candidate.proposal_json()
        diff = candidate.unified_diff
        redacted_proposal = redact_sensitive_text(proposal)
        redacted_diff = redact_sensitive_text(diff)
        (directory / "candidate.json").write_text(
            redacted_proposal,
            encoding="utf-8",
        )
        (directory / "candidate.diff").write_text(redacted_diff, encoding="utf-8")

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        path.write_text(
            json.dumps(redact_nested(data), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _finding_data(finding: Finding, root: Path) -> dict[str, Any]:
        record = finding.to_dict()
        if finding.file_path:
            path = Path(finding.file_path)
            resolved = (root / path).resolve(strict=False) if not path.is_absolute() else path.resolve(strict=False)
            try:
                record["file_path"] = resolved.relative_to(root).as_posix()
            except ValueError:
                record["file_path"] = path.as_posix()
        return redact_nested(record)

    @staticmethod
    def _incomplete_report(
        run_id: str,
        report_directory: Path,
        strategy: str,
        maximum_attempts: int,
        error: str,
        target: Path,
        original_integrity: dict[str, str],
        started: float,
    ) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "report_directory": str(report_directory),
            "target": str(target),
            "strategy": strategy,
            "maximum_attempts": maximum_attempts,
            "attempts": [],
            "final_status": ValidationStatus.INCONCLUSIVE.value,
            "error": error,
            "integrity": verify_tree_snapshot(target, original_integrity),
            "processing_time_seconds": round(time.monotonic() - started, 6),
        }

    @staticmethod
    def _write_summary(path: Path, result: RepairWorkflowResult) -> None:
        lines = [
            "SecureFix verification summary",
            f"Run: {result.run_id}",
            f"Strategy: {result.strategy}",
            f"Model: {result.model or 'unknown'}",
            f"Status: {result.final_status}",
            f"Attempts: {len(result.attempts)}/{result.maximum_attempts}",
            f"Original project preserved: {result.integrity.get('preserved')}",
            f"Processing time (seconds): {result.processing_time_seconds}",
            "",
        ]
        for attempt in result.attempts:
            validation = attempt.get("validation") or {}
            lines.append(
                f"Attempt {attempt['attempt']}: {validation.get('status', 'UNKNOWN')}"
            )
        lines.extend(
            [
                "",
                "A successful scan is not proof of complete security.",
                "Review all proposal, diff, and attempt artifacts manually.",
            ]
        )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _safe_error(error: Exception | str) -> str:
    return redact_sensitive_text(str(error))[:2000]


def _usage_data(usage: Any) -> dict[str, int | None]:
    if usage is None:
        return {"input_tokens": None, "output_tokens": None, "total_tokens": None}
    return {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }


def _aggregate_usage(
    calls: list[dict[str, int | None]],
) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for field in ("input_tokens", "output_tokens", "total_tokens"):
        values = [call[field] for call in calls]
        result[field] = (
            sum(value for value in values if isinstance(value, int))
            if values and all(isinstance(value, int) for value in values)
            else None
        )
    return result


def _make_feedback(validation: ValidationResult) -> str:
    tests = validation.tests or {}
    security = validation.security or {}
    feedback = {
        "validation_status": validation.status.value,
        "reasons": validation.reasons,
        "functional_tests": {
            "status": tests.get("status"),
            "exit_code": tests.get("exit_code"),
            "passed": tests.get("passed"),
            "failed": tests.get("failed"),
            "skipped": tests.get("skipped"),
            "failure_identifiers": _failure_identifiers(tests),
        },
        "security_rescan": {
            "status": security.get("status"),
            "original_finding_remains": security.get("original_finding_remains"),
            "introduced_findings": security.get("introduced_findings", [])[:10],
            "scanner_errors": security.get("scanner_errors", [])[:5],
        },
    }
    return redact_sensitive_text(json.dumps(feedback, ensure_ascii=False))[:8000]


def _failure_identifiers(tests: dict[str, Any]) -> list[str]:
    output = "\n".join(
        str(tests.get(field) or "") for field in ("stdout", "stderr")
    )
    identifiers = [
        line.strip()
        for line in output.splitlines()
        if line.strip().startswith(("FAILED ", "ERROR "))
    ]
    return [redact_sensitive_text(line)[:500] for line in identifiers[:10]]


def _is_refinable(status: ValidationStatus) -> bool:
    return status in {
        ValidationStatus.FAILED_TESTS,
        ValidationStatus.SECURITY_FINDING_REMAINS,
        ValidationStatus.NEW_SECURITY_FINDINGS,
        ValidationStatus.PATCH_APPLICATION_FAILED,
    }


def _rescan_with_baseline_error(result: SecurityRescanResult) -> SecurityRescanResult:
    return SecurityRescanResult(
        status="ERROR",
        original_finding_remains=result.original_finding_remains,
        original_findings=result.original_findings,
        remaining_original_findings=result.remaining_original_findings,
        introduced_findings=result.introduced_findings,
        severity_changes=result.severity_changes,
        scanner_errors=result.scanner_errors,
        scan_results=result.scan_results,
        error="The original scan reported errors; before-and-after comparison is inconclusive.",
    )
