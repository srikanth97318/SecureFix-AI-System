"""Reproducible, machine-readable comparison of repair prompting strategies."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from securefix.llm.gemini_provider import LLMError
from securefix.llm.prompts import PromptStrategy
from securefix.sanitization import redact_nested
from securefix.verification.workflow import RepairWorkflow, RepairWorkflowError

_MAXIMUM_REPAIR_ATTEMPTS = RepairWorkflow.ABSOLUTE_MAXIMUM_ATTEMPTS


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    category: str
    target_directory: Path
    expected_secure_behavior: str
    semgrep_support: str


class EvaluationError(RuntimeError):
    """Raised when an evaluation dataset or output destination is invalid."""


def load_evaluation_cases(dataset_directory: str | Path) -> list[EvaluationCase]:
    dataset_root = Path(dataset_directory).resolve(strict=True)
    if not dataset_root.is_dir():
        raise EvaluationError("Evaluation dataset must be a directory")
    cases: list[EvaluationCase] = []
    for discovered_manifest in sorted(dataset_root.rglob("case.json")):
        try:
            manifest_path = discovered_manifest.resolve(strict=True)
            manifest_path.relative_to(dataset_root)
        except (OSError, ValueError, RuntimeError) as exc:
            raise EvaluationError(
                "Evaluation manifest escapes the dataset directory"
            ) from exc
        if any(part in {".git", ".venv", "venv"} for part in manifest_path.parts):
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvaluationError(f"Unable to read case manifest: {manifest_path}") from exc
        if not isinstance(manifest, dict):
            raise EvaluationError(f"Case manifest must contain an object: {manifest_path}")
        case_id = manifest.get("case_id")
        category = manifest.get("category")
        behavior = manifest.get("expected_secure_behavior")
        support = manifest.get("semgrep_support", "not_assessed")
        if any(not isinstance(value, str) or not value.strip() for value in (case_id, category, behavior)):
            raise EvaluationError(
                f"Case manifest requires non-empty case_id, category, and "
                f"expected_secure_behavior: {manifest_path}"
            )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", case_id):
            raise EvaluationError(
                f"Case ID must be a safe filename component: {manifest_path}"
            )
        case_root = manifest_path.parent
        try:
            case_root.relative_to(dataset_root)
        except ValueError as exc:
            raise EvaluationError("Evaluation case escapes the dataset directory") from exc
        if support not in {"not_assessed", "observed", "not_observed"}:
            raise EvaluationError(
                "semgrep_support must be not_assessed, observed, or not_observed"
            )
        cases.append(
            EvaluationCase(
                case_id=case_id,
                category=category,
                target_directory=case_root,
                expected_secure_behavior=behavior,
                semgrep_support=support,
            )
        )
    if not cases:
        raise EvaluationError(f"No case.json manifests found in {dataset_root}")
    identifiers = [case.case_id for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise EvaluationError("Evaluation case_id values must be unique")
    return cases


def evaluate_strategies(
    dataset_directory: str | Path,
    *,
    strategies: list[PromptStrategy | str],
    provider_factory: Callable[[], Any],
    output_directory: str | Path,
    maximum_attempts: int = 3,
    scanner_config: str | Sequence[str] = "auto",
    scanner_timeout_seconds: int = 120,
    test_timeout_seconds: int = 180,
    context_lines: int = 5,
) -> dict[str, Any]:
    if not 1 <= maximum_attempts <= _MAXIMUM_REPAIR_ATTEMPTS:
        raise EvaluationError(
            "maximum_attempts must be between 1 and "
            f"{_MAXIMUM_REPAIR_ATTEMPTS}"
        )
    if scanner_timeout_seconds <= 0 or test_timeout_seconds <= 0:
        raise EvaluationError("Scanner and test timeouts must be positive")
    if not 0 <= context_lines <= 100:
        raise EvaluationError("context_lines must be between 0 and 100")
    cases = load_evaluation_cases(dataset_directory)
    parsed_strategies: list[PromptStrategy] = []
    for strategy in strategies:
        try:
            parsed = PromptStrategy(strategy)
        except ValueError as exc:
            raise EvaluationError(f"Unknown strategy: {strategy}") from exc
        if parsed not in parsed_strategies:
            parsed_strategies.append(parsed)
    if not parsed_strategies:
        raise EvaluationError("At least one strategy must be selected")

    dataset_root = Path(dataset_directory).resolve(strict=True)
    output_root = Path(output_directory).resolve()
    if output_root == dataset_root or output_root.is_relative_to(dataset_root):
        raise EvaluationError("Evaluation output must be outside the dataset directory")
    output_root.mkdir(parents=True, exist_ok=False)

    started = time.monotonic()
    strategy_reports: list[dict[str, Any]] = []
    for strategy in parsed_strategies:
        case_reports: list[dict[str, Any]] = []
        for case in cases:
            case_output = output_root / case.case_id / strategy.value
            case_output.parent.mkdir(parents=True, exist_ok=True)
            case_started = time.monotonic()
            try:
                provider = provider_factory()
                workflow = RepairWorkflow(
                    provider,
                    output_directory=case_output / "runs",
                    scanner_config=scanner_config,
                    scanner_timeout_seconds=scanner_timeout_seconds,
                    test_timeout_seconds=test_timeout_seconds,
                    context_lines=context_lines,
                )
                result = workflow.run(
                    case.target_directory,
                    strategy=strategy,
                    maximum_attempts=maximum_attempts,
                )
                workflow_data = result.to_dict()
                case_reports.append(
                    _case_report(
                        case,
                        workflow_data,
                        case_output,
                        time.monotonic() - case_started,
                    )
                )
            except (LLMError, RepairWorkflowError, OSError, ValueError) as exc:
                case_reports.append(
                    {
                        "case_id": case.case_id,
                        "category": case.category,
                        "status": "INCONCLUSIVE",
                        "semgrep_support": _support_status(case, None),
                        "error": redact_nested(str(exc)),
                        "processing_time_seconds": round(
                            time.monotonic() - case_started, 6
                        ),
                        "attempts": [],
                        "token_usage": {
                            "input_tokens": None,
                            "output_tokens": None,
                            "total_tokens": None,
                        },
                    }
                )
        strategy_reports.append(
            {
                "strategy": strategy.value,
                "cases": case_reports,
                "metrics": _aggregate_metrics(case_reports, len(cases)),
            }
        )

    report: dict[str, Any] = {
        "schema_version": 1,
        "evaluation_id": output_root.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_directory": str(dataset_root),
        "dataset_cases": [
            {
                "case_id": case.case_id,
                "category": case.category,
                "expected_secure_behavior": case.expected_secure_behavior,
                "semgrep_support": case.semgrep_support,
            }
            for case in cases
        ],
        "reproducibility": {
            "python_version": sys.version.split()[0],
            "model_by_case": "Recorded per repair workflow from provider configuration.",
            "semgrep_configuration": scanner_config,
            "maximum_attempts": maximum_attempts,
            "test_timeout_seconds": test_timeout_seconds,
            "network_for_tests": "Disabled by Bubblewrap namespace isolation.",
            "semgrep_support_note": (
                "Categories without a matching observed finding are marked not_observed; "
                "this does not prove that the configured Semgrep rules lack support."
            ),
            "project_revision": _git_revision(dataset_root),
        },
        "processing_time_seconds": round(time.monotonic() - started, 6),
        "strategies": strategy_reports,
        "limitations": [
            "No live Gemini usage metadata is synthesized; missing input/output/total token "
            "counts remain null.",
            "A Semgrep finding disappearing is not proof of vulnerability removal.",
            "Test success and static-analysis results do not prove a repair is secure.",
            "Dataset expected behavior is a benchmark oracle, not a complete security proof.",
        ],
    }
    _write_json_exclusive(output_root / "evaluation-report.json", report)
    (output_root / "evaluation-summary.txt").write_text(
        _format_summary(report),
        encoding="utf-8",
    )
    return redact_nested(report)


def _case_report(
    case: EvaluationCase,
    workflow: dict[str, Any],
    output_directory: Path,
    duration: float,
) -> dict[str, Any]:
    attempts = workflow.get("attempts", [])
    findings = workflow.get("original_findings", [])
    matching = [
        finding
        for finding in findings
        if finding.get("rule_id") in _expected_rule_ids(case)
    ]
    return {
        "case_id": case.case_id,
        "category": case.category,
        "status": workflow.get("final_status", "INCONCLUSIVE"),
        "semgrep_support": _support_status(case, bool(matching)),
        "expected_secure_behavior": case.expected_secure_behavior,
        "model": workflow.get("model"),
        "report_directory": workflow.get("report_directory"),
        "candidate_patches_generated": sum(
            attempt.get("generation") == "completed" for attempt in attempts
        ),
        "successful_patch_applications": sum(
            bool((attempt.get("patch_application") or {}).get("applied"))
            for attempt in attempts
        ),
        "tests": [
            attempt.get("tests") for attempt in attempts if attempt.get("tests") is not None
        ],
        "security_rescans": [
            attempt.get("security_rescan")
            for attempt in attempts
            if attempt.get("security_rescan") is not None
        ],
        "attempts": attempts,
        "expected_rule_matches": matching,
        "token_usage": workflow.get(
            "token_usage",
            {"input_tokens": None, "output_tokens": None, "total_tokens": None},
        ),
        "processing_time_seconds": round(duration, 6),
        "patch_correctness": (
            "validation passed" if workflow.get("final_status") == "VALIDATED"
            else "not established"
        ),
    }


def _expected_rule_ids(case: EvaluationCase) -> set[str]:
    manifest_path = case.target_directory / "case.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return set()
    value = manifest.get("expected_rule_ids", [])
    return set(item for item in value if isinstance(item, str)) if isinstance(value, list) else set()


def _support_status(case: EvaluationCase, detected: bool | None) -> str:
    if case.semgrep_support in {"observed", "not_observed"}:
        return case.semgrep_support
    if detected is None:
        return "not_assessed"
    return "observed" if detected else "not_observed"


def _aggregate_metrics(cases: list[dict[str, Any]], total_cases: int) -> dict[str, Any]:
    attempts = [attempt for case in cases for attempt in case.get("attempts", [])]
    rescans = [
        rescan
        for case in cases
        for rescan in case.get("security_rescans", [])
        if rescan.get("status") == "COMPLETED" and not rescan.get("scanner_errors")
    ]
    test_results = [test for case in cases for test in case.get("tests", [])]
    usage_values = [case.get("token_usage", {}) for case in cases]
    completed_tests = [
        result
        for result in test_results
        if result.get("status") in {"PASSED", "FAILED"}
    ]

    def sum_if_known(name: str) -> int | None:
        values = [usage.get(name) for usage in usage_values]
        if not values or any(not isinstance(value, int) for value in values):
            return None
        return sum(values)

    generated = sum(
        attempt.get("generation") == "completed" for attempt in attempts
    )
    applied = sum(
        bool((attempt.get("patch_application") or {}).get("applied"))
        for attempt in attempts
    )
    test_passed = sum(test.get("status") == "PASSED" for test in completed_tests)
    removed = sum(
        rescan.get("original_finding_remains") is False for rescan in rescans
    )
    introduced = sum(
        len(rescan.get("introduced_findings") or []) for rescan in rescans
    )
    validated = sum(case.get("status") == "VALIDATED" for case in cases)
    token_counts = {
        "input_tokens": sum_if_known("input_tokens"),
        "output_tokens": sum_if_known("output_tokens"),
        "total_tokens": sum_if_known("total_tokens"),
    }
    return {
        "total_vulnerability_cases": total_cases,
        "candidate_patches_generated": generated,
        "successful_patch_applications": applied,
        "patch_application_integrity_rate": (
            round(applied / generated, 6) if generated else None
        ),
        "test_pass_rate": (
            round(test_passed / len(completed_tests), 6) if completed_tests else None
        ),
        "original_vulnerability_removal_rate": (
            round(removed / len(rescans), 6) if rescans else None
        ),
        "newly_introduced_finding_count": introduced,
        "validated_repair_rate": (
            round(validated / total_cases, 6) if total_cases else None
        ),
        "average_repair_attempts": (
            round(sum(len(case.get("attempts", [])) for case in cases) / len(cases), 6)
            if cases
            else None
        ),
        **token_counts,
        "processing_time_seconds": round(
            sum(case.get("processing_time_seconds", 0) for case in cases), 6
        ),
        "processing_time_per_case_seconds": (
            round(
                sum(case.get("processing_time_seconds", 0) for case in cases) / len(cases),
                6,
            )
            if cases
            else None
        ),
        "metrics_notes": {
            "patch_application_integrity_rate": (
                "Candidate application success divided by generated candidates; "
                "not a semantic correctness measure."
            ),
            "test_pass_rate": "Passed test runs divided by completed passed/failed pytest runs.",
            "original_vulnerability_removal_rate": (
                "Selected findings not rediscovered divided by completed clean rescans; "
                "not proof of remediation."
            ),
            "token_counts": (
                "Aggregated only when provider usage metadata is available for every case; "
                "otherwise null."
            ),
        },
    }


def _git_revision(directory: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _write_json_exclusive(path: Path, report: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as output_file:
        json.dump(redact_nested(report), output_file, indent=2, ensure_ascii=False)
        output_file.write("\n")


def _format_summary(report: dict[str, Any]) -> str:
    lines = [
        "SecureFix strategy evaluation",
        f"Evaluation: {report['evaluation_id']}",
        f"Cases: {len(report['dataset_cases'])}",
        f"Processing time (seconds): {report['processing_time_seconds']}",
        "",
    ]
    for entry in report["strategies"]:
        metrics = entry["metrics"]
        lines.extend(
            [
                f"Strategy: {entry['strategy']}",
                f"  Validated repair rate: {metrics['validated_repair_rate']}",
                f"  Test pass rate: {metrics['test_pass_rate']}",
                f"  Original finding removal rate: "
                f"{metrics['original_vulnerability_removal_rate']}",
                f"  New findings: {metrics['newly_introduced_finding_count']}",
                f"  Average attempts: {metrics['average_repair_attempts']}",
                f"  Tokens (input/output/total): {metrics['input_tokens']}/"
                f"{metrics['output_tokens']}/{metrics['total_tokens']}",
                "",
            ]
        )
    lines.append("A passing evaluation is not proof of complete security.")
    return "\n".join(lines) + "\n"
