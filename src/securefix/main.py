"""Command-line entry point for scanning and repair validation."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from securefix.analysis import RepairAnalyzer
from securefix.config import (
    DEFAULT_CONTEXT_LINES,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    DEFAULT_REPORT_PATH,
    DEFAULT_REPAIR_REPORT_DIRECTORY,
    DEFAULT_RUN_SEMGREP_CONFIG,
    DEFAULT_SEMGREP_CONFIG,
    DEFAULT_TIMEOUT_SECONDS,
)
from securefix.context import collect_context, resolve_target_file
from securefix.context.code_context import SOURCE_EXTENSIONS
from securefix.detection import parse_findings
from securefix.llm import (
    GeminiProvider,
    LLMError,
    PromptStrategy,
)
from securefix.models import Finding
from securefix.patching import PatchManager
from securefix.sanitization import redact_nested
from securefix.scanner import SemgrepError, SemgrepScanner
from securefix.verification.evaluation import EvaluationError, evaluate_strategies
from securefix.verification.workflow import RepairWorkflow, RepairWorkflowError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securefix")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="scan a directory with Semgrep")
    scan_parser.add_argument("target", help="source-code directory to scan")
    scan_parser.add_argument("--output", default=DEFAULT_REPORT_PATH)
    scan_parser.add_argument(
        "--config",
        action="append",
        default=None,
        help="Semgrep configuration; repeat to combine configurations",
    )
    scan_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    scan_parser.add_argument(
        "--context-lines",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help="number of lines to collect before and after each finding",
    )
    repair_parser = commands.add_parser(
        "repair",
        help="generate a review-only repair proposal for a Semgrep finding",
    )
    repair_parser.add_argument("target", help="source-code directory that was scanned")
    repair_parser.add_argument(
        "--strategy",
        choices=[strategy.value for strategy in PromptStrategy],
        default=PromptStrategy.STRUCTURED.value,
    )
    repair_parser.add_argument(
        "--report",
        help="reuse a SecureFix JSON scan report instead of running Semgrep",
    )
    repair_parser.add_argument(
        "--finding-index",
        type=int,
        default=1,
        help="1-based finding number to repair (default: 1)",
    )
    repair_parser.add_argument(
        "--config",
        action="append",
        default=None,
        help="Semgrep configuration; repeat to combine configurations",
    )
    repair_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    repair_parser.add_argument(
        "--context-lines",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help="number of lines to collect before and after the finding",
    )
    repair_parser.add_argument("--model", default=None, help="Gemini model (or GEMINI_MODEL)")
    repair_parser.add_argument(
        "--llm-timeout",
        type=int,
        default=DEFAULT_LLM_TIMEOUT_SECONDS,
        help="Gemini request timeout in seconds",
    )
    repair_parser.add_argument(
        "--previous-repair",
        help="optional prior proposal text for context_feedback strategy",
    )
    repair_parser.add_argument(
        "--validation-failure",
        help="optional validation failure description for context_feedback strategy",
    )
    repair_parser.add_argument(
        "--output",
        help="proposal JSON path (default: a timestamped file in reports/)",
    )
    repair_parser.add_argument(
        "--diff-output",
        help="unified diff path (default: alongside the proposal JSON)",
    )
    run_parser = commands.add_parser(
        "run",
        help="generate and validate bounded repair candidates in isolation",
    )
    run_parser.add_argument("target", help="source-code directory to validate")
    run_parser.add_argument(
        "--strategy",
        choices=[strategy.value for strategy in PromptStrategy],
        default=PromptStrategy.STRUCTURED.value,
    )
    run_parser.add_argument("--finding-index", type=int, default=1)
    run_parser.add_argument("--max-attempts", type=int, default=3)
    run_parser.add_argument(
        "--config",
        action="append",
        default=None,
        help="Semgrep configuration; repeat to combine configurations",
    )
    run_parser.add_argument("--scanner-timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    run_parser.add_argument("--test-timeout", type=int, default=180)
    run_parser.add_argument("--context-lines", type=int, default=DEFAULT_CONTEXT_LINES)
    run_parser.add_argument("--model", default=None, help="Gemini model (or GEMINI_MODEL)")
    run_parser.add_argument(
        "--llm-timeout",
        type=int,
        default=DEFAULT_LLM_TIMEOUT_SECONDS,
    )
    run_parser.add_argument("--output-dir", default="reports/verification")

    evaluate_parser = commands.add_parser(
        "evaluate",
        help="compare selected repair strategies on an evaluation dataset",
    )
    evaluate_parser.add_argument("dataset", help="directory containing case.json manifests")
    evaluate_parser.add_argument(
        "--strategies",
        nargs="+",
        choices=[strategy.value for strategy in PromptStrategy],
        default=[strategy.value for strategy in PromptStrategy],
    )
    evaluate_parser.add_argument("--max-attempts", type=int, default=3)
    evaluate_parser.add_argument(
        "--config",
        action="append",
        default=None,
        help="Semgrep configuration; repeat to combine configurations",
    )
    evaluate_parser.add_argument("--scanner-timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    evaluate_parser.add_argument("--test-timeout", type=int, default=180)
    evaluate_parser.add_argument("--context-lines", type=int, default=DEFAULT_CONTEXT_LINES)
    evaluate_parser.add_argument("--model", default=None, help="Gemini model (or GEMINI_MODEL)")
    evaluate_parser.add_argument(
        "--llm-timeout",
        type=int,
        default=DEFAULT_LLM_TIMEOUT_SECONDS,
    )
    evaluate_parser.add_argument("--output-dir", help="new report directory outside the dataset")
    return parser


def _scanner_configs(configs: list[str] | None, default: str) -> list[str]:
    return configs if configs else [default]


def _serialize_report(
    target: Path,
    scan_results: dict[str, Any],
    context_lines: int,
) -> dict[str, Any]:
    findings = parse_findings(scan_results)
    serialized_findings: list[dict[str, Any]] = []
    for finding in findings:
        item = finding.to_dict()
        item["context"] = None
        if finding.file_path and finding.start_line is not None:
            try:
                context = collect_context(
                    target,
                    finding.file_path,
                    finding.start_line,
                    finding.end_line or finding.start_line,
                    context_lines,
                )
                item["context"] = context.to_dict()
            except (OSError, ValueError) as exc:
                item["context_error"] = str(exc)
        serialized_findings.append(item)

    errors = scan_results.get("errors", [])
    if not isinstance(errors, list):
        raise ValueError("Semgrep JSON field 'errors' must be a list")
    return {
        "scanner": "semgrep",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "findings": serialized_findings,
        "scanner_errors": redact_nested(errors),
    }


def _finding_from_report_record(record: Any) -> Finding:
    if not isinstance(record, Mapping):
        raise ValueError("Scan report finding must be a JSON object")

    text_fields = ("rule_id", "severity", "file_path", "message", "matched_code")
    for field in text_fields:
        value = record.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"Scan report finding field {field!r} must be a string")

    category = record.get("category")
    if category is not None and (
        not isinstance(category, (str, list))
        or (isinstance(category, list) and any(not isinstance(item, str) for item in category))
    ):
        raise ValueError("Scan report finding category must be a string or list of strings")

    line_numbers: dict[str, int | None] = {}
    for field in ("start_line", "end_line"):
        value = record.get(field)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 1
        ):
            raise ValueError(f"Scan report finding field {field!r} must be a positive integer")
        line_numbers[field] = value

    metadata = record.get("scanner_metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Scan report scanner_metadata must be an object")
    return Finding(
        rule_id=record.get("rule_id"),
        category=category,
        severity=record.get("severity"),
        file_path=record.get("file_path"),
        start_line=line_numbers["start_line"],
        end_line=line_numbers["end_line"],
        message=record.get("message"),
        matched_code=record.get("matched_code"),
        scanner_metadata=metadata,
    )


def _load_scan_report(report_path: str | Path, target: Path) -> list[Finding]:
    path = Path(report_path).resolve(strict=True)
    try:
        with path.open("r", encoding="utf-8") as report_file:
            report = json.load(report_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read scan report: {path}") from exc

    if not isinstance(report, dict) or report.get("scanner") != "semgrep":
        raise ValueError("Input report is not a SecureFix Semgrep report")
    report_target = report.get("target")
    if not isinstance(report_target, str) or Path(report_target).resolve() != target:
        raise ValueError("Scan report target does not match the requested target directory")
    records = report.get("findings")
    if not isinstance(records, list):
        raise ValueError("Scan report findings must be a list")
    return [_finding_from_report_record(record) for record in records]


def _run_repair(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"Error: target is not a directory: {target}", file=sys.stderr)
        return 2
    if args.timeout <= 0 or args.llm_timeout <= 0:
        print("Error: scanner and LLM timeouts must be greater than zero", file=sys.stderr)
        return 2
    if args.context_lines < 0:
        print("Error: --context-lines cannot be negative", file=sys.stderr)
        return 2
    if args.finding_index < 1:
        print("Error: --finding-index must be at least 1", file=sys.stderr)
        return 2
    if (
        (args.previous_repair or args.validation_failure)
        and args.strategy != PromptStrategy.CONTEXT_FEEDBACK.value
    ):
        print(
            "Error: prior repair and validation feedback require --strategy context_feedback",
            file=sys.stderr,
        )
        return 2

    try:
        if args.report:
            findings = _load_scan_report(args.report, target)
        else:
            scan_results = SemgrepScanner(
                config=_scanner_configs(args.config, DEFAULT_SEMGREP_CONFIG),
                timeout_seconds=args.timeout,
            ).scan(target)
            findings = parse_findings(scan_results)
    except (SemgrepError, ValueError, OSError) as exc:
        print(f"Unable to obtain scan findings: {exc}", file=sys.stderr)
        return 1

    if args.finding_index > len(findings):
        print(
            f"Error: finding index {args.finding_index} is unavailable "
            f"({len(findings)} finding(s) in scan)",
            file=sys.stderr,
        )
        return 2
    finding = findings[args.finding_index - 1]
    if not finding.file_path or finding.start_line is None:
        print("Error: selected finding has no source path or start line", file=sys.stderr)
        return 2

    try:
        target_root, source_path = resolve_target_file(target, finding.file_path)
        relative_path = source_path.relative_to(target_root).as_posix()
        context = collect_context(
            target,
            finding.file_path,
            finding.start_line,
            finding.end_line or finding.start_line,
            args.context_lines,
        ).to_dict()
    except (OSError, ValueError) as exc:
        print(f"Unable to collect safe source context: {exc}", file=sys.stderr)
        return 1

    try:
        provider = GeminiProvider(
            model=args.model,
            timeout_seconds=args.llm_timeout,
        )
        proposal = RepairAnalyzer(provider).generate(
            finding,
            context,
            strategy=args.strategy,
            target_relative_path=relative_path,
            previous_repair=args.previous_repair,
            validation_failure=args.validation_failure,
        )
        patch_manager = PatchManager()
        candidate = patch_manager.prepare(
            target,
            finding,
            proposal,
            context_start_line=context["start_line"],
            context_end_line=context["end_line"],
        )
    except (LLMError, ValueError, OSError) as exc:
        print(f"Unable to generate a valid repair proposal: {exc}", file=sys.stderr)
        return 1

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    default_proposal = Path(DEFAULT_REPAIR_REPORT_DIRECTORY) / f"repair-proposal-{timestamp}.json"
    proposal_path = Path(args.output) if args.output else default_proposal
    diff_path = (
        Path(args.diff_output)
        if args.diff_output
        else proposal_path.with_suffix(".diff")
    )
    try:
        saved_proposal, saved_diff = patch_manager.save(
            candidate,
            target,
            proposal_path,
            diff_path,
        )
    except (OSError, ValueError) as exc:
        print(f"Unable to save repair proposal: {exc}", file=sys.stderr)
        return 1

    print("Vulnerability analysis:")
    print(f"Type: {proposal.analysis.vulnerability_type}")
    print(proposal.analysis.explanation)
    print(f"Security impact: {proposal.analysis.security_impact}")
    print(f"Reasoning summary: {proposal.reasoning_summary}")
    if proposal.analysis.assumptions:
        print("Assumptions:")
        for assumption in proposal.analysis.assumptions:
            print(f"- {assumption}")
    if proposal.limitations:
        print("Limitations:")
        for limitation in proposal.limitations:
            print(f"- {limitation}")
    print(f"Repair: {proposal.repair.summary}")
    print("\nProposed unified diff (not applied):")
    print(candidate.unified_diff, end="")
    print(f"\nProposal JSON: {saved_proposal}")
    print(f"Unified diff: {saved_diff}")
    print("Original source files were not modified.")
    return 0


def _run_validation(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"Error: target is not a directory: {target}", file=sys.stderr)
        return 2
    if args.finding_index < 1 or args.max_attempts < 1:
        print("Error: finding index and maximum attempts must be positive", file=sys.stderr)
        return 2
    if min(args.scanner_timeout, args.test_timeout, args.llm_timeout) <= 0:
        print("Error: timeouts must be greater than zero", file=sys.stderr)
        return 2
    if args.context_lines < 0:
        print("Error: --context-lines cannot be negative", file=sys.stderr)
        return 2
    try:
        provider = GeminiProvider(
            model=args.model,
            timeout_seconds=args.llm_timeout,
        )
        result = RepairWorkflow(
            provider,
            output_directory=args.output_dir,
            scanner_config=_scanner_configs(
                args.config,
                DEFAULT_RUN_SEMGREP_CONFIG,
            ),
            scanner_timeout_seconds=args.scanner_timeout,
            test_timeout_seconds=args.test_timeout,
            context_lines=args.context_lines,
        ).run(
            target,
            strategy=args.strategy,
            finding_index=args.finding_index,
            maximum_attempts=args.max_attempts,
        )
    except (LLMError, RepairWorkflowError, OSError, ValueError) as exc:
        print(f"Repair validation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Validation status: {result.final_status}")
    print(f"Attempts: {len(result.attempts)}/{result.maximum_attempts}")
    print(f"Original project preserved: {result.integrity.get('preserved')}")
    print(f"Report directory: {result.report_directory}")
    generation_failures = [
        attempt.get("generation_error")
        for attempt in result.attempts
        if attempt.get("generation") == "failed"
    ]
    if generation_failures:
        print(f"Repair generation failed: {generation_failures[-1]}", file=sys.stderr)
        return 1
    if result.final_status != "VALIDATED":
        print("The candidate was not validated; review artifacts before any use.")
    return 0


def _run_evaluation(args: argparse.Namespace) -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_directory = args.output_dir or f"reports/evaluation-{timestamp}"

    def provider_factory() -> GeminiProvider:
        return GeminiProvider(
            model=args.model,
            timeout_seconds=args.llm_timeout,
        )

    try:
        report = evaluate_strategies(
            args.dataset,
            strategies=args.strategies,
            provider_factory=provider_factory,
            output_directory=output_directory,
            maximum_attempts=args.max_attempts,
            scanner_config=_scanner_configs(args.config, DEFAULT_SEMGREP_CONFIG),
            scanner_timeout_seconds=args.scanner_timeout,
            test_timeout_seconds=args.test_timeout,
            context_lines=args.context_lines,
        )
    except (EvaluationError, OSError, ValueError) as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Evaluation complete: {len(report['dataset_cases'])} case(s)")
    case_errors = 0
    for strategy in report["strategies"]:
        metrics = strategy["metrics"]
        inconclusive = sum(
            case["status"] == "INCONCLUSIVE" for case in strategy["cases"]
        )
        case_errors += sum(
            "error" in case
            or (
                bool(case.get("attempts"))
                and all(
                    attempt.get("generation") != "completed"
                    for attempt in case["attempts"]
                )
            )
            for case in strategy["cases"]
        )
        print(
            f"{strategy['strategy']}: validated rate="
            f"{metrics['validated_repair_rate']}, "
            f"inconclusive={inconclusive}, "
            f"mean attempts={metrics['average_repair_attempts']}"
        )
    print(f"Report: {Path(output_directory).resolve() / 'evaluation-report.json'}")
    print(f"Summary: {Path(output_directory).resolve() / 'evaluation-summary.txt'}")
    if case_errors:
        print(f"Evaluation has {case_errors} case-level error(s).", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "repair":
        return _run_repair(args)
    if args.command == "run":
        return _run_validation(args)
    if args.command == "evaluate":
        return _run_evaluation(args)
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"Error: target is not a directory: {target}", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("Error: --timeout must be greater than zero", file=sys.stderr)
        return 2
    if args.context_lines < 0:
        print("Error: --context-lines cannot be negative", file=sys.stderr)
        return 2

    report_path = Path(args.output).resolve()
    if report_path.suffix.lower() in SOURCE_EXTENSIONS:
        print(
            "Error: report output must not use a source-code file extension",
            file=sys.stderr,
        )
        return 2

    try:
        scanner = SemgrepScanner(
            config=_scanner_configs(args.config, DEFAULT_SEMGREP_CONFIG),
            timeout_seconds=args.timeout,
        )
        scan_results = scanner.scan(target)
    except SemgrepError as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 2

    try:
        report = _serialize_report(target, scan_results, args.context_lines)
    except ValueError as exc:
        print(f"Unable to process Semgrep results: {exc}", file=sys.stderr)
        return 1
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"Unable to write report {report_path}: {exc}", file=sys.stderr)
        return 1

    print(
        f"Scan complete: {len(report['findings'])} finding(s); "
        f"{len(report['scanner_errors'])} scanner error(s)."
    )
    print(f"Report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
