"""Compare initial and post-patch Semgrep findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from securefix.detection import parse_findings
from securefix.models import Finding
from securefix.scanner import SemgrepError, SemgrepScanner
from securefix.sanitization import redact_nested


@dataclass(frozen=True)
class SecurityRescanResult:
    status: str
    original_finding_remains: bool | None
    original_findings: list[dict[str, Any]]
    remaining_original_findings: list[dict[str, Any]]
    introduced_findings: list[dict[str, Any]]
    severity_changes: list[dict[str, Any]]
    scanner_errors: list[Any]
    scan_results: dict[str, Any] | None
    error: str | None

    def to_dict(self, *, include_scan_results: bool = True) -> dict[str, Any]:
        result = asdict(self)
        if not include_scan_results:
            result["scan_results"] = None
        return redact_nested(result)


class SecurityScanner:
    def __init__(
        self,
        *,
        config: str | Sequence[str] = "auto",
        timeout_seconds: int = 120,
        scanner: SemgrepScanner | None = None,
    ) -> None:
        self.scanner = scanner or SemgrepScanner(
            config=config,
            timeout_seconds=timeout_seconds,
        )

    def scan(self, target: str | Path) -> tuple[dict[str, Any], list[Finding]]:
        results = self.scanner.scan(target)
        return results, parse_findings(results)


def compare_findings(
    original_findings: list[Finding],
    current_findings: list[Finding],
    *,
    original_target: str | Path,
    current_target: str | Path,
    selected_finding: Finding,
) -> SecurityRescanResult:
    original_root = Path(original_target).resolve()
    current_root = Path(current_target).resolve()
    original_counter = Counter(_finding_key(item, original_root) for item in original_findings)
    current_counter = Counter(_finding_key(item, current_root) for item in current_findings)
    introduced_counts = current_counter - original_counter
    introduced: list[Finding] = []
    remaining_original: list[Finding] = []

    for key, count in introduced_counts.items():
        candidate = next((item for item in current_findings if _finding_key(item, current_root) == key), None)
        if candidate is not None:
            introduced.extend([candidate] * count)
    for key, count in (original_counter & current_counter).items():
        candidate = next((item for item in original_findings if _finding_key(item, original_root) == key), None)
        if candidate is not None:
            remaining_original.extend([candidate] * count)

    selected_key = _finding_key(selected_finding, original_root)
    selected_remaining = any(
        _finding_key(item, current_root) == selected_key for item in current_findings
    )
    severity_changes = _severity_changes(
        original_findings,
        current_findings,
        original_root,
        current_root,
    )
    return SecurityRescanResult(
        status="COMPLETED",
        original_finding_remains=selected_remaining,
        original_findings=[_finding_data(item, original_root) for item in original_findings],
        remaining_original_findings=[
            _finding_data(item, original_root) for item in remaining_original
        ],
        introduced_findings=[_finding_data(item, current_root) for item in introduced],
        severity_changes=severity_changes,
        scanner_errors=[],
        scan_results=None,
        error=None,
    )


def run_security_rescan(
    scanner: SecurityScanner,
    target: str | Path,
    *,
    original_target: str | Path,
    original_findings: list[Finding],
    selected_finding: Finding,
) -> SecurityRescanResult:
    try:
        scan_results, current_findings = scanner.scan(target)
    except SemgrepError as exc:
        return _rescan_error(f"Semgrep rescan failed: {exc}")
    except (OSError, ValueError) as exc:
        return _rescan_error(f"Unable to parse Semgrep rescan: {exc}")

    scanner_errors = scan_results.get("errors", [])
    if not isinstance(scanner_errors, list):
        return _rescan_error("Semgrep rescan returned malformed errors data")
    comparison = compare_findings(
        original_findings,
        current_findings,
        original_target=original_target,
        current_target=target,
        selected_finding=selected_finding,
    )
    return SecurityRescanResult(
        **{
            **asdict(comparison),
            "scanner_errors": redact_nested(scanner_errors),
            "scan_results": redact_nested(scan_results),
        }
    )


def _rescan_error(error: str) -> SecurityRescanResult:
    return SecurityRescanResult(
        status="ERROR",
        original_finding_remains=None,
        original_findings=[],
        remaining_original_findings=[],
        introduced_findings=[],
        severity_changes=[],
        scanner_errors=[],
        scan_results=None,
        error=error,
    )


def _finding_key(finding: Finding, root: Path) -> tuple[str | None, str | None]:
    path = finding.file_path
    if path:
        candidate = Path(path)
        if not candidate.is_absolute():
            resolved = (root / candidate).resolve(strict=False)
        else:
            resolved = candidate.resolve(strict=False)
        try:
            normalized = resolved.relative_to(root).as_posix()
        except ValueError:
            normalized = candidate.as_posix()
    else:
        normalized = None
    return finding.rule_id, normalized


def _finding_data(finding: Finding, root: Path) -> dict[str, Any]:
    result = finding.to_dict()
    result["file_path"] = _finding_key(finding, root)[1]
    return redact_nested(result)


def _severity_changes(
    original: list[Finding],
    current: list[Finding],
    original_root: Path,
    current_root: Path,
) -> list[dict[str, Any]]:
    original_severity: dict[tuple[str | None, str | None], list[str | None]] = {}
    current_severity: dict[tuple[str | None, str | None], list[str | None]] = {}
    for finding in original:
        original_severity.setdefault(_finding_key(finding, original_root), []).append(
            finding.severity
        )
    for finding in current:
        current_severity.setdefault(_finding_key(finding, current_root), []).append(
            finding.severity
        )

    changes: list[dict[str, Any]] = []
    for key in original_severity.keys() & current_severity.keys():
        before = sorted(original_severity[key], key=lambda value: value or "")
        after = sorted(current_severity[key], key=lambda value: value or "")
        if before != after:
            changes.append(
                {
                    "rule_id": key[0],
                    "file_path": key[1],
                    "original_severities": before,
                    "current_severities": after,
                }
            )
    return sorted(changes, key=lambda item: (item["rule_id"] or "", item["file_path"] or ""))
