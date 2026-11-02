"""Convert Semgrep JSON results into normalized findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from securefix.models import Finding
from securefix.sanitization import (
    is_sensitive_path,
    redact_nested,
    redact_sensitive_text,
)


def _line_number(value: Any) -> int | None:
    if isinstance(value, Mapping) and isinstance(value.get("line"), int):
        return value["line"]
    return None


def parse_findings(scan_results: Mapping[str, Any]) -> list[Finding]:
    """Parse Semgrep's result list, preserving only fields it actually reports."""
    if "results" not in scan_results:
        raise ValueError("Semgrep JSON is missing the 'results' field")
    results = scan_results["results"]
    if not isinstance(results, list):
        raise ValueError("Semgrep JSON field 'results' must be a list")

    findings: list[Finding] = []
    for index, result in enumerate(results):
        if not isinstance(result, Mapping):
            raise ValueError(f"Semgrep result at index {index} must be an object")

        extra = result.get("extra")
        if not isinstance(extra, Mapping):
            extra = {}
        metadata = extra.get("metadata")
        if not isinstance(metadata, Mapping):
            metadata = {}

        raw_category = metadata.get("category")
        category = raw_category if isinstance(raw_category, (str, list)) else None
        severity = extra.get("severity")
        file_path = result.get("path")
        rule_id = result.get("check_id")
        message = extra.get("message")
        matched_code = extra.get("lines")

        scanner_metadata: dict[str, Any] = {}
        if metadata:
            scanner_metadata["metadata"] = redact_nested(dict(metadata))
        for key in ("fingerprint", "engine_kind", "validation_state"):
            if key in extra:
                scanner_metadata[key] = redact_nested(extra[key])

        findings.append(
            Finding(
                rule_id=rule_id if isinstance(rule_id, str) else None,
                category=category,
                severity=severity if isinstance(severity, str) else None,
                file_path=file_path if isinstance(file_path, str) else None,
                start_line=_line_number(result.get("start")),
                end_line=_line_number(result.get("end")),
                message=(
                    redact_sensitive_text(message)
                    if isinstance(message, str)
                    else None
                ),
                matched_code=(
                    redact_sensitive_text(matched_code)
                    if isinstance(matched_code, str)
                    and not (isinstance(file_path, str) and is_sensitive_path(file_path))
                    else None
                ),
                scanner_metadata=scanner_metadata,
            )
        )
    return findings
