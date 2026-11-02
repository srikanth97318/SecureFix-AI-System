"""Validated, structured output from an AI repair proposal."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


class RepairResponseError(ValueError):
    """Raised when an LLM response does not match the repair schema."""


@dataclass(frozen=True)
class RepairAnalysis:
    vulnerability_type: str
    explanation: str
    security_impact: str
    assumptions: list[str]


@dataclass(frozen=True)
class RepairChange:
    start_line: int
    end_line: int
    original_code: str
    replacement_code: str


@dataclass(frozen=True)
class RepairDetails:
    summary: str
    file_path: str
    changes: list[RepairChange]


@dataclass(frozen=True)
class RepairProposal:
    vulnerability_id: str
    analysis: RepairAnalysis
    repair: RepairDetails
    reasoning_summary: str
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, response: str) -> RepairProposal:
        """Parse strict JSON without guessing or repairing malformed output."""
        if not isinstance(response, str) or len(response) > 1_000_000:
            raise RepairResponseError("LLM response must be text no larger than 1 MB")

        def object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise RepairResponseError(f"Duplicate JSON field: {key}")
                result[key] = value
            return result

        def reject_non_json_constant(value: str) -> None:
            raise RepairResponseError(f"Invalid JSON constant: {value}")

        try:
            document = json.loads(
                response,
                object_pairs_hook=object_without_duplicate_keys,
                parse_constant=reject_non_json_constant,
            )
        except RepairResponseError:
            raise
        except (json.JSONDecodeError, TypeError, RecursionError) as exc:
            raise RepairResponseError("LLM response is not valid JSON") from exc

        root = _object(document, "response")
        _require_keys(
            root,
            {"vulnerability_id", "analysis", "repair", "reasoning_summary", "limitations"},
            "response",
        )
        analysis_data = _object(root["analysis"], "analysis")
        _require_keys(
            analysis_data,
            {"vulnerability_type", "explanation", "security_impact", "assumptions"},
            "analysis",
        )
        repair_data = _object(root["repair"], "repair")
        _require_keys(repair_data, {"summary", "file_path", "changes"}, "repair")

        changes_data = repair_data["changes"]
        if not isinstance(changes_data, list) or not changes_data:
            raise RepairResponseError("repair.changes must be a non-empty list")
        changes: list[RepairChange] = []
        for index, value in enumerate(changes_data):
            change_data = _object(value, f"repair.changes[{index}]")
            _require_keys(
                change_data,
                {"start_line", "end_line", "original_code", "replacement_code"},
                f"repair.changes[{index}]",
            )
            changes.append(
                RepairChange(
                    start_line=_positive_integer(
                        change_data["start_line"],
                        f"repair.changes[{index}].start_line",
                    ),
                    end_line=_positive_integer(
                        change_data["end_line"],
                        f"repair.changes[{index}].end_line",
                    ),
                    original_code=_string(
                        change_data["original_code"],
                        f"repair.changes[{index}].original_code",
                        allow_empty=True,
                    ),
                    replacement_code=_string(
                        change_data["replacement_code"],
                        f"repair.changes[{index}].replacement_code",
                        allow_empty=True,
                    ),
                )
            )

        return cls(
            vulnerability_id=_string(root["vulnerability_id"], "vulnerability_id"),
            analysis=RepairAnalysis(
                vulnerability_type=_string(
                    analysis_data["vulnerability_type"],
                    "analysis.vulnerability_type",
                ),
                explanation=_string(analysis_data["explanation"], "analysis.explanation"),
                security_impact=_string(
                    analysis_data["security_impact"],
                    "analysis.security_impact",
                ),
                assumptions=_string_list(analysis_data["assumptions"], "analysis.assumptions"),
            ),
            repair=RepairDetails(
                summary=_string(repair_data["summary"], "repair.summary"),
                file_path=_string(repair_data["file_path"], "repair.file_path"),
                changes=changes,
            ),
            reasoning_summary=_string(root["reasoning_summary"], "reasoning_summary"),
            limitations=_string_list(root["limitations"], "limitations"),
        )


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RepairResponseError(f"{field} must be a JSON object")
    return value


def _require_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise RepairResponseError(f"{field} is missing required fields: {sorted(missing)}")
    if extra:
        raise RepairResponseError(f"{field} contains unexpected fields: {sorted(extra)}")


def _string(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise RepairResponseError(f"{field} must be a non-empty string")
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RepairResponseError(f"{field} must be a list of strings")
    return value


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RepairResponseError(f"{field} must be a positive integer")
    return value
