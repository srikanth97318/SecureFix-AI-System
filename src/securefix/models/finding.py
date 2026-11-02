"""Normalized vulnerability finding model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    rule_id: str | None = None
    category: str | list[str] | None = None
    severity: str | None = None
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    message: str | None = None
    matched_code: str | None = None
    scanner_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of this finding."""
        return asdict(self)
