"""Redact common credential formats from report text."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


SENSITIVE_NAMES = {
    ".aws",
    ".git",
    ".gnupg",
    ".kube",
    ".ssh",
    "credentials",
    "id_rsa",
    "id_ed25519",
    "private",
    "secrets",
}
SENSITIVE_EXTENSIONS = {".env", ".key", ".pem", ".p12", ".pfx"}

_REDACTION_PATTERNS = (
    re.compile(
        r"""(?i)(\b(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|password|passwd|token|client[_-]?secret|authorization)\b\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)"""
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)


def is_sensitive_path(path: str | Path) -> bool:
    """Identify common secret and private-key file names before exposing match text."""
    candidate = Path(path)
    lowered_parts = {part.lower() for part in candidate.parts}
    lowered_name = candidate.name.lower()
    return (
        lowered_name in SENSITIVE_EXTENSIONS
        or candidate.suffix.lower() in SENSITIVE_EXTENSIONS
        or bool(lowered_parts & SENSITIVE_NAMES)
        or candidate.stem.lower() in SENSITIVE_NAMES
        or any(word in lowered_name for word in ("secret", "credential", "password"))
    )


def redact_sensitive_text(value: str) -> str:
    """Mask common secret values while preserving surrounding source text."""
    redacted = value
    for pattern in _REDACTION_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_nested(value: Any) -> Any:
    """Redact strings in scanner metadata without changing its structure."""
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [redact_nested(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_nested(item) for key, item in value.items()}
    return value
