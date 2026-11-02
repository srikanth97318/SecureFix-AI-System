"""Collect bounded, read-only source context for a finding."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from securefix.sanitization import is_sensitive_path, redact_sensitive_text


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
}


@dataclass(frozen=True)
class ContextLine:
    line_number: int
    content: str


@dataclass(frozen=True)
class CodeContext:
    start_line: int
    end_line: int
    lines: list[ContextLine]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _is_sensitive_or_non_source(path: Path) -> bool:
    return (
        path.suffix.lower() not in SOURCE_EXTENSIONS
        or is_sensitive_path(path)
    )


def resolve_target_file(
    target_directory: str | Path,
    file_path: str | Path,
) -> tuple[Path, Path]:
    """Resolve a file reported by a scanner and ensure it stays inside the target."""
    target_root = Path(target_directory).resolve(strict=True)
    if not target_root.is_dir():
        raise NotADirectoryError(f"Target is not a directory: {target_root}")

    supplied_path = Path(file_path)
    if supplied_path.is_absolute():
        candidates = [supplied_path]
    else:
        candidates = [target_root / supplied_path, Path.cwd() / supplied_path]

    resolved_file: Path | None = None
    missing_error: FileNotFoundError | None = None
    for candidate in candidates:
        try:
            resolved_file = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            missing_error = exc
            continue
        except RuntimeError as exc:
            raise ValueError("Finding file path contains a symlink loop") from exc

        try:
            resolved_file.relative_to(target_root)
        except ValueError as exc:
            raise ValueError("Finding file is outside the target directory") from exc
        break

    if resolved_file is None:
        if missing_error is not None:
            raise missing_error
        raise FileNotFoundError(f"Finding file does not exist: {file_path}")
    if not resolved_file.is_file():
        raise ValueError("Finding path is not a regular file")
    return target_root, resolved_file


def collect_context(
    target_directory: str | Path,
    file_path: str | Path,
    start_line: int,
    end_line: int,
    surrounding_lines: int = 5,
) -> CodeContext:
    """Read a source file's finding range and surrounding lines without modifying it."""
    if start_line < 1 or end_line < 1:
        raise ValueError("Finding line numbers must be positive")
    if surrounding_lines < 0:
        raise ValueError("surrounding_lines cannot be negative")

    target_root, resolved_file = resolve_target_file(target_directory, file_path)
    if _is_sensitive_or_non_source(resolved_file):
        raise ValueError("Refusing context for a sensitive or non-source file")

    try:
        content = resolved_file.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Source file is not valid UTF-8: {resolved_file}") from exc

    source_lines = content.splitlines()
    if start_line > len(source_lines):
        return CodeContext(start_line=start_line, end_line=0, lines=[])
    actual_start = max(1, start_line - surrounding_lines)
    actual_end = min(len(source_lines), max(end_line, start_line) + surrounding_lines)
    selected_lines = [
        ContextLine(
            line_number=line_number,
            content=redact_sensitive_text(source_lines[line_number - 1]),
        )
        for line_number in range(actual_start, actual_end + 1)
    ]
    return CodeContext(
        start_line=actual_start,
        end_line=actual_end if selected_lines else 0,
        lines=selected_lines,
    )
