"""Create a disposable source copy and apply one validated candidate to it."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from securefix.context.code_context import SOURCE_EXTENSIONS
from securefix.models import Finding
from securefix.patching import CandidatePatch, PatchManager, PatchValidationError
from securefix.sanitization import is_sensitive_path


class WorkspaceError(RuntimeError):
    """Raised when a safe isolated working copy cannot be created or patched."""


@dataclass(frozen=True)
class AppliedChange:
    file_path: str
    original_sha256: str
    candidate_sha256: str
    unified_diff: str
    applied: bool


class IsolatedWorkspace:
    """Owns a temporary copy; closing it discards all applied changes."""

    def __init__(self, source_directory: str | Path) -> None:
        source_root = Path(source_directory).resolve(strict=True)
        if not source_root.is_dir():
            raise WorkspaceError("Project source must be a directory")
        self.source_root = source_root
        self._temporary_directory = Path(tempfile.mkdtemp(prefix="securefix-verify-"))
        self.working_copy = self._temporary_directory / "project"
        self.changes: list[AppliedChange] = []
        try:
            self._validate_source_symlinks()
            shutil.copytree(
                source_root,
                self.working_copy,
                symlinks=True,
                ignore=self._ignore_sensitive_or_generated,
            )
        except Exception:
            self.close()
            raise

    def __enter__(self) -> IsolatedWorkspace:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        shutil.rmtree(self._temporary_directory, ignore_errors=True)

    def apply(self, candidate: CandidatePatch) -> AppliedChange:
        relative = PurePosixPath(candidate.file_path)
        if (
            relative.is_absolute()
            or "\\" in candidate.file_path
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise WorkspaceError("Candidate path must be a normalized relative file path")
        if relative.suffix.lower() not in SOURCE_EXTENSIONS or is_sensitive_path(relative):
            raise WorkspaceError("Candidate targets a sensitive or unsupported source file")

        destination = self.working_copy.joinpath(*relative.parts)
        try:
            resolved = destination.resolve(strict=True)
            resolved.relative_to(self.working_copy.resolve())
        except (OSError, ValueError, RuntimeError) as exc:
            raise WorkspaceError("Candidate path escapes or is missing from the working copy") from exc
        if not resolved.is_file():
            raise WorkspaceError("Candidate path is not a regular file")

        try:
            with resolved.open("r", encoding="utf-8", newline="") as source_file:
                current_source = source_file.read()
        except UnicodeDecodeError as exc:
            raise WorkspaceError("Working-copy source is not valid UTF-8") from exc

        if current_source != candidate.original_source:
            raise WorkspaceError("Working-copy source does not match the candidate's original source")

        change_lines = candidate.proposal.repair.changes
        context_start = min(change.start_line for change in change_lines)
        context_end = max(change.end_line for change in change_lines)
        finding = Finding(file_path=candidate.file_path)
        try:
            recalculated = PatchManager().prepare(
                self.working_copy,
                finding,
                candidate.proposal,
                context_start_line=context_start,
                context_end_line=context_end,
            )
        except (OSError, PatchValidationError, ValueError) as exc:
            raise WorkspaceError(f"Candidate patch failed revalidation: {exc}") from exc
        if (
            recalculated.original_source != candidate.original_source
            or recalculated.candidate_source != candidate.candidate_source
            or recalculated.unified_diff != candidate.unified_diff
        ):
            raise WorkspaceError("Candidate patch content does not match its validated proposal")

        before_hash = hashlib.sha256(current_source.encode("utf-8")).hexdigest()
        try:
            resolved.chmod(resolved.stat().st_mode | 0o200)
            with resolved.open("w", encoding="utf-8", newline="") as source_file:
                source_file.write(candidate.candidate_source)
        except OSError as exc:
            raise WorkspaceError("Unable to apply candidate to the isolated copy") from exc
        after_hash = hashlib.sha256(candidate.candidate_source.encode("utf-8")).hexdigest()
        record = AppliedChange(
            file_path=relative.as_posix(),
            original_sha256=before_hash,
            candidate_sha256=after_hash,
            unified_diff=candidate.unified_diff,
            applied=True,
        )
        self.changes.append(record)
        return record

    def audit_record(self) -> dict[str, object]:
        return {
            "source_directory": str(self.source_root),
            "working_copy": str(self.working_copy),
            "changes": [asdict(change) for change in self.changes],
        }

    def _validate_source_symlinks(self) -> None:
        for path in self.source_root.rglob("*"):
            if not path.is_symlink():
                continue
            try:
                target = path.resolve(strict=True)
                target.relative_to(self.source_root)
            except (OSError, ValueError, RuntimeError) as exc:
                raise WorkspaceError(
                    f"Refusing source symlink outside the project or with a missing target: "
                    f"{path.relative_to(self.source_root)}"
                ) from exc
            if Path(os.readlink(path)).is_absolute():
                raise WorkspaceError("Absolute source symlinks are not copied")

    @staticmethod
    def _ignore_sensitive_or_generated(
        directory: str,
        names: list[str],
    ) -> set[str]:
        ignored: set[str] = set()
        current_directory = Path(directory)
        for name in names:
            path = current_directory / name
            if (
                name in {".git", "__pycache__", ".pytest_cache", ".venv", "venv"}
                or name.endswith((".pyc", ".pyo"))
                or name == ".env"
                or name.startswith(".env.")
                or is_sensitive_path(path)
            ):
                ignored.add(name)
        return ignored


def save_audit_record(workspace: IsolatedWorkspace, output_path: str | Path) -> Path:
    """Write the workspace audit outside the disposable tree."""
    destination = Path(output_path).resolve()
    if destination.is_relative_to(workspace.working_copy.resolve()):
        raise WorkspaceError("Workspace audit must be saved outside the working copy")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as audit_file:
        json.dump(workspace.audit_record(), audit_file, indent=2)
        audit_file.write("\n")
    return destination
