"""Validate candidate edits and save them separately from scanned source."""

from __future__ import annotations

import difflib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from securefix.context.code_context import SOURCE_EXTENSIONS, resolve_target_file
from securefix.models import Finding, RepairProposal
from securefix.sanitization import is_sensitive_path


class PatchValidationError(ValueError):
    """Raised when a proposed change is unsafe or does not match the source."""


class PatchSaveError(OSError):
    """Raised when proposal files cannot be safely written."""


@dataclass(frozen=True)
class CandidatePatch:
    proposal: RepairProposal
    file_path: str
    original_source: str
    candidate_source: str
    unified_diff: str

    def proposal_json(self) -> str:
        return json.dumps(
            {
                **asdict(self.proposal),
                "candidate_file": self.file_path,
                "unified_diff": self.unified_diff,
            },
            indent=2,
            ensure_ascii=False,
        ) + "\n"


class PatchManager:
    """Prepare and persist reviewable proposals without modifying source files."""

    def prepare(
        self,
        target_directory: str | Path,
        finding: Finding,
        proposal: RepairProposal,
        *,
        context_start_line: int,
        context_end_line: int,
    ) -> CandidatePatch:
        target_root = Path(target_directory).resolve(strict=True)
        if not target_root.is_dir():
            raise PatchValidationError("Target is not a directory")
        if not finding.file_path:
            raise PatchValidationError("Finding does not identify a source file")

        try:
            _, source_path = resolve_target_file(target_root, finding.file_path)
        except (OSError, ValueError) as exc:
            raise PatchValidationError(f"Unable to resolve finding source file: {exc}") from exc
        relative_path = source_path.relative_to(target_root).as_posix()
        proposed_path = proposal.repair.file_path
        if (
            "\\" in proposed_path
            or PurePosixPath(proposed_path).is_absolute()
            or any(part in {"", ".", ".."} for part in proposed_path.split("/"))
        ):
            raise PatchValidationError("Proposal file_path must be a normalized target-relative path")
        if proposed_path != relative_path:
            raise PatchValidationError("Proposal must modify only the finding's source file")
        if source_path.suffix.lower() not in SOURCE_EXTENSIONS or is_sensitive_path(source_path):
            raise PatchValidationError("Refusing to patch a sensitive or unsupported source file")

        try:
            with source_path.open("r", encoding="utf-8", newline="") as source_file:
                original_source = source_file.read()
        except UnicodeDecodeError as exc:
            raise PatchValidationError("Source file is not valid UTF-8") from exc

        original_lines = original_source.splitlines()
        if not original_lines and original_source:
            original_lines = [original_source]
        changes = proposal.repair.changes
        sorted_changes = sorted(changes, key=lambda change: (change.start_line, change.end_line))
        previous_end = 0
        for change in sorted_changes:
            if change.start_line > change.end_line:
                raise PatchValidationError("Patch line range start_line must not exceed end_line")
            if change.end_line > len(original_lines):
                raise PatchValidationError("Patch line range exceeds the source file")
            if change.start_line < context_start_line or change.end_line > context_end_line:
                raise PatchValidationError("Patch line range is outside the supplied code context")
            if change.start_line <= previous_end:
                raise PatchValidationError("Patch changes must not overlap")
            actual_code = original_lines[change.start_line - 1 : change.end_line]
            if not change.original_code or change.original_code.splitlines() != actual_code:
                raise PatchValidationError(
                    f"original_code does not match source lines {change.start_line}-{change.end_line}"
                )
            if change.original_code == change.replacement_code:
                raise PatchValidationError("Patch change does not modify the source")
            previous_end = change.end_line

        candidate_lines = list(original_lines)
        for change in reversed(sorted_changes):
            candidate_lines[change.start_line - 1 : change.end_line] = (
                change.replacement_code.splitlines()
            )
        newline = "\r\n" if "\r\n" in original_source else "\n"
        trailing_newline = original_source.endswith(("\n", "\r"))
        candidate_source = newline.join(candidate_lines)
        if trailing_newline and candidate_lines:
            candidate_source += newline

        diff = "".join(
            difflib.unified_diff(
                original_source.splitlines(keepends=True),
                candidate_source.splitlines(keepends=True),
                fromfile=f"a/{relative_path}",
                tofile=f"b/{relative_path}",
            )
        )
        if not diff:
            raise PatchValidationError("Candidate patch is empty")
        return CandidatePatch(
            proposal=proposal,
            file_path=relative_path,
            original_source=original_source,
            candidate_source=candidate_source,
            unified_diff=diff,
        )

    def save(
        self,
        candidate: CandidatePatch,
        target_directory: str | Path,
        proposal_path: str | Path,
        diff_path: str | Path,
    ) -> tuple[Path, Path]:
        target_root = Path(target_directory).resolve(strict=True)
        proposal_destination = self._validate_output_path(
            target_root, proposal_path, expected_suffix=".json"
        )
        diff_destination = self._validate_output_path(
            target_root, diff_path, allowed_suffixes={".diff", ".patch"}
        )
        if proposal_destination == diff_destination:
            raise PatchSaveError("Proposal and diff output paths must be different")

        for destination in (proposal_destination, diff_destination):
            if destination.exists():
                raise PatchSaveError(f"Refusing to overwrite existing output: {destination}")

        created: list[Path] = []
        try:
            proposal_destination.parent.mkdir(parents=True, exist_ok=True)
            diff_destination.parent.mkdir(parents=True, exist_ok=True)
            self._write_exclusive(proposal_destination, candidate.proposal_json())
            created.append(proposal_destination)
            self._write_exclusive(diff_destination, candidate.unified_diff)
            created.append(diff_destination)
        except OSError as exc:
            for path in created:
                path.unlink(missing_ok=True)
            raise PatchSaveError("Unable to save repair proposal and diff") from exc
        return proposal_destination, diff_destination

    @staticmethod
    def _validate_output_path(
        target_root: Path,
        path: str | Path,
        *,
        expected_suffix: str | None = None,
        allowed_suffixes: set[str] | None = None,
    ) -> Path:
        destination = Path(path).resolve()
        try:
            destination.relative_to(target_root)
        except ValueError:
            pass
        else:
            raise PatchSaveError("Proposal outputs must be outside the scanned target directory")
        suffix = destination.suffix.lower()
        if expected_suffix is not None and suffix != expected_suffix:
            raise PatchSaveError(f"Proposal output must use the {expected_suffix} extension")
        if allowed_suffixes is not None and suffix not in allowed_suffixes:
            raise PatchSaveError(
                f"Diff output must use one of: {', '.join(sorted(allowed_suffixes))}"
            )
        return destination

    @staticmethod
    def _write_exclusive(path: Path, content: str) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output_file:
                output_file.write(content)
        except OSError:
            path.unlink(missing_ok=True)
            raise
