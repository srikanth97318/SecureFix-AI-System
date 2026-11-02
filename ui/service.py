"""Secure upload handling and controlled integration with the SecureFix CLI."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from securefix.context.code_context import SOURCE_EXTENSIONS
from securefix.llm.prompts import PromptStrategy
from securefix.sanitization import redact_sensitive_text
from securefix.verification.validation import ValidationStatus
from securefix.verification.workflow import RepairWorkflow


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
REPORTS_ROOT = WORKSPACE_ROOT / "reports"
UI_REPORTS_ROOT = REPORTS_ROOT / "streamlit"
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_EXPANDED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 2_000
MAX_ARCHIVE_ENTRIES = MAX_ARCHIVE_FILES * 2
MAX_COMPRESSION_RATIO = 100
MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_REPAIR_ATTEMPTS = RepairWorkflow.ABSOLUTE_MAXIMUM_ATTEMPTS

SUPPORTED_SEMGREP_CONFIGS = (
    "p/security-audit",
    "p/python",
    "p/owasp-top-ten",
    "datasets/phase3/sql_injection/securefix_sql_injection.yml",
)
SUPPORTED_PROMPT_STRATEGIES = tuple(strategy.value for strategy in PromptStrategy)

_PROJECT_METADATA_EXTENSIONS = {
    ".cfg",
    ".css",
    ".csv",
    ".conf",
    ".gradle",
    ".html",
    ".in",
    ".ini",
    ".kts",
    ".json",
    ".lock",
    ".mk",
    ".md",
    ".mod",
    ".properties",
    ".rst",
    ".sql",
    ".sum",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_PROJECT_METADATA_NAMES = {
    ".dockerignore",
    ".gitignore",
    "dockerfile",
    "editorconfig",
    "gemfile",
    "gnumakefile",
    "license",
    "makefile",
    "procfile",
    "pipfile",
    "readme",
    "rakefile",
    "justfile",
}


class ArchiveValidationError(ValueError):
    """Raised when an uploaded project archive is unsafe or unsupported."""


@dataclass(frozen=True)
class ArchiveSummary:
    files: tuple[str, ...]
    expanded_bytes: int


@dataclass(frozen=True)
class ReportRecord:
    path: Path
    data: dict[str, Any]
    kind: str
    title: str
    status: str | None
    generated_at: str


@dataclass(frozen=True)
class DashboardMetrics:
    scan_runs: int
    workflow_runs: int
    findings_reported: int
    repairs_validated: int
    repairs_blocked_or_failed: int
    incomplete_reports: int
    unknown_workflows: int


@dataclass(frozen=True)
class ExecutionResult:
    action: Literal["scan", "run"]
    status: str
    report_path: Path | None
    report: dict[str, Any] | None
    report_directory: Path | None
    error: str | None
    stdout: str
    stderr: str
    project_preserved: bool | None


@dataclass(frozen=True)
class PatchArtifact:
    attempt: int
    filename: str
    contents: bytes


def inspect_zip_archive(contents: bytes) -> ArchiveSummary:
    """Validate ZIP structure and resource bounds without extracting its contents."""
    if not contents:
        raise ArchiveValidationError("The uploaded ZIP file is empty.")
    if len(contents) > MAX_ARCHIVE_BYTES:
        raise ArchiveValidationError("The ZIP file exceeds the 50 MiB upload limit.")

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as archive:
            entries = archive.infolist()
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ArchiveValidationError("The upload is not a readable ZIP archive.") from exc

    if not entries:
        raise ArchiveValidationError("The ZIP archive contains no project files.")
    if len(entries) > MAX_ARCHIVE_ENTRIES:
        raise ArchiveValidationError("The ZIP archive contains too many entries.")

    paths: list[str] = []
    seen: dict[str, bool] = {}
    expanded_bytes = 0
    file_count = 0

    for entry in entries:
        name = getattr(entry, "orig_filename", entry.filename)
        is_directory = entry.is_dir()
        if (
            not name
            or "\x00" in name
            or "\\" in name
            or name.startswith("/")
            or (len(name) >= 2 and name[1] == ":")
        ):
            raise ArchiveValidationError("The ZIP archive contains an unsafe path.")

        normalized_name = name[:-1] if is_directory and name.endswith("/") else name
        components = normalized_name.split("/")
        if (
            not normalized_name
            or any(component in {"", ".", ".."} for component in components)
        ):
            raise ArchiveValidationError("The ZIP archive contains an unsafe path.")

        path = PurePosixPath(normalized_name)
        if path.is_absolute():
            raise ArchiveValidationError("The ZIP archive contains an absolute path.")
        normalized = path.as_posix()
        if normalized in seen:
            raise ArchiveValidationError("The ZIP archive contains duplicate paths.")
        seen[normalized] = is_directory

        mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if stat.S_ISLNK(mode) or file_type not in {
            0,
            stat.S_IFREG if not is_directory else stat.S_IFDIR,
        }:
            raise ArchiveValidationError("The ZIP archive contains a link or special file.")
        if entry.flag_bits & 0x1:
            raise ArchiveValidationError("Encrypted ZIP entries are not supported.")

        if is_directory:
            if entry.file_size != 0:
                raise ArchiveValidationError("Directory entries must not contain data.")
            continue

        file_count += 1
        if file_count > MAX_ARCHIVE_FILES:
            raise ArchiveValidationError("The ZIP archive contains too many files.")
        if entry.file_size > MAX_FILE_BYTES:
            raise ArchiveValidationError(
                f"File {normalized!r} exceeds the 20 MiB per-file limit."
            )
        expanded_bytes += entry.file_size
        if expanded_bytes > MAX_EXPANDED_BYTES:
            raise ArchiveValidationError(
                "The ZIP archive expands beyond the 100 MiB project limit."
            )
        if entry.file_size > 1024 * 1024 and (
            entry.compress_size == 0
            or entry.file_size / entry.compress_size > MAX_COMPRESSION_RATIO
        ):
            raise ArchiveValidationError(
                f"File {normalized!r} exceeds the allowed compression ratio."
            )
        if not _is_supported_project_file(path):
            raise ArchiveValidationError(
                f"Unsupported file type in project archive: {normalized!r}."
            )
        paths.append(normalized)

    file_paths = {path for path, is_directory in seen.items() if not is_directory}
    for name in seen:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath("."):
            if parent.as_posix() in file_paths:
                raise ArchiveValidationError(
                    "The ZIP archive contains a file used as a parent directory."
                )
            parent = parent.parent
    if not paths:
        raise ArchiveValidationError("The ZIP archive contains no supported project files.")

    return ArchiveSummary(tuple(sorted(paths)), expanded_bytes)


def extract_validated_zip(contents: bytes, destination: str | Path) -> ArchiveSummary:
    """Extract a validated archive using exclusive, non-executable regular files."""
    summary = inspect_zip_archive(contents)
    root = Path(destination).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as archive:
            extracted_bytes = 0
            for entry in archive.infolist():
                relative = PurePosixPath(
                    entry.filename[:-1] if entry.is_dir() else entry.filename
                )
                output_path = root.joinpath(*relative.parts)
                try:
                    output_path.resolve(strict=False).relative_to(root)
                except ValueError as exc:
                    raise ArchiveValidationError(
                        "The ZIP archive contains a path outside the extraction directory."
                    ) from exc
                if entry.is_dir():
                    output_path.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                file_bytes = 0
                with archive.open(entry) as source, output_path.open("xb") as target:
                    while chunk := source.read(64 * 1024):
                        file_bytes += len(chunk)
                        extracted_bytes += len(chunk)
                        if file_bytes > MAX_FILE_BYTES or extracted_bytes > MAX_EXPANDED_BYTES:
                            raise ArchiveValidationError(
                                "ZIP contents exceeded the validated extraction limits."
                            )
                        target.write(chunk)
                if file_bytes != entry.file_size:
                    raise ArchiveValidationError(
                        "A ZIP entry's declared and extracted sizes do not match."
                    )
    except ArchiveValidationError:
        raise
    except (
        OSError,
        RuntimeError,
        NotImplementedError,
        zlib.error,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        raise ArchiveValidationError(
            "The validated ZIP archive could not be extracted safely."
        ) from exc
    return summary


def run_uploaded_project(
    contents: bytes,
    *,
    action: Literal["scan", "run"],
    configs: tuple[str, ...] | list[str],
    strategy: str = "structured",
    maximum_attempts: int = 3,
) -> ExecutionResult:
    """Run an uploaded project through the existing SecureFix CLI only."""
    summary = inspect_zip_archive(contents)
    selected_configs = tuple(configs)
    if not selected_configs or any(
        config not in SUPPORTED_SEMGREP_CONFIGS for config in selected_configs
    ):
        raise ValueError("Select one or more supported Semgrep configurations.")
    if action not in {"scan", "run"}:
        raise ValueError("Unsupported SecureFix action.")
    if action == "run":
        if strategy not in SUPPORTED_PROMPT_STRATEGIES:
            raise ValueError("Select a supported repair prompt strategy.")
        if not 1 <= maximum_attempts <= MAX_REPAIR_ATTEMPTS:
            raise ValueError(
                f"Maximum repair attempts must be between 1 and {MAX_REPAIR_ATTEMPTS}."
            )

    report_directory = _create_ui_report_directory()
    if action == "run":
        missing = _missing_repair_prerequisites()
        if missing:
            message = " ".join(missing)
            report_path = _write_ui_report(
                report_directory,
                action=action,
                status="BLOCKED",
                error=message,
                project_preserved=None,
                file_count=len(summary.files),
                expanded_bytes=summary.expanded_bytes,
            )
            return ExecutionResult(
                action,
                "BLOCKED",
                report_path,
                _read_json_object(report_path),
                report_directory,
                message,
                "",
                "",
                None,
            )

    with tempfile.TemporaryDirectory(prefix="securefix-ui-") as temporary_directory:
        project = Path(temporary_directory) / "project"
        try:
            extract_validated_zip(contents, project)
            before = _snapshot_project(project)
        except (ArchiveValidationError, OSError) as exc:
            message = redact_sensitive_text(str(exc))
            report_path = _write_ui_report(
                report_directory,
                action=action,
                status="FAILED",
                error=message,
                project_preserved=None,
                file_count=len(summary.files),
                expanded_bytes=summary.expanded_bytes,
            )
            return ExecutionResult(
                action,
                "FAILED",
                report_path,
                _read_json_object(report_path),
                report_directory,
                message,
                "",
                "",
                None,
            )

        command = _build_cli_command(
            action=action,
            project=project,
            report_directory=report_directory,
            configs=selected_configs,
            strategy=strategy,
            maximum_attempts=maximum_attempts,
        )
        environment = os.environ.copy()
        source_path = str(WORKSPACE_ROOT / "src")
        inherited_python_path = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            f"{source_path}{os.pathsep}{inherited_python_path}"
            if inherited_python_path
            else source_path
        )
        timeout = 180 if action == "scan" else 180 + maximum_attempts * 600

        try:
            completed = subprocess.run(
                command,
                cwd=WORKSPACE_ROOT,
                env=environment,
                capture_output=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=timeout,
            )
            stdout = _redact_cli_text(completed.stdout)[-20_000:]
            stderr = _redact_cli_text(completed.stderr)[-20_000:]
        except subprocess.TimeoutExpired:
            completed = None
            stdout = ""
            stderr = ""
            error = f"SecureFix exceeded the {timeout}-second operation timeout."
        except OSError as exc:
            completed = None
            stdout = ""
            stderr = ""
            error = f"Unable to start SecureFix: {redact_sensitive_text(str(exc))}"
        else:
            error = None

        try:
            preserved = _snapshot_project(project) == before
        except (ArchiveValidationError, OSError):
            preserved = False
        if action == "scan":
            report_path = report_directory / "scan-report.json"
            report = _try_read_json_object(report_path)
            if completed is not None and completed.returncode == 0 and report is not None:
                status = "COMPLETED" if preserved else "FAILED"
                if not preserved:
                    error = "Source preservation check detected an unexpected change."
                return ExecutionResult(
                    action,
                    status,
                    report_path,
                    report,
                    report_directory,
                    error,
                    stdout,
                    stderr,
                    preserved,
                )
            error = error or _cli_failure(completed, stderr, report_path)
            report_path = _write_ui_report(
                report_directory,
                action=action,
                status="FAILED",
                error=error,
                project_preserved=preserved,
                file_count=len(summary.files),
                expanded_bytes=summary.expanded_bytes,
            )
            return ExecutionResult(
                action,
                "FAILED",
                report_path,
                _read_json_object(report_path),
                report_directory,
                error,
                stdout,
                stderr,
                preserved,
            )

        workflow_path = _find_workflow_report(report_directory)
        workflow_report = (
            _try_read_json_object(workflow_path) if workflow_path is not None else None
        )
        if completed is None or workflow_report is None:
            error = error or _cli_failure(completed, stderr, workflow_path)
            report_path = _write_ui_report(
                report_directory,
                action=action,
                status="FAILED",
                error=error,
                project_preserved=preserved,
                file_count=len(summary.files),
                expanded_bytes=summary.expanded_bytes,
            )
            return ExecutionResult(
                action,
                "FAILED",
                report_path,
                _read_json_object(report_path),
                report_directory,
                error,
                stdout,
                stderr,
                preserved,
            )

        status = workflow_display_status(workflow_report)
        if not preserved:
            status = "FAILED"
            error = "Source preservation check detected an unexpected change."
        elif completed.returncode != 0 and status == "VALIDATED":
            status = "FAILED"
            error = _cli_failure(completed, stderr, workflow_path)
        return ExecutionResult(
            action,
            status,
            workflow_path,
            workflow_report,
            report_directory,
            error,
            stdout,
            stderr,
            preserved,
        )


def workflow_display_status(report: dict[str, Any]) -> str:
    """Classify a workflow only when its report provides enough evidence."""
    final_status = report.get("final_status")
    known_statuses = {status.value for status in ValidationStatus}
    if not isinstance(final_status, str):
        return "UNKNOWN"
    if final_status not in known_statuses:
        return "UNKNOWN"

    attempts = report.get("attempts")
    if not isinstance(attempts, list):
        return "INCOMPLETE"

    if final_status == ValidationStatus.VALIDATED.value:
        if not attempts or not isinstance(report.get("integrity"), dict):
            return "INCOMPLETE"
        last_attempt = attempts[-1]
        validation = (
            last_attempt.get("validation")
            if isinstance(last_attempt, dict)
            else None
        )
        if (
            isinstance(validation, dict)
            and validation.get("status") == ValidationStatus.VALIDATED.value
            and report["integrity"].get("preserved") is True
        ):
            return "VALIDATED"
        return "INCOMPLETE"

    if final_status == ValidationStatus.PATCH_APPLICATION_FAILED.value:
        if not attempts:
            return "BLOCKED" if report.get("error") else "INCOMPLETE"
        if all(
            isinstance(attempt, dict) and attempt.get("generation") != "completed"
            for attempt in attempts
        ):
            return "BLOCKED"
        return "FAILED"

    if final_status == ValidationStatus.INCONCLUSIVE.value:
        if not attempts:
            return "BLOCKED" if report.get("error") else "INCOMPLETE"
        if all(
            isinstance(attempt, dict) and attempt.get("generation") != "completed"
            for attempt in attempts
        ):
            return "BLOCKED"
        return "INCOMPLETE"

    if final_status in {
        ValidationStatus.FAILED_TESTS.value,
        ValidationStatus.SECURITY_FINDING_REMAINS.value,
        ValidationStatus.NEW_SECURITY_FINDINGS.value,
        ValidationStatus.VALIDATION_ERROR.value,
    }:
        if not attempts:
            return "INCOMPLETE"
        return "FAILED"

    return "UNKNOWN"


def status_badge_class(status: str) -> str:
    """Return a known presentation class for one workflow status."""
    normalized = status.upper()
    known_styles = {
        "VALIDATED": "validated",
        "BLOCKED": "blocked",
        "FAILED": "failed",
        "INCOMPLETE": "incomplete",
        "COMPLETED": "completed",
    }
    return known_styles.get(normalized, "unknown")


def attempt_display_status(attempt: dict[str, Any]) -> str:
    """Classify one attempt without promoting missing validation evidence."""
    validation = attempt.get("validation")
    if not isinstance(validation, dict):
        return "INCOMPLETE"
    final_status = validation.get("status")
    if not isinstance(final_status, str):
        return "UNKNOWN"
    integrity = attempt.get("original_integrity")
    report = {
        "final_status": final_status,
        "attempts": [attempt],
        "integrity": integrity if isinstance(integrity, dict) else {},
        "error": validation.get("reasons"),
    }
    return workflow_display_status(report)


def dashboard_metrics(
    records: list[ReportRecord],
    *,
    report_error_count: int = 0,
) -> DashboardMetrics:
    """Count reports once, keeping scan-only runs distinct from repair workflows."""
    unique_records = {record.path.resolve(): record for record in records}
    scan_runs = 0
    workflow_runs = 0
    findings_reported = 0
    repairs_validated = 0
    repairs_blocked_or_failed = 0
    incomplete_reports = max(0, report_error_count)
    unknown_workflows = 0

    for record in unique_records.values():
        report_incomplete = False
        if record.kind == "Scan":
            scan_runs += 1
            findings = record.data.get("findings")
            if isinstance(findings, list):
                findings_reported += len(findings)
            else:
                report_incomplete = True
            scanner_errors = record.data.get("scanner_errors")
            if not isinstance(scanner_errors, list):
                report_incomplete = True
            elif scanner_errors:
                report_incomplete = True
            incomplete_reports += int(report_incomplete)
            continue

        if record.kind == "Workflow":
            workflow_runs += 1
            findings = record.data.get("original_findings")
            attempts = record.data.get("attempts")
            if isinstance(findings, list):
                findings_reported += len(findings)
            else:
                report_incomplete = True
            if not isinstance(attempts, list):
                report_incomplete = True
            if not isinstance(record.data.get("final_status"), str):
                report_incomplete = True

            if record.status == "VALIDATED":
                repairs_validated += 1
            elif record.status in {"BLOCKED", "FAILED"}:
                repairs_blocked_or_failed += 1
            else:
                if record.status == "UNKNOWN":
                    unknown_workflows += 1
                report_incomplete = True
            incomplete_reports += int(report_incomplete)
            continue

        if record.kind == "Interface run":
            action = record.data.get("action")
            if action == "scan":
                scan_runs += 1
            elif action == "run":
                workflow_runs += 1
                if record.status == "VALIDATED":
                    repairs_validated += 1
                elif record.status in {"BLOCKED", "FAILED"}:
                    repairs_blocked_or_failed += 1
                else:
                    if record.status == "UNKNOWN":
                        unknown_workflows += 1
                    report_incomplete = True
            incomplete_reports += int(report_incomplete)

    return DashboardMetrics(
        scan_runs=scan_runs,
        workflow_runs=workflow_runs,
        findings_reported=findings_reported,
        repairs_validated=repairs_validated,
        repairs_blocked_or_failed=repairs_blocked_or_failed,
        incomplete_reports=incomplete_reports,
        unknown_workflows=unknown_workflows,
    )


def finding_vulnerability_name(finding: dict[str, Any]) -> str:
    """Use a Semgrep vulnerability class or a readable form of its actual rule ID."""
    metadata = finding.get("scanner_metadata")
    rule_metadata = metadata.get("metadata") if isinstance(metadata, dict) else None
    vulnerability_class = (
        rule_metadata.get("vulnerability_class")
        if isinstance(rule_metadata, dict)
        else None
    )
    if isinstance(vulnerability_class, str) and vulnerability_class.strip():
        return vulnerability_class.strip()
    if isinstance(vulnerability_class, list):
        for item in vulnerability_class:
            if isinstance(item, str) and item.strip():
                return item.strip()

    rule_id = finding.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        return "Vulnerability name not available"
    parts = [part for part in re.split(r"[._-]+", rule_id) if part]
    readable = " ".join(parts[-3:]).title()
    return readable or "Vulnerability name not available"


def finding_cwe_identifiers(finding: dict[str, Any]) -> tuple[str, ...]:
    """Extract only CWE identifiers explicitly present in Semgrep metadata."""
    metadata = finding.get("scanner_metadata")
    rule_metadata = metadata.get("metadata") if isinstance(metadata, dict) else None
    cwe_data = rule_metadata.get("cwe") if isinstance(rule_metadata, dict) else None
    values = [cwe_data] if isinstance(cwe_data, str) else (
        cwe_data if isinstance(cwe_data, list) else []
    )
    identifiers: set[str] = set()
    for value in values:
        if isinstance(value, str):
            identifiers.update(match.upper() for match in re.findall(r"\bCWE-\d+\b", value, re.I))
    return tuple(sorted(identifiers, key=lambda identifier: int(identifier.split("-")[1])))


def short_run_identifier(record: ReportRecord) -> str:
    """Build a compact UI identifier while retaining the full value in metadata."""
    run_id = record.data.get("run_id")
    if isinstance(run_id, str) and run_id:
        suffix = run_id.removeprefix("securefix-run-")
        return f"…{suffix[-8:]}" if len(suffix) > 8 else suffix
    if record.kind == "Scan":
        stem = record.path.stem
        return stem if len(stem) <= 24 else f"{stem[:21]}…"
    return record.path.parent.name


def existing_patch_artifacts(record: ReportRecord) -> tuple[PatchArtifact, ...]:
    """Return only named candidate diff files that exist under this workflow report."""
    if record.kind != "Workflow":
        return ()
    attempts = record.data.get("attempts")
    if not isinstance(attempts, list):
        return ()
    artifacts: list[PatchArtifact] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        number = attempt.get("attempt")
        files = attempt.get("candidate_files")
        if (
            not isinstance(number, int)
            or isinstance(number, bool)
            or number < 1
            or not isinstance(files, dict)
        ):
            continue
        filename = files.get("unified_diff")
        if filename not in {"candidate.diff", "candidate.patch"}:
            continue
        try:
            contents = read_report_artifact(
                record.path,
                f"attempt-{number:02d}/{filename}",
            )
        except (FileNotFoundError, OSError, ValueError):
            continue
        artifacts.append(PatchArtifact(number, filename, contents))
    return tuple(artifacts)


def load_reports(root: str | Path = REPORTS_ROOT) -> tuple[list[ReportRecord], list[str]]:
    """Load real reports under the reports directory and surface malformed files."""
    reports_root = Path(root).resolve()
    candidates: set[Path] = set()
    if reports_root.is_dir():
        candidates.update(reports_root.glob("*.json"))
        for name in (
            "scan-report.json",
            "workflow-report.json",
            "evaluation-report.json",
            "securefix-ui-run.json",
        ):
            candidates.update(reports_root.rglob(name))

    records: list[ReportRecord] = []
    errors: list[str] = []
    for path in sorted(candidates):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(reports_root)
            if resolved.stat().st_size > MAX_REPORT_BYTES:
                errors.append(f"{path.name}: report exceeds the 20 MiB read limit.")
                continue
            data = _read_json_object(resolved)
        except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"{path.name}: unable to read JSON report ({exc}).")
            continue
        record = _report_record(resolved, data)
        records.append(record)

    records.sort(key=lambda item: item.generated_at, reverse=True)
    return records, errors


def read_report_artifact(report_path: str | Path, relative_path: str) -> bytes:
    """Read one report or patch artifact without allowing paths outside reports."""
    reports_root = REPORTS_ROOT.resolve()
    report_file = Path(report_path).resolve(strict=True)
    report_file.relative_to(reports_root)
    relative = PurePosixPath(relative_path)
    if (
        relative.is_absolute()
        or "\\" in relative_path
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("Report artifact path is invalid.")
    artifact = (report_file.parent / Path(*relative.parts)).resolve(strict=True)
    artifact.relative_to(report_file.parent.resolve(strict=True))
    if not artifact.is_file() or artifact.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Report artifact is missing or exceeds the 20 MiB read limit.")
    return artifact.read_bytes()


def _is_supported_project_file(path: PurePosixPath) -> bool:
    if path.suffix.lower() in SOURCE_EXTENSIONS | _PROJECT_METADATA_EXTENSIONS:
        return True
    return path.name.lower() in _PROJECT_METADATA_NAMES


def _snapshot_project(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ArchiveValidationError("Symbolic links are not allowed in project files.")
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[path.relative_to(root).as_posix()] = digest
    return snapshot


def _create_ui_report_directory() -> Path:
    reports_root = REPORTS_ROOT.resolve()
    UI_REPORTS_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved_ui_root = UI_REPORTS_ROOT.resolve(strict=True)
    resolved_ui_root.relative_to(reports_root)
    directory = resolved_ui_root / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    return directory


def _missing_repair_prerequisites() -> list[str]:
    missing: list[str] = []
    if not _configured_api_key():
        missing.append("Repair is BLOCKED because GEMINI_API_KEY is not configured.")
    if shutil.which("semgrep") is None:
        missing.append("Repair is BLOCKED because the Semgrep executable is unavailable.")
    if shutil.which("bwrap") is None:
        missing.append(
            "Repair is BLOCKED because Bubblewrap (bwrap) is unavailable; "
            "isolated verification will not be bypassed."
        )
    return missing


def repair_prerequisite_messages() -> tuple[str, ...]:
    """Return sanitized prerequisite messages without exposing credential values."""
    return tuple(_missing_repair_prerequisites())


def _configured_api_key() -> str | None:
    key = os.environ.get("GEMINI_API_KEY")
    if key and key.strip():
        return key.strip()
    try:
        from dotenv import dotenv_values
    except ModuleNotFoundError:
        return None
    values = dotenv_values(WORKSPACE_ROOT / ".env")
    dotenv_key = values.get("GEMINI_API_KEY")
    return dotenv_key.strip() if isinstance(dotenv_key, str) and dotenv_key.strip() else None


def _redact_cli_text(value: str) -> str:
    redacted = redact_sensitive_text(value)
    api_key = _configured_api_key()
    return redacted.replace(api_key, "[REDACTED]") if api_key else redacted


def _build_cli_command(
    *,
    action: Literal["scan", "run"],
    project: Path,
    report_directory: Path,
    configs: tuple[str, ...],
    strategy: str,
    maximum_attempts: int,
) -> list[str]:
    command = [sys.executable, "-m", "securefix.main", action, str(project)]
    for config in configs:
        command.extend(("--config", config))
    if action == "scan":
        command.extend(
            (
                "--timeout",
                "120",
                "--output",
                str(report_directory / "scan-report.json"),
            )
        )
    else:
        command.extend(
            (
                "--strategy",
                strategy,
                "--max-attempts",
                str(maximum_attempts),
                "--output-dir",
                str(report_directory),
            )
        )
    return command


def _write_ui_report(
    report_directory: Path,
    *,
    action: str,
    status: str,
    error: str,
    project_preserved: bool | None,
    file_count: int,
    expanded_bytes: int,
) -> Path:
    report_path = report_directory / "securefix-ui-run.json"
    report = {
        "run_id": report_directory.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "ui_status": status,
        "error": _redact_cli_text(error),
        "project_preserved": project_preserved,
        "uploaded_file_count": file_count,
        "expanded_bytes": expanded_bytes,
    }
    report["error"] = _redact_cli_text(report["error"])
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return report_path


def _read_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as report_file:
        data = json.load(report_file)
    if not isinstance(data, dict):
        raise ValueError("JSON report root must be an object.")
    return data


def _try_read_json_object(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        return _read_json_object(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def _find_workflow_report(report_directory: Path) -> Path | None:
    matches = sorted(report_directory.rglob("workflow-report.json"))
    if len(matches) != 1:
        return None
    path = matches[0]
    try:
        path.resolve(strict=True).relative_to(report_directory.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return path


def _cli_failure(
    completed: subprocess.CompletedProcess[str] | None,
    stderr: str,
    report_path: Path | None,
) -> str:
    if completed is None:
        return "SecureFix did not complete successfully."
    details = stderr.strip()
    if details:
        return f"SecureFix exited with status {completed.returncode}: {details}"
    if report_path is not None and not report_path.is_file():
        return "SecureFix did not create the expected report."
    return f"SecureFix exited with status {completed.returncode}."


def _report_record(path: Path, data: dict[str, Any]) -> ReportRecord:
    if data.get("scanner") == "semgrep":
        kind = "Scan"
        scanner_errors = data.get("scanner_errors")
        status = (
            "COMPLETED"
            if isinstance(scanner_errors, list) and not scanner_errors
            else "INCOMPLETE"
        )
        target = data.get("target")
        target_name = Path(target).name if isinstance(target, str) and target else path.stem
        title = f"Scan · {target_name}"
        timestamp = data.get("generated_at")
    elif "final_status" in data and "attempts" in data:
        kind = "Workflow"
        status = workflow_display_status(data)
        title = f"Workflow · {data.get('run_id', path.parent.name)}"
        timestamp = data.get("completed_at") or data.get("generated_at")
    elif "ui_status" in data:
        kind = "Interface run"
        status = str(data["ui_status"])
        title = f"{data.get('action', 'SecureFix').title()} · {data.get('run_id', path.parent.name)}"
        timestamp = data.get("generated_at")
    elif path.name == "evaluation-report.json":
        kind = "Evaluation"
        status = None
        title = f"Evaluation · {path.parent.name}"
        timestamp = data.get("generated_at")
    else:
        kind = "Report"
        status = None
        title = path.name
        timestamp = None
    if not isinstance(timestamp, str) or not timestamp:
        timestamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    return ReportRecord(path, data, kind, title, status, timestamp)
