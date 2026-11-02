from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from ui import service
from ui.service import (
    ArchiveValidationError,
    ReportRecord,
    dashboard_metrics,
    extract_validated_zip,
    existing_patch_artifacts,
    inspect_zip_archive,
    load_reports,
    read_report_artifact,
    run_uploaded_project,
    short_run_identifier,
    status_badge_class,
    workflow_display_status,
)


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    from io import BytesIO

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, contents in files.items():
            archive.writestr(name, contents)
    return buffer.getvalue()


def _set_report_roots(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(service, "REPORTS_ROOT", root)
    monkeypatch.setattr(service, "UI_REPORTS_ROOT", root / "streamlit")


def test_zip_validation_and_project_structure() -> None:
    archive = _zip_bytes(
        {
            "sample/app.py": b"print('safe to scan')\n",
            "sample/pyproject.toml": b"[project]\n",
            "sample/tests/test_app.py": b"def test_app(): pass\n",
        }
    )

    summary = inspect_zip_archive(archive)

    assert summary.files == (
        "sample/app.py",
        "sample/pyproject.toml",
        "sample/tests/test_app.py",
    )
    assert summary.expanded_bytes == sum(
        len(value)
        for value in (
            b"print('safe to scan')\n",
            b"[project]\n",
            b"def test_app(): pass\n",
        )
    )


@pytest.mark.parametrize(
    "filename",
    [
        "../outside.py",
        "/absolute.py",
        "C:/drive.py",
        "project/../outside.py",
        "project//empty.py",
        "project/.hidden/../outside.py",
    ],
)
def test_zip_rejects_traversal_and_ambiguous_paths(filename: str) -> None:
    with pytest.raises(ArchiveValidationError, match="unsafe path"):
        inspect_zip_archive(_zip_bytes({filename: b"content"}))


def test_zip_rejects_unsupported_and_oversized_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ArchiveValidationError, match="Unsupported file type"):
        inspect_zip_archive(_zip_bytes({"project/payload.exe": b"no"}))

    monkeypatch.setattr(service, "MAX_FILE_BYTES", 4)
    with pytest.raises(ArchiveValidationError, match="per-file limit"):
        inspect_zip_archive(_zip_bytes({"project/app.py": b"12345"}))


def test_zip_rejects_high_compression_ratio_and_expanded_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service, "MAX_COMPRESSION_RATIO", 2)
    with pytest.raises(ArchiveValidationError, match="compression ratio"):
        inspect_zip_archive(_zip_bytes({"project/app.py": b"a" * (1024 * 1024 + 1)}))

    monkeypatch.setattr(service, "MAX_EXPANDED_BYTES", 3)
    with pytest.raises(ArchiveValidationError, match="100 MiB project limit"):
        inspect_zip_archive(
            _zip_bytes({"project/a.py": b"12", "project/b.py": b"34"})
        )


def test_invalid_zip_upload_is_rejected() -> None:
    with pytest.raises(ArchiveValidationError, match="readable ZIP"):
        inspect_zip_archive(b"not a zip")


def test_zip_rejects_symlink_entries() -> None:
    from io import BytesIO
    import stat

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("project/link.py")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target.py")

    with pytest.raises(ArchiveValidationError, match="link or special file"):
        inspect_zip_archive(buffer.getvalue())


def test_extraction_writes_regular_non_executable_files(tmp_path: Path) -> None:
    destination = tmp_path / "extracted"
    archive = _zip_bytes({"project/app.py": b"pass\n"})

    summary = extract_validated_zip(archive, destination)

    source = destination / "project" / "app.py"
    assert summary.files == ("project/app.py",)
    assert source.read_bytes() == b"pass\n"
    assert source.stat().st_mode & 0o111 == 0


def test_missing_api_key_blocks_repair_without_starting_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    _set_report_roots(monkeypatch, reports)
    monkeypatch.setattr(service, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(service.shutil, "which", lambda _: "/usr/bin/tool")

    def fail_if_started(*args: object, **kwargs: object) -> None:
        raise AssertionError("CLI must not start without the Gemini API key")

    monkeypatch.setattr(service.subprocess, "run", fail_if_started)
    result = run_uploaded_project(
        _zip_bytes({"project/app.py": b"pass\n"}),
        action="run",
        configs=("p/security-audit",),
    )

    assert result.status == "BLOCKED"
    assert result.report is not None
    assert "GEMINI_API_KEY" in result.report["error"]
    assert result.report_path is not None and result.report_path.is_file()


def test_missing_bubblewrap_blocks_repair_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _set_report_roots(monkeypatch, tmp_path / "reports")
    monkeypatch.setattr(service, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setenv("GEMINI_API_KEY", "private-test-value")
    monkeypatch.setattr(
        service.shutil,
        "which",
        lambda executable: "/usr/bin/semgrep" if executable == "semgrep" else None,
    )

    def fail_if_started(*args: object, **kwargs: object) -> None:
        raise AssertionError("Repair must not run without the backend sandbox")

    monkeypatch.setattr(service.subprocess, "run", fail_if_started)
    result = run_uploaded_project(
        _zip_bytes({"project/app.py": b"pass\n"}),
        action="run",
        configs=("p/security-audit",),
    )

    assert result.status == "BLOCKED"
    assert result.report is not None
    assert "Bubblewrap" in result.report["error"]


def test_api_key_in_local_dotenv_is_recognized_without_displaying_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(service, "WORKSPACE_ROOT", tmp_path)
    (tmp_path / ".env").write_text("GEMINI_API_KEY=private-test-value\n", encoding="utf-8")

    assert service._configured_api_key() == "private-test-value"
    assert "private-test-value" not in json.dumps(service._missing_repair_prerequisites())


def test_secret_values_are_redacted_from_interface_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "private-test-value")

    assert service._redact_cli_text("provider rejected private-test-value") == (
        "provider rejected [REDACTED]"
    )


def test_cli_execution_failure_is_reported_as_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _set_report_roots(monkeypatch, tmp_path / "reports")
    monkeypatch.setenv("GEMINI_API_KEY", "not-for-output")
    monkeypatch.setattr(service.shutil, "which", lambda _: "/usr/bin/tool")

    def fail_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = args[0]
        assert isinstance(command, list)
        assert kwargs["shell"] is False
        assert kwargs["timeout"] > 0
        return subprocess.CompletedProcess(command, 1, "", "workflow failed")

    monkeypatch.setattr(service.subprocess, "run", fail_run)
    result = run_uploaded_project(
        _zip_bytes({"project/app.py": b"pass\n"}),
        action="run",
        configs=("p/security-audit",),
    )

    assert result.status == "FAILED"
    assert result.report is not None
    assert result.report["ui_status"] == "FAILED"
    assert "not-for-output" not in json.dumps(result.report)


def test_cli_timeout_is_reported_as_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _set_report_roots(monkeypatch, tmp_path / "reports")
    monkeypatch.setattr(service, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setenv("GEMINI_API_KEY", "private-test-value")
    monkeypatch.setattr(service.shutil, "which", lambda _: "/usr/bin/tool")

    def time_out(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(service.subprocess, "run", time_out)
    result = run_uploaded_project(
        _zip_bytes({"project/app.py": b"pass\n"}),
        action="run",
        configs=("p/security-audit",),
    )

    assert result.status == "FAILED"
    assert result.report is not None
    assert result.report["ui_status"] == "FAILED"
    assert "operation timeout" in result.report["error"]


def test_scan_uses_cli_and_preserves_uploaded_project(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _set_report_roots(monkeypatch, tmp_path / "reports")
    original = b"def safe():\n    return True\n"
    uploaded = _zip_bytes({"project/app.py": original})
    original_archive = uploaded

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        assert command[1:4] == ["-m", "securefix.main", "scan"]
        assert kwargs["shell"] is False
        project = Path(command[4])
        assert (project / "project" / "app.py").read_bytes() == original
        output = Path(command[command.index("--output") + 1])
        output.write_text(
            json.dumps(
                {
                    "scanner": "semgrep",
                    "generated_at": "2026-01-01T00:00:00+00:00",
                    "target": str(project),
                    "findings": [],
                    "scanner_errors": [],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "Scan complete", "")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    result = run_uploaded_project(
        uploaded,
        action="scan",
        configs=("p/security-audit",),
    )

    assert result.status == "COMPLETED"
    assert result.project_preserved is True
    assert result.report is not None and result.report["findings"] == []
    assert uploaded == original_archive


def test_sql_rule_is_allowlisted_and_arbitrary_configs_are_rejected() -> None:
    local_rule = "datasets/phase3/sql_injection/securefix_sql_injection.yml"
    assert local_rule in service.SUPPORTED_SEMGREP_CONFIGS

    with pytest.raises(ValueError, match="supported Semgrep configurations"):
        run_uploaded_project(
            _zip_bytes({"project/app.py": b"pass\n"}),
            action="scan",
            configs=("/tmp/untrusted-rules.yml",),
        )


def test_repair_uses_existing_run_command_and_preserves_original_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _set_report_roots(monkeypatch, tmp_path / "reports")
    monkeypatch.setenv("GEMINI_API_KEY", "private-test-value")
    monkeypatch.setattr(service.shutil, "which", lambda _: "/usr/bin/tool")
    original = b"def vulnerable():\n    return 'original'\n"

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        assert command[1:4] == ["-m", "securefix.main", "run"]
        assert "--strategy" in command
        assert command[command.index("--strategy") + 1] == "structured"
        assert command[command.index("--max-attempts") + 1] == "2"
        assert kwargs["shell"] is False
        project = Path(command[4])
        assert (project / "project" / "app.py").read_bytes() == original
        output = Path(command[command.index("--output-dir") + 1])
        run_directory = output / "securefix-run-test"
        run_directory.mkdir()
        (run_directory / "workflow-report.json").write_text(
            json.dumps(
                {
                    "run_id": "securefix-run-test",
                    "final_status": "VALIDATED",
                    "attempts": [
                        {
                            "generation": "completed",
                            "validation": {"status": "VALIDATED"},
                        }
                    ],
                    "integrity": {"preserved": True},
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "Validation status: VALIDATED", "")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    result = run_uploaded_project(
        _zip_bytes({"project/app.py": original}),
        action="run",
        configs=("p/security-audit",),
        strategy="structured",
        maximum_attempts=2,
    )

    assert result.status == "VALIDATED"
    assert result.project_preserved is True
    assert result.report is not None
    assert result.report["final_status"] == "VALIDATED"


def test_report_loading_includes_existing_scans_and_workflows(
    tmp_path: Path,
) -> None:
    scan_report = tmp_path / "scan.json"
    scan_report.write_text(
        json.dumps(
            {
                "scanner": "semgrep",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    nested_scan_report = tmp_path / "streamlit" / "scan-run" / "scan-report.json"
    nested_scan_report.parent.mkdir(parents=True)
    nested_scan_report.write_text(
        json.dumps(
            {
                "scanner": "semgrep",
                "generated_at": "2026-01-02T00:00:00+00:00",
                "findings": [{"rule_id": "example.rule"}],
            }
        ),
        encoding="utf-8",
    )
    workflow_directory = tmp_path / "workflow" / "securefix-run-test"
    workflow_directory.mkdir(parents=True)
    workflow_report = workflow_directory / "workflow-report.json"
    workflow_report.write_text(
        json.dumps(
            {
                "run_id": "securefix-run-test",
                "final_status": "FAILED_TESTS",
                "attempts": [{"generation": "completed"}],
            }
        ),
        encoding="utf-8",
    )
    invalid_report = tmp_path / "broken.json"
    invalid_report.write_text("{", encoding="utf-8")

    records, errors = load_reports(tmp_path)

    assert {record.kind for record in records} == {"Scan", "Workflow"}
    assert sum(record.kind == "Scan" for record in records) == 2
    assert next(item for item in records if item.kind == "Workflow").status == "FAILED"
    assert any("broken.json" in error for error in errors)


def test_dashboard_metrics_separate_runs_and_deduplicate_report_paths(
    tmp_path: Path,
) -> None:
    timestamp = "2026-01-01T00:00:00+00:00"
    scan_path = tmp_path / "scan.json"
    scan = ReportRecord(
        scan_path,
        {
            "findings": [{"rule_id": "one"}, {"rule_id": "two"}],
            "scanner_errors": [],
        },
        "Scan",
        "Scan · project",
        "COMPLETED",
        timestamp,
    )
    workflow = ReportRecord(
        tmp_path / "workflow.json",
        {
            "original_findings": [{"rule_id": "three"}],
            "final_status": "VALIDATED",
            "attempts": [
                {
                    "generation": "completed",
                    "validation": {"status": "VALIDATED"},
                }
            ],
            "integrity": {"preserved": True},
        },
        "Workflow",
        "Workflow · run",
        "VALIDATED",
        timestamp,
    )

    metrics = dashboard_metrics(
        [scan, scan, workflow],
        report_error_count=2,
    )

    assert metrics.scan_runs == 1
    assert metrics.workflow_runs == 1
    assert metrics.findings_reported == 3
    assert metrics.repairs_validated == 1
    assert metrics.repairs_blocked_or_failed == 0
    assert metrics.incomplete_reports == 2


def test_dashboard_counts_blocked_failed_incomplete_and_unknown_separately(
    tmp_path: Path,
) -> None:
    timestamp = "2026-01-01T00:00:00+00:00"
    records = [
        ReportRecord(tmp_path / "blocked.json", {}, "Workflow", "blocked", "BLOCKED", timestamp),
        ReportRecord(tmp_path / "failed.json", {}, "Workflow", "failed", "FAILED", timestamp),
        ReportRecord(tmp_path / "incomplete.json", {}, "Workflow", "incomplete", "INCOMPLETE", timestamp),
        ReportRecord(tmp_path / "unknown.json", {}, "Workflow", "unknown", "UNKNOWN", timestamp),
    ]

    metrics = dashboard_metrics(records)

    assert metrics.workflow_runs == 4
    assert metrics.repairs_validated == 0
    assert metrics.repairs_blocked_or_failed == 2
    assert metrics.unknown_workflows == 1
    assert metrics.incomplete_reports == 4


def test_empty_dashboard_metrics_are_zero(tmp_path: Path) -> None:
    metrics = dashboard_metrics([])

    assert metrics.scan_runs == 0
    assert metrics.workflow_runs == 0
    assert metrics.findings_reported == 0
    assert metrics.repairs_validated == 0
    assert metrics.repairs_blocked_or_failed == 0
    assert metrics.incomplete_reports == 0


def test_report_and_patch_downloads_only_offer_existing_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(service, "REPORTS_ROOT", tmp_path)
    report_path = tmp_path / "securefix-run-1234567890" / "workflow-report.json"
    attempt_directory = report_path.parent / "attempt-01"
    attempt_directory.mkdir(parents=True)
    report_contents = b'{"final_status": "FAILED_TESTS"}\n'
    report_path.write_bytes(report_contents)
    (attempt_directory / "candidate.diff").write_text("--- before\n+++ after\n", encoding="utf-8")
    record = ReportRecord(
        report_path,
        {
            "run_id": "securefix-run-1234567890",
            "attempts": [
                {"attempt": 1, "candidate_files": {"unified_diff": "candidate.diff"}},
                {"attempt": 2, "candidate_files": {"unified_diff": "missing.diff"}},
                {"attempt": 3, "candidate_files": {"unified_diff": "../workflow-report.json"}},
            ],
        },
        "Workflow",
        "Workflow · run",
        "FAILED",
        "2026-01-01T00:00:00+00:00",
    )

    assert read_report_artifact(report_path, report_path.name) == report_contents
    artifacts = existing_patch_artifacts(record)
    assert [(artifact.attempt, artifact.filename) for artifact in artifacts] == [
        (1, "candidate.diff")
    ]
    assert artifacts[0].contents == b"--- before\n+++ after\n"
    assert short_run_identifier(record) == "…34567890"


def test_vulnerability_name_and_cwe_use_only_report_metadata() -> None:
    from ui.service import finding_cwe_identifiers, finding_vulnerability_name

    finding = {
        "rule_id": "python.security.sql-injection.interpolation",
        "scanner_metadata": {
            "metadata": {
                "vulnerability_class": ["SQL Injection"],
                "cwe": ["CWE-89: Improper Neutralization of Special Elements"],
            }
        },
    }

    assert finding_vulnerability_name(finding) == "SQL Injection"
    assert finding_cwe_identifiers(finding) == ("CWE-89",)
    assert finding_cwe_identifiers({"rule_id": "unclassified.rule"}) == ()


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (
            {
                "final_status": "VALIDATED",
                "attempts": [
                    {
                        "generation": "completed",
                        "validation": {"status": "VALIDATED"},
                    }
                ],
                "integrity": {"preserved": True},
            },
            "VALIDATED",
        ),
        ({"final_status": "INCONCLUSIVE", "attempts": [], "error": "scan unavailable"}, "BLOCKED"),
        ({"final_status": "INCONCLUSIVE", "attempts": []}, "INCOMPLETE"),
        ({"final_status": "SOMETHING_NEW", "attempts": []}, "UNKNOWN"),
        (
            {
                "final_status": "VALIDATED",
                "attempts": [{"generation": "completed"}],
                "integrity": {"preserved": True},
            },
            "INCOMPLETE",
        ),
        (
            {
                "final_status": "PATCH_APPLICATION_FAILED",
                "attempts": [{"generation": "failed"}],
            },
            "BLOCKED",
        ),
        (
            {
                "final_status": "FAILED_TESTS",
                "attempts": [{"generation": "completed"}],
            },
            "FAILED",
        ),
    ],
)
def test_workflow_statuses_are_not_overstated(
    report: dict[str, object],
    expected: str,
) -> None:
    assert workflow_display_status(report) == expected


@pytest.mark.parametrize(
    ("status", "style"),
    [
        ("VALIDATED", "validated"),
        ("BLOCKED", "blocked"),
        ("FAILED", "failed"),
    ],
)
def test_workflow_status_badges_are_distinct(status: str, style: str) -> None:
    assert status_badge_class(status) == style


def test_long_unknown_workflow_status_is_not_promoted_or_truncated() -> None:
    long_status = "UNRECOGNIZED_VALIDATION_STATE_" + "X" * 80

    assert workflow_display_status(
        {"final_status": long_status, "attempts": [{"generation": "completed"}]}
    ) == "UNKNOWN"
    assert status_badge_class(long_status) == "unknown"
