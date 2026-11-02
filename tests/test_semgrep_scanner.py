from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from securefix.scanner import (
    ScannerExecutionError,
    ScannerTimeoutError,
    SemgrepNotFoundError,
    SemgrepScanner,
)
from securefix.models import Finding
from securefix.verification.security_rescan import SecurityScanner, run_security_rescan


def test_missing_semgrep_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: None)

    with pytest.raises(SemgrepNotFoundError, match="pip install semgrep"):
        SemgrepScanner().scan(tmp_path)


def test_scanner_executes_without_shell_and_parses_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout='{"results": []}', stderr=""
    )
    run = Mock(return_value=completed)
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.subprocess.run", run)

    result = SemgrepScanner().scan(tmp_path)

    assert result == {"results": []}
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["timeout"] == 120


def test_scanner_execution_error_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = subprocess.CompletedProcess(
        args=["semgrep"], returncode=2, stdout="", stderr="scanner failed"
    )
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        "securefix.scanner.semgrep_scanner.subprocess.run",
        Mock(return_value=completed),
    )

    with pytest.raises(ScannerExecutionError, match="scanner failed"):
        SemgrepScanner().scan(tmp_path)


def test_scanner_timeout_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        "securefix.scanner.semgrep_scanner.subprocess.run",
        Mock(side_effect=subprocess.TimeoutExpired("semgrep", 1)),
    )

    with pytest.raises(ScannerTimeoutError, match="timeout"):
        SemgrepScanner(timeout_seconds=1).scan(tmp_path)


def test_scanner_rejects_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout="not-json", stderr=""
    )
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        "securefix.scanner.semgrep_scanner.subprocess.run",
        Mock(return_value=completed),
    )

    with pytest.raises(ScannerExecutionError, match="invalid JSON"):
        SemgrepScanner().scan(tmp_path)


def test_scanner_passes_json_configuration_and_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout=json.dumps({"results": []}), stderr=""
    )
    run = Mock(return_value=completed)
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.subprocess.run", run)

    SemgrepScanner(config="rules.yml").scan(tmp_path)
    command = run.call_args.args[0]

    assert command[1:4] == ["scan", "--config", "rules.yml"]
    assert "--json" in command
    assert str(tmp_path.resolve()) == command[-1]


def test_scanner_passes_multiple_configurations_as_repeated_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout=json.dumps({"results": []}), stderr=""
    )
    run = Mock(return_value=completed)
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.subprocess.run", run)

    SemgrepScanner(config=["p/security-audit", "custom-rules.yml"]).scan(tmp_path)
    command = run.call_args.args[0]

    assert command[1:7] == [
        "scan",
        "--config",
        "p/security-audit",
        "--config",
        "custom-rules.yml",
        "--json",
    ]


def test_rescan_reuses_all_configurations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout=json.dumps({"results": []}), stderr=""
    )
    run = Mock(return_value=completed)
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("securefix.scanner.semgrep_scanner.subprocess.run", run)
    configs = ["p/security-audit", "custom-rules.yml"]
    scanner = SecurityScanner(
        config=configs,
        scanner=SemgrepScanner(config=configs),
    )

    scanner.scan(tmp_path)
    result = run_security_rescan(
        scanner,
        tmp_path,
        original_target=tmp_path,
        original_findings=[],
        selected_finding=Finding(rule_id="selected.rule"),
    )

    assert result.status == "COMPLETED"
    assert run.call_count == 2
    expected_options = [
        "--config",
        "p/security-audit",
        "--config",
        "custom-rules.yml",
    ]
    for call in run.call_args_list:
        command = call.args[0]
        assert command[2:6] == expected_options
