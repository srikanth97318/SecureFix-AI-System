from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from securefix.main import main


def test_cli_writes_report_for_empty_scan(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "source"
    target.mkdir()
    report_path = tmp_path / "output" / "report.json"
    monkeypatch.setattr("securefix.main.SemgrepScanner.scan", lambda self, path: {"results": []})

    status = main(["scan", str(target), "--output", str(report_path)])

    assert status == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["findings"] == []
    assert report["scanner_errors"] == []
    assert report["target"] == str(target.resolve())


def test_module_cli_runs_with_json_semgrep_executable(tmp_path: Path) -> None:
    target = tmp_path / "source"
    target.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    semgrep = fake_bin / "semgrep"
    semgrep.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({'results': []}))\n",
        encoding="utf-8",
    )
    semgrep.chmod(0o755)
    report_path = tmp_path / "report.json"
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "securefix.main",
            "scan",
            str(target),
            "--output",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(report_path.read_text(encoding="utf-8"))["findings"] == []


def test_cli_includes_multiple_findings_and_context(
    tmp_path: Path, monkeypatch
) -> None:
    target = tmp_path / "source"
    target.mkdir()
    (target / "app.py").write_text("first\nbad_call()\nthird\n", encoding="utf-8")
    report_path = tmp_path / "report.json"
    scan_results = {
        "results": [
            {
                "check_id": f"rule.{number}",
                "path": "app.py",
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {"message": "issue", "lines": "bad_call()"},
            }
            for number in (1, 2)
        ]
    }
    monkeypatch.setattr(
        "securefix.main.SemgrepScanner.scan",
        lambda self, path: scan_results,
    )

    assert main(
        ["scan", str(target), "--output", str(report_path), "--context-lines", "1"]
    ) == 0
    findings = json.loads(report_path.read_text(encoding="utf-8"))["findings"]

    assert len(findings) == 2
    assert [line["line_number"] for line in findings[0]["context"]["lines"]] == [1, 2, 3]


def test_cli_invalid_target_returns_error(tmp_path: Path) -> None:
    assert main(["scan", str(tmp_path / "missing")]) == 2





def test_cli_missing_scanner_reports_error(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    target = tmp_path / "source"
    target.mkdir()

    def missing_scanner(self, path):
        from securefix.scanner import SemgrepNotFoundError

        raise SemgrepNotFoundError("install Semgrep")

    monkeypatch.setattr("securefix.main.SemgrepScanner.scan", missing_scanner)

    assert main(["scan", str(target)]) == 1
    assert "install Semgrep" in capsys.readouterr().err
