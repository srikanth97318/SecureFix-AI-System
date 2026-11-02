from __future__ import annotations

import json
from pathlib import Path

import pytest

from securefix.llm.gemini_provider import MissingAPIKeyError
from securefix.main import main


def valid_response() -> dict[str, object]:
    return {
        "vulnerability_id": "python.security.test",
        "analysis": {
            "vulnerability_type": "unsafe evaluation",
            "explanation": "The input reaches eval; this is supported by the shown call.",
            "security_impact": "Untrusted input could cause unintended code execution.",
            "assumptions": ["The input may be influenced by a caller."],
        },
        "repair": {
            "summary": "Use a restricted conversion.",
            "file_path": "app.py",
            "changes": [
                {
                    "start_line": 2,
                    "end_line": 2,
                    "original_code": "    eval(value)",
                    "replacement_code": "    int(value)",
                }
            ],
        },
        "reasoning_summary": "Restricts the operation to the expected input type.",
        "limitations": ["The surrounding validation should still be reviewed."],
    }


def _scan_result() -> dict[str, object]:
    return {
        "results": [
            {
                "check_id": "python.security.test",
                "path": "app.py",
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {
                    "message": "Unsafe evaluation",
                    "severity": "ERROR",
                    "lines": "eval(value)",
                },
            }
        ]
    }


class FakeProvider:
    response = json.dumps(valid_response())
    prompts: list[str] = []

    def __init__(self, *, model=None, timeout_seconds=90) -> None:
        self.model = model
        self.timeout_seconds = timeout_seconds

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.response


def _source_target(tmp_path: Path) -> tuple[Path, Path, str]:
    target = tmp_path / "source"
    target.mkdir()
    source = target / "app.py"
    original = "def run(value):\n    eval(value)\n    return True\n"
    source.write_text(original, encoding="utf-8")
    return target, source, original


@pytest.mark.parametrize("strategy", ["basic", "structured", "context_feedback"])
def test_repair_cli_generates_proposal_for_each_strategy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    strategy: str,
) -> None:
    target, source, original = _source_target(tmp_path)
    proposal_path = tmp_path / f"{strategy}.json"
    diff_path = tmp_path / f"{strategy}.diff"
    monkeypatch.setattr("securefix.main.SemgrepScanner.scan", lambda self, path: _scan_result())
    monkeypatch.setattr("securefix.main.GeminiProvider", FakeProvider)
    FakeProvider.prompts.clear()

    arguments = [
        "repair",
        str(target),
        "--strategy",
        strategy,
        "--output",
        str(proposal_path),
        "--diff-output",
        str(diff_path),
    ]
    if strategy == "context_feedback":
        arguments.extend(["--previous-repair", "old candidate", "--validation-failure", "check failed"])

    assert main(arguments) == 0

    output = capsys.readouterr().out
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    assert proposal["vulnerability_id"] == "python.security.test"
    assert proposal["candidate_file"] == "app.py"
    assert "Proposed unified diff (not applied)" in output
    assert diff_path.read_text(encoding="utf-8").startswith("--- a/app.py")
    assert source.read_text(encoding="utf-8") == original
    if strategy == "basic":
        assert "minimal repair" in FakeProvider.prompts[0]
    elif strategy == "structured":
        assert "Security constraints" in FakeProvider.prompts[0]
    else:
        assert "old candidate" in FakeProvider.prompts[0]


def test_repair_cli_reuses_report_without_running_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, source, original = _source_target(tmp_path)
    report_path = tmp_path / "scan.json"
    report_path.write_text(
        json.dumps(
            {
                "scanner": "semgrep",
                "target": str(target.resolve()),
                "findings": [
                    {
                        "rule_id": "python.security.test",
                        "category": None,
                        "severity": "ERROR",
                        "file_path": "app.py",
                        "start_line": 2,
                        "end_line": 2,
                        "message": "Unsafe evaluation",
                        "matched_code": "eval(value)",
                        "scanner_metadata": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "securefix.main.SemgrepScanner.scan",
        lambda self, path: (_ for _ in ()).throw(AssertionError("scanner should not run")),
    )
    monkeypatch.setattr("securefix.main.GeminiProvider", FakeProvider)

    assert main(
        [
            "repair",
            str(target),
            "--report",
            str(report_path),
            "--output",
            str(tmp_path / "reused.json"),
            "--diff-output",
            str(tmp_path / "reused.diff"),
        ]
    ) == 0
    assert source.read_text(encoding="utf-8") == original


def test_repair_cli_missing_api_key_is_explicit_and_writes_no_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    target, _, _ = _source_target(tmp_path)
    proposal_path = tmp_path / "proposal.json"
    monkeypatch.setattr("securefix.main.SemgrepScanner.scan", lambda self, path: _scan_result())

    def missing_key(**kwargs):
        raise MissingAPIKeyError("GEMINI_API_KEY is required")

    monkeypatch.setattr("securefix.main.GeminiProvider", missing_key)

    assert main(
        [
            "repair",
            str(target),
            "--output",
            str(proposal_path),
            "--diff-output",
            str(tmp_path / "proposal.diff"),
        ]
    ) == 1
    assert "GEMINI_API_KEY is required" in capsys.readouterr().err
    assert not proposal_path.exists()


def test_repair_cli_reports_malformed_model_response_without_writing_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    target, _, _ = _source_target(tmp_path)
    proposal_path = tmp_path / "proposal.json"
    FakeProvider.response = "not json"
    monkeypatch.setattr("securefix.main.SemgrepScanner.scan", lambda self, path: _scan_result())
    monkeypatch.setattr("securefix.main.GeminiProvider", FakeProvider)

    try:
        assert main(
            [
                "repair",
                str(target),
                "--output",
                str(proposal_path),
                "--diff-output",
                str(tmp_path / "proposal.diff"),
            ]
        ) == 1
        assert "not valid JSON" in capsys.readouterr().err
        assert not proposal_path.exists()
    finally:
        FakeProvider.response = json.dumps(valid_response())


def test_repair_cli_rejects_report_for_different_target(tmp_path: Path, capsys) -> None:
    target, _, _ = _source_target(tmp_path)
    report_path = tmp_path / "scan.json"
    report_path.write_text(
        json.dumps(
            {
                "scanner": "semgrep",
                "target": str(tmp_path),
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    assert main(["repair", str(target), "--report", str(report_path)]) == 1
    assert "does not match" in capsys.readouterr().err
