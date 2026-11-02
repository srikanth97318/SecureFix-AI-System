from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from securefix.llm import MissingAPIKeyError
from securefix.main import _build_parser, _scanner_configs, main


def test_run_cli_invokes_bounded_workflow(tmp_path: Path, monkeypatch, capsys) -> None:
    target = tmp_path / "target"
    target.mkdir()
    workflow_calls = {}
    fake_result = SimpleNamespace(
        final_status="INCONCLUSIVE",
        attempts=[],
        maximum_attempts=2,
        integrity={"preserved": True},
        report_directory=str(tmp_path / "reports" / "run"),
    )

    class FakeWorkflow:
        def __init__(self, provider, **options):
            workflow_calls["options"] = options

        def run(self, path, **options):
            workflow_calls["target"] = path
            workflow_calls["run_options"] = options
            return fake_result

    monkeypatch.setattr("securefix.main.GeminiProvider", lambda **kwargs: object())
    monkeypatch.setattr("securefix.main.RepairWorkflow", FakeWorkflow)

    status = main(
        [
            "run",
            str(target),
            "--strategy",
            "basic",
            "--max-attempts",
            "2",
            "--config",
            "p/security-audit",
            "--config",
            "custom-rules.yml",
            "--output-dir",
            str(tmp_path / "reports"),
        ]
    )

    assert status == 0
    assert workflow_calls["run_options"] == {
        "strategy": "basic",
        "finding_index": 1,
        "maximum_attempts": 2,
    }
    assert workflow_calls["options"]["scanner_config"] == [
        "p/security-audit",
        "custom-rules.yml",
    ]
    assert "INCONCLUSIVE" in capsys.readouterr().out


def test_run_cli_accepts_repeated_semgrep_configurations() -> None:
    args = _build_parser().parse_args(
        [
            "run",
            "target",
            "--config",
            "p/security-audit",
            "--config",
            "custom-rules.yml",
        ]
    )

    assert args.config == ["p/security-audit", "custom-rules.yml"]
    assert _scanner_configs(args.config, "p/security-audit") == [
        "p/security-audit",
        "custom-rules.yml",
    ]


def test_run_cli_defaults_to_security_audit_configuration() -> None:
    args = _build_parser().parse_args(["run", "target"])

    assert args.config is None
    assert _scanner_configs(args.config, "p/security-audit") == ["p/security-audit"]


def test_single_run_config_remains_supported() -> None:
    args = _build_parser().parse_args(
        ["run", "target", "--config", "p/security-audit"]
    )

    assert _scanner_configs(args.config, "p/security-audit") == ["p/security-audit"]


def test_evaluate_cli_saves_inconclusive_cases_on_missing_api_key(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    dataset = tmp_path / "dataset"
    case = dataset / "example"
    case.mkdir(parents=True)
    (case / "case.json").write_text(
        json.dumps(
            {
                "case_id": "example",
                "category": "unit test",
                "expected_secure_behavior": "Use a safe implementation.",
                "semgrep_support": "not_assessed",
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "reports" / "evaluation"

    def missing_key_provider(**kwargs):
        raise MissingAPIKeyError("GEMINI_API_KEY is required")

    monkeypatch.setattr("securefix.main.GeminiProvider", missing_key_provider)
    status = main(
        [
            "evaluate",
            str(dataset),
            "--strategies",
            "basic",
            "--output-dir",
            str(output),
        ]
    )

    assert status == 1
    report = json.loads(
        (output / "evaluation-report.json").read_text(encoding="utf-8")
    )
    result = report["strategies"][0]["cases"][0]
    assert result["status"] == "INCONCLUSIVE"
    assert "GEMINI_API_KEY" in result["error"]
    assert "inconclusive=1" in capsys.readouterr().out
