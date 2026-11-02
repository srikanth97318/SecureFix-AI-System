from __future__ import annotations

import json
from pathlib import Path

import pytest

from securefix.verification.evaluation import (
    EvaluationError,
    _case_report,
    evaluate_strategies,
    load_evaluation_cases,
)
from securefix.models import Finding
from securefix.sanitization import is_sensitive_path
from securefix.verification.isolated_workspace import IsolatedWorkspace


def _write_case(directory: Path, case_id: str) -> None:
    directory.mkdir(parents=True)
    (directory / "case.json").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "category": "example",
                "expected_secure_behavior": "Use a safe implementation.",
            }
        ),
        encoding="utf-8",
    )


def test_evaluation_rejects_case_id_path_traversal(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    case = dataset / "example"
    _write_case(case, "../outside")

    with pytest.raises(EvaluationError, match="safe filename component"):
        load_evaluation_cases(dataset)


def test_evaluation_rejects_manifest_symlink_outside_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    outside_manifest = tmp_path / "case.json"
    outside_manifest.write_text("{}", encoding="utf-8")
    (dataset / "case.json").symlink_to(outside_manifest)

    with pytest.raises(EvaluationError, match="escapes the dataset"):
        load_evaluation_cases(dataset)


def test_evaluation_output_must_be_outside_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    _write_case(dataset / "example", "example")

    with pytest.raises(EvaluationError, match="outside the dataset"):
        evaluate_strategies(
            dataset,
            strategies=["basic"],
            provider_factory=lambda: object(),
            output_directory=dataset / "reports",
        )

    assert not (dataset / "reports").exists()


@pytest.mark.parametrize(
    ("case_name", "rule_id"),
    [
        (
            "command_injection",
            "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        ),
        (
            "insecure_deserialization",
            "python.lang.security.deserialization.pickle.avoid-pickle",
        ),
    ],
)
def test_benchmark_rule_ids_match_live_semgrep_report(
    case_name: str,
    rule_id: str,
) -> None:
    case = load_evaluation_cases(Path("datasets/phase3") / case_name)[0]
    report = _case_report(
        case,
        {
            "final_status": "INCONCLUSIVE",
            "attempts": [],
            "original_findings": [
                Finding(
                    rule_id=rule_id,
                    severity="ERROR",
                    file_path=f"{case_name}/app.py",
                ).to_dict()
            ],
        },
        Path("/tmp/securefix-evaluation-test"),
        0.0,
    )

    assert report["semgrep_support"] == "observed"
    assert report["expected_rule_matches"][0]["rule_id"] == rule_id


def test_benchmark_projects_are_included_in_isolated_workspace() -> None:
    cases = load_evaluation_cases("datasets/phase3")

    assert len(cases) == 5
    for case in cases:
        assert not is_sensitive_path(case.target_directory)
        with IsolatedWorkspace(case.target_directory) as workspace:
            assert (workspace.working_copy / "app.py").is_file()
            assert list((workspace.working_copy).glob("test_*.py"))
