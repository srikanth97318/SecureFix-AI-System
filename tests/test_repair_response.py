from __future__ import annotations

import json

import pytest

from securefix.analysis import RepairAnalyzer
from securefix.llm.prompts import PromptStrategy
from securefix.models import Finding, RepairProposal, RepairResponseError


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


class StubProvider:
    def __init__(self, response: str) -> None:
        self.response = response
        self.prompt = ""

    def generate(self, prompt: str) -> str:
        self.prompt = prompt
        return self.response


def test_structured_response_validates_and_serializes() -> None:
    proposal = RepairProposal.from_json(json.dumps(valid_response()))

    assert proposal.repair.changes[0].start_line == 2
    assert json.loads(json.dumps(proposal.to_dict()))["repair"]["file_path"] == "app.py"


@pytest.mark.parametrize(
    "response",
    [
        "not-json",
        '{"vulnerability_id": "duplicate", "vulnerability_id": "again"}',
        json.dumps({**valid_response(), "extra": "unexpected"}),
        json.dumps(
            {
                **valid_response(),
                "analysis": {**valid_response()["analysis"], "assumptions": "not a list"},
            }
        ),
        json.dumps(
            {
                **valid_response(),
                "repair": {
                    **valid_response()["repair"],
                    "changes": [
                        {
                            **valid_response()["repair"]["changes"][0],
                            "start_line": True,
                        }
                    ],
                },
            }
        ),
    ],
)
def test_malformed_or_invalid_response_is_rejected(response: str) -> None:
    with pytest.raises(RepairResponseError):
        RepairProposal.from_json(response)


def test_response_larger_than_limit_is_rejected() -> None:
    with pytest.raises(RepairResponseError, match="1 MB"):
        RepairProposal.from_json(" " * 1_000_001)


def test_analyzer_calls_provider_with_selected_strategy_and_validates_id() -> None:
    provider = StubProvider(json.dumps(valid_response()))
    finding = Finding(
        rule_id="python.security.test",
        file_path="app.py",
        start_line=2,
        end_line=2,
    )

    proposal = RepairAnalyzer(provider).generate(
        finding,
        {"lines": []},
        strategy=PromptStrategy.BASIC,
        target_relative_path="app.py",
    )

    assert proposal.vulnerability_id == "python.security.test"
    assert "python.security.test" in provider.prompt


def test_analyzer_rejects_response_for_another_finding() -> None:
    response = valid_response()
    response["vulnerability_id"] = "other.rule"
    analyzer = RepairAnalyzer(StubProvider(json.dumps(response)))

    with pytest.raises(RepairResponseError, match="does not match"):
        analyzer.generate(
            Finding(rule_id="python.security.test"),
            {},
            strategy=PromptStrategy.STRUCTURED,
            target_relative_path="app.py",
        )
