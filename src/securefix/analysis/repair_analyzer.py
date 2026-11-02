"""Generate and validate structured repair proposals from a provider."""

from __future__ import annotations

import json
from typing import Any, Protocol

from securefix.llm.prompts import PromptStrategy, build_prompt
from securefix.models import Finding, RepairProposal, RepairResponseError
from securefix.sanitization import redact_nested


class TextGenerationProvider(Protocol):
    def generate(self, prompt: str) -> str: ...


class RepairAnalyzer:
    def __init__(self, provider: TextGenerationProvider) -> None:
        self.provider = provider

    def generate(
        self,
        finding: Finding,
        context: dict[str, Any],
        *,
        strategy: PromptStrategy | str,
        target_relative_path: str,
        previous_repair: str | None = None,
        validation_failure: str | None = None,
    ) -> RepairProposal:
        prompt = build_prompt(
            strategy,
            finding,
            context,
            target_relative_path=target_relative_path,
            previous_repair=previous_repair,
            validation_failure=validation_failure,
        )
        response = self.provider.generate(prompt)
        proposal = RepairProposal.from_json(response)
        expected_id = finding.rule_id or "unknown"
        if proposal.vulnerability_id != expected_id:
            raise RepairResponseError(
                "LLM response vulnerability_id does not match the selected finding"
            )
        return _redact_proposal(proposal)


def _redact_proposal(proposal: RepairProposal) -> RepairProposal:
    """Redact common credential patterns from model-authored report fields."""
    data = redact_nested(proposal.to_dict())
    return RepairProposal.from_json(json.dumps(data))
