from __future__ import annotations

from pathlib import Path

import pytest

from securefix.models import (
    Finding,
    RepairAnalysis,
    RepairChange,
    RepairDetails,
    RepairProposal,
)
from securefix.patching import PatchManager, PatchSaveError, PatchValidationError


def _proposal(
    *,
    file_path: str = "app.py",
    start_line: int = 2,
    end_line: int = 2,
    original_code: str = "    eval(value)",
    replacement_code: str = "    int(value)",
) -> RepairProposal:
    return RepairProposal(
        vulnerability_id="rule.test",
        analysis=RepairAnalysis(
            vulnerability_type="unsafe evaluation",
            explanation="A shown call evaluates the supplied value.",
            security_impact="May execute unintended code.",
            assumptions=[],
        ),
        repair=RepairDetails(
            summary="Restrict the conversion.",
            file_path=file_path,
            changes=[
                RepairChange(
                    start_line=start_line,
                    end_line=end_line,
                    original_code=original_code,
                    replacement_code=replacement_code,
                )
            ],
        ),
        reasoning_summary="Limits evaluation.",
        limitations=[],
    )


def _prepare(target: Path, proposal: RepairProposal | None = None):
    source = target / "app.py"
    source.write_text("def run(value):\n    eval(value)\n    return True\n", encoding="utf-8")
    finding = Finding(
        rule_id="rule.test",
        file_path="app.py",
        start_line=2,
        end_line=2,
    )
    return PatchManager().prepare(
        target,
        finding,
        proposal or _proposal(),
        context_start_line=1,
        context_end_line=3,
    )


def test_patch_manager_generates_reviewable_diff_without_modifying_source(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    original = "def run(value):\n    eval(value)\n    return True\n"
    source.write_text(original, encoding="utf-8")

    candidate = _prepare(target)

    assert source.read_text(encoding="utf-8") == original
    assert "    eval(value)" in candidate.original_source
    assert "    int(value)" in candidate.candidate_source
    assert "--- a/app.py" in candidate.unified_diff
    assert "+++ b/app.py" in candidate.unified_diff


@pytest.mark.parametrize(
    "proposal",
    [
        _proposal(file_path="../outside.py"),
        _proposal(file_path="/tmp/outside.py"),
        _proposal(file_path="other.py"),
        _proposal(start_line=3, end_line=2),
        _proposal(start_line=3, end_line=4, original_code="    return True\nextra"),
        _proposal(start_line=1, end_line=1, original_code="wrong source"),
    ],
)
def test_patch_manager_rejects_unsafe_paths_and_ranges(
    tmp_path: Path,
    proposal: RepairProposal,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    _prepare_source = target / "app.py"
    _prepare_source.write_text(
        "def run(value):\n    eval(value)\n    return True\n",
        encoding="utf-8",
    )
    finding = Finding(
        rule_id="rule.test",
        file_path="app.py",
        start_line=2,
        end_line=2,
    )

    with pytest.raises(PatchValidationError):
        PatchManager().prepare(
            target,
            finding,
            proposal,
            context_start_line=1,
            context_end_line=3,
        )


def test_patch_manager_rejects_traversal_in_finding_path(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "outside.py").write_text("dangerous()\n", encoding="utf-8")
    finding = Finding(rule_id="rule.test", file_path="../outside.py", start_line=1, end_line=1)

    with pytest.raises(PatchValidationError, match="outside"):
        PatchManager().prepare(
            target,
            finding,
            _proposal(file_path="outside.py", start_line=1, end_line=1, original_code="dangerous()"),
            context_start_line=1,
            context_end_line=1,
        )


def test_patch_manager_saves_json_and_diff_exclusively_outside_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    original = "def run(value):\n    eval(value)\n    return True\n"
    source.write_text(original, encoding="utf-8")
    candidate = _prepare(target)
    proposal_path = tmp_path / "proposals" / "proposal.json"
    diff_path = tmp_path / "proposals" / "proposal.diff"

    saved_proposal, saved_diff = PatchManager().save(
        candidate, target, proposal_path, diff_path
    )

    assert saved_proposal.exists() and saved_diff.exists()
    assert "unified_diff" in saved_proposal.read_text(encoding="utf-8")
    assert saved_diff.read_text(encoding="utf-8") == candidate.unified_diff
    assert source.read_text(encoding="utf-8") == original
    with pytest.raises(PatchSaveError, match="overwrite"):
        PatchManager().save(candidate, target, proposal_path, diff_path)


def test_patch_manager_refuses_outputs_inside_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    candidate = _prepare(target)

    with pytest.raises(PatchSaveError, match="outside"):
        PatchManager().save(
            candidate,
            target,
            target / "proposal.json",
            tmp_path / "proposal.diff",
        )
