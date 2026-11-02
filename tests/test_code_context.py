from __future__ import annotations

from pathlib import Path

import pytest

from securefix.context import collect_context


def test_collect_context_preserves_line_numbers_and_bounds(tmp_path: Path) -> None:
    source = tmp_path / "module.py"
    source.write_text("one\ntwo\nthree\nfour\nfive\n", encoding="utf-8")

    context = collect_context(tmp_path, "module.py", 3, 3, surrounding_lines=1)

    assert context.start_line == 2
    assert context.end_line == 4
    assert [(line.line_number, line.content) for line in context.lines] == [
        (2, "two"),
        (3, "three"),
        (4, "four"),
    ]


def test_collect_context_handles_empty_file(tmp_path: Path) -> None:
    (tmp_path / "empty.py").write_text("", encoding="utf-8")

    context = collect_context(tmp_path, "empty.py", 1, 1)

    assert context.start_line == 1
    assert context.end_line == 0
    assert context.lines == []


def test_context_rejects_traversal_and_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1", encoding="utf-8")
    (root / "link.py").symlink_to(outside)

    with pytest.raises(ValueError, match="outside"):
        collect_context(root, "../outside.py", 1, 1)
    with pytest.raises(ValueError, match="outside"):
        collect_context(root, "link.py", 1, 1)


def test_context_resolves_semgrep_path_relative_to_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "examples"
    root.mkdir()
    (root / "app.py").write_text("vulnerable()\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    context = collect_context(root, "examples/app.py", 1, 1)

    assert context.lines[0].content == "vulnerable()"


def test_context_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        collect_context(tmp_path, "missing.py", 1, 1)


def test_context_rejects_directory_with_source_extension(tmp_path: Path) -> None:
    (tmp_path / "module.py").mkdir()

    with pytest.raises(ValueError, match="not a regular file"):
        collect_context(tmp_path, "module.py", 1, 1)


def test_context_rejects_sensitive_and_non_source_files(tmp_path: Path) -> None:
    (tmp_path / "credentials.py").write_text("value = 1", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("value", encoding="utf-8")

    with pytest.raises(ValueError, match="sensitive or non-source"):
        collect_context(tmp_path, "credentials.py", 1, 1)
    with pytest.raises(ValueError, match="sensitive or non-source"):
        collect_context(tmp_path, "notes.txt", 1, 1)


def test_context_redacts_common_credentials(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "api_key = 'sample-secret-value'\n", encoding="utf-8"
    )

    context = collect_context(tmp_path, "config.py", 1, 1)

    assert "sample-secret-value" not in context.lines[0].content
    assert "[REDACTED]" in context.lines[0].content


def test_context_reports_encoding_errors(tmp_path: Path) -> None:
    (tmp_path / "invalid.py").write_bytes(b"\xff")

    with pytest.raises(ValueError, match="valid UTF-8"):
        collect_context(tmp_path, "invalid.py", 1, 1)


def test_context_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        collect_context(tmp_path, "missing.py", 1, 1)
