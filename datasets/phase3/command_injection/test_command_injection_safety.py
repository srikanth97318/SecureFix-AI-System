import ast
import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest


def _load_app():
    app_path = Path(__file__).with_name("app.py")
    spec = importlib.util.spec_from_file_location("command_injection_app", app_path)
    assert spec is not None and spec.loader is not None
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


def test_command_uses_arguments_without_shell():
    tree = ast.parse(Path(__file__).with_name("app.py").read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]

    assert calls
    for call in calls:
        arguments = call.args[0]
        if isinstance(arguments, ast.Name):
            assignments = [
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == arguments.id
                    for target in node.targets
                )
            ]
            assert assignments
            arguments = assignments[-1]
        assert isinstance(arguments, (ast.List, ast.Tuple))
        assert not any(
            keyword.arg == "shell"
            and not (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
            )
            for keyword in call.keywords
        )


@pytest.mark.parametrize(
    "directory",
    [
        "/tmp/securefix; echo secondary",
        "/tmp/securefix$(echo secondary)",
        "/tmp/securefix directory",
        "/tmp/securefix 'quoted'",
        "/tmp/securefix && echo secondary",
        "/tmp/securefix | echo secondary",
    ],
)
def test_directory_is_one_argument_and_shell_is_disabled(
    directory: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _load_app()
    run = Mock(
        return_value=subprocess.CompletedProcess(
            args=["ls", directory],
            returncode=0,
            stdout="entry.txt\n",
            stderr="",
        )
    )
    monkeypatch.setattr(app.subprocess, "run", run)

    app.list_files(directory)

    run.assert_called_once()
    command = run.call_args.args[0]
    assert isinstance(command, (list, tuple))
    assert list(command) == ["ls", directory]
    assert command[1] == directory
    assert run.call_args.kwargs.get("shell", False) is False


@pytest.mark.parametrize(
    "payload",
    [
        "{missing}; touch {marker}",
        "{missing}$(touch {marker})",
        "{missing} '' ; touch {marker}; #",
        "{missing} || touch {marker}",
    ],
    ids=["semicolon", "command-substitution", "quotes", "shell-metacharacters"],
)
def test_injection_payloads_do_not_execute_secondary_commands(
    payload: str,
    tmp_path: Path,
) -> None:
    app = _load_app()
    missing_directory = tmp_path / "not-a-real-directory"
    marker = tmp_path / "secondary-command-marker"
    directory = payload.format(missing=missing_directory, marker=marker)
    try:
        app.list_files(directory)
    except subprocess.CalledProcessError:
        pass

    assert not marker.exists(), f"secondary command ran for payload {payload!r}"


def test_lists_files_from_a_normal_directory(tmp_path: Path) -> None:
    app = _load_app()
    directory = tmp_path / "normal"
    directory.mkdir()
    (directory / "alpha.txt").write_text("alpha", encoding="utf-8")
    (directory / "beta.txt").write_text("beta", encoding="utf-8")

    result = app.list_files(str(directory))

    assert set(result.stdout.splitlines()) == {"alpha.txt", "beta.txt"}


def test_lists_files_from_a_directory_with_spaces(tmp_path: Path) -> None:
    app = _load_app()
    directory = tmp_path / "directory with spaces"
    directory.mkdir()
    (directory / "entry.txt").write_text("entry", encoding="utf-8")

    result = app.list_files(str(directory))

    assert result.stdout.splitlines() == ["entry.txt"]
