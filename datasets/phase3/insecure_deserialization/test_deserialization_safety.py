import ast
import importlib.util
import json
from pathlib import Path

import pytest


def _load_app():
    app_path = Path(__file__).with_name("app.py")
    spec = importlib.util.spec_from_file_location("deserialization_app", app_path)
    assert spec is not None and spec.loader is not None
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


def test_untrusted_data_does_not_use_pickle():
    tree = ast.parse(Path(__file__).with_name("app.py").read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
    ]

    assert any(
        node.func.value.id == "json" and node.func.attr == "loads"
        for node in calls
    )
    assert not any(
        node.func.value.id == "pickle" for node in calls
    )


def test_normal_json_record_is_loaded():
    app = _load_app()

    assert app.load_record('{"name": "Alice"}') == {"name": "Alice"}


def test_pickle_payload_is_rejected_without_side_effect(tmp_path: Path):
    app = _load_app()
    marker = tmp_path / "pickle-side-effect"
    payload = (
        b"cposix\nmkdir\np0\n(V"
        + str(marker).encode("utf-8")
        + b"\np1\ntp2\nRp3\n."
    )
    try:
        with pytest.raises((json.JSONDecodeError, TypeError, UnicodeError)):
            app.load_record(payload)
    finally:
        assert not marker.exists()
