import ast
import importlib.util
from pathlib import Path


def _load_app():
    app_path = Path(__file__).with_name("app.py")
    spec = importlib.util.spec_from_file_location("hardcoded_key_app", app_path)
    assert spec is not None and spec.loader is not None
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


def test_api_key_comes_from_a_runtime_source():
    tree = ast.parse(Path(__file__).with_name("app.py").read_text(encoding="utf-8"))
    environment_lookups = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"get", "getenv"}
        and (
            isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "environ"
            or isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        )
    ]

    assert environment_lookups


def test_key_matching_uses_the_runtime_environment(monkeypatch):
    app = _load_app()
    monkeypatch.setenv("API_KEY", "runtime-test-key")

    assert app.has_api_key("runtime-test-key")
    assert not app.has_api_key("dummy-example-key-not-a-real-credential")
