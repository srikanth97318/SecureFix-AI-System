import ast
import importlib.util
from html import escape
from pathlib import Path


def _load_app():
    app_path = Path(__file__).with_name("app.py")
    spec = importlib.util.spec_from_file_location("xss_app", app_path)
    assert spec is not None and spec.loader is not None
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


def test_xss_output_escapes_untrusted_text():
    tree = ast.parse(Path(__file__).with_name("app.py").read_text(encoding="utf-8"))
    escaped_interpolations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        escaped_interpolations.extend(
            value
            for value in node.values
            if isinstance(value, ast.FormattedValue)
            and isinstance(value.value, ast.Call)
            and isinstance(value.value.func, ast.Attribute)
            and value.value.func.attr == "escape"
        )

    assert escaped_interpolations


def test_normal_greeting_remains_unchanged():
    app = _load_app()

    assert app.render_greeting("Alice") == "<p>Alice</p>"


def test_script_markup_is_rendered_as_text():
    app = _load_app()
    payload = "<script>alert('xss')</script>"

    rendered = app.render_greeting(payload)

    assert rendered == f"<p>{escape(payload)}</p>"
    assert "<script>" not in rendered
