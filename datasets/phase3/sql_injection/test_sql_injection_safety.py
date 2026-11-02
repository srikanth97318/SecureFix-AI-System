import ast
import importlib.util
import sqlite3
from pathlib import Path


def _load_app():
    app_path = Path(__file__).with_name("app.py")
    spec = importlib.util.spec_from_file_location("sql_injection_app", app_path)
    assert spec is not None and spec.loader is not None
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


def _database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE users (name TEXT NOT NULL, password TEXT NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO users (name, password) VALUES (?, ?)",
        [("alice", "alice-secret"), ("bob", "bob-secret")],
    )
    return connection


def test_sql_query_uses_parameter_binding():
    tree = ast.parse(Path(__file__).with_name("app.py").read_text(encoding="utf-8"))
    execute_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
    ]

    assert execute_calls
    assert all(len(call.args) >= 2 for call in execute_calls)


def test_normal_user_query_returns_only_the_matching_user():
    app = _load_app()
    connection = _database()

    try:
        rows = app.find_user(connection.cursor(), "alice")
    finally:
        connection.close()

    assert rows == [("alice", "alice-secret")]


def test_tautology_and_authentication_bypass_inputs_do_not_return_users():
    app = _load_app()
    connection = _database()
    payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
    ]

    try:
        results = [
            app.find_user(connection.cursor(), payload)
            for payload in payloads
        ]
    finally:
        connection.close()

    assert results == [[], []]


def test_execute_receives_query_and_bound_user_value():
    app = _load_app()
    connection = _database()
    executed = []

    class RecordingCursor:
        def __init__(self):
            self.cursor = connection.cursor()

        def execute(self, query, parameters=()):
            executed.append((query, parameters))
            self.cursor.execute(query, parameters)
            return self

        def fetchall(self):
            return self.cursor.fetchall()

    try:
        rows = app.find_user(RecordingCursor(), "alice")
    finally:
        connection.close()

    assert rows == [("alice", "alice-secret")]
    assert len(executed) == 1
    query, parameters = executed[0]
    assert "alice" not in query
    assert parameters == ("alice",)
