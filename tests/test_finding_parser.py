from __future__ import annotations

import json

import pytest

from securefix.detection import parse_findings
from securefix.models import Finding


def test_parse_finding_and_serialize_json() -> None:
    results = {
        "results": [
            {
                "check_id": "python.security.test",
                "path": "app.py",
                "start": {"line": 7, "col": 1},
                "end": {"line": 8, "col": 2},
                "extra": {
                    "message": "Potential issue",
                    "severity": "ERROR",
                    "lines": "dangerous_call()",
                    "metadata": {"category": "security", "cwe": ["CWE-89"]},
                    "fingerprint": "abc123",
                },
            }
        ]
    }

    finding = parse_findings(results)[0]
    encoded = json.dumps(finding.to_dict())

    assert json.loads(encoded) == {
        "rule_id": "python.security.test",
        "category": "security",
        "severity": "ERROR",
        "file_path": "app.py",
        "start_line": 7,
        "end_line": 8,
        "message": "Potential issue",
        "matched_code": "dangerous_call()",
        "scanner_metadata": {
            "metadata": {"category": "security", "cwe": ["CWE-89"]},
            "fingerprint": "abc123",
        },
    }


def test_missing_scanner_fields_are_not_invented() -> None:
    finding = parse_findings({"results": [{"extra": {}}]})[0]

    assert finding == Finding()


def test_multiple_findings_are_preserved() -> None:
    findings = parse_findings(
        {"results": [{"check_id": "one"}, {"check_id": "two"}]}
    )

    assert [finding.rule_id for finding in findings] == ["one", "two"]


def test_parser_rejects_malformed_results() -> None:
    with pytest.raises(ValueError, match="missing the 'results' field"):
        parse_findings({})
    with pytest.raises(ValueError, match="must be a list"):
        parse_findings({"results": {}})
    with pytest.raises(ValueError, match="must be an object"):
        parse_findings({"results": [None]})


def test_parser_redacts_secret_values() -> None:
    finding = parse_findings(
        {
            "results": [
                {
                    "extra": {
                        "message": "api_key='sample-secret-value'",
                        "lines": "password = 'sample-secret-value'",
                    }
                }
            ]
        }
    )[0]

    assert "sample-secret-value" not in (finding.message or "")
    assert "sample-secret-value" not in (finding.matched_code or "")


def test_parser_does_not_expose_matched_code_from_sensitive_files() -> None:
    finding = parse_findings(
        {
            "results": [
                {
                    "path": "config/.env",
                    "extra": {"lines": "UNRECOGNIZED_SECRET_VALUE"},
                }
            ]
        }
    )[0]

    assert finding.matched_code is None
