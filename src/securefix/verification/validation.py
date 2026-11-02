"""Combine patch, test, rescan, and source-integrity evidence into one status."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from securefix.verification.security_rescan import SecurityRescanResult
from securefix.verification.test_runner import FunctionalTestResult, TestExecutionStatus


class ValidationStatus(str, Enum):
    VALIDATED = "VALIDATED"
    FAILED_TESTS = "FAILED_TESTS"
    SECURITY_FINDING_REMAINS = "SECURITY_FINDING_REMAINS"
    NEW_SECURITY_FINDINGS = "NEW_SECURITY_FINDINGS"
    PATCH_APPLICATION_FAILED = "PATCH_APPLICATION_FAILED"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ValidationResult:
    status: ValidationStatus
    patch_applied: bool
    tests_passed: bool | None
    security_rescan_completed: bool
    original_finding_remains: bool | None
    new_findings_count: int | None
    original_source_preserved: bool | None
    reasons: list[str]
    tests: dict[str, Any] | None
    security: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


def validate_candidate(
    *,
    patch_applied: bool,
    tests: FunctionalTestResult | None,
    security: SecurityRescanResult | None,
    original_source_preserved: bool | None,
    patch_error: str | None = None,
) -> ValidationResult:
    reasons: list[str] = []
    tests_passed: bool | None = None

    if not patch_applied:
        reasons.append(patch_error or "Candidate patch was not applied to the isolated copy")
        status = ValidationStatus.PATCH_APPLICATION_FAILED
    else:
        status = ValidationStatus.INCONCLUSIVE

    if original_source_preserved is False:
        reasons.append("Original project integrity check detected a change")
        status = ValidationStatus.VALIDATION_ERROR
    elif original_source_preserved is None:
        reasons.append("Original project integrity could not be verified")

    if patch_applied and tests is None:
        reasons.append("Functional tests were not run")
    elif tests is not None:
        if tests.status == TestExecutionStatus.PASSED:
            tests_passed = True
        elif tests.status == TestExecutionStatus.FAILED:
            tests_passed = False
            reasons.append("One or more functional tests failed")
            status = ValidationStatus.FAILED_TESTS
        else:
            reasons.append(tests.error or f"Functional tests status: {tests.status}")
            status = ValidationStatus.VALIDATION_ERROR

    if security is None:
        reasons.append("Security rescan was not run")
    elif security.status != "COMPLETED" or security.scanner_errors:
        reasons.append(security.error or "Security rescan did not complete cleanly")
        if security.scanner_errors:
            reasons.append("Semgrep reported scanner errors")
        if status not in {
            ValidationStatus.PATCH_APPLICATION_FAILED,
            ValidationStatus.FAILED_TESTS,
            ValidationStatus.VALIDATION_ERROR,
        }:
            status = ValidationStatus.INCONCLUSIVE
    elif security.original_finding_remains:
        reasons.append("The selected original Semgrep finding remains")
        if status not in {ValidationStatus.PATCH_APPLICATION_FAILED, ValidationStatus.FAILED_TESTS}:
            status = ValidationStatus.SECURITY_FINDING_REMAINS
    elif security.introduced_findings:
        reasons.append("The security rescan found new findings")
        if status not in {ValidationStatus.PATCH_APPLICATION_FAILED, ValidationStatus.FAILED_TESTS}:
            status = ValidationStatus.NEW_SECURITY_FINDINGS

    if (
        patch_applied
        and tests_passed is True
        and security is not None
        and security.status == "COMPLETED"
        and not security.scanner_errors
        and security.original_finding_remains is False
        and not security.introduced_findings
        and original_source_preserved is True
    ):
        status = ValidationStatus.VALIDATED
        reasons = [
            "Patch applied in an isolated copy, tests passed, the selected finding "
            "was not rediscovered, no new findings were observed, and original-source "
            "integrity was preserved"
        ]
    elif status == ValidationStatus.INCONCLUSIVE and not reasons:
        reasons.append("Mandatory validation evidence is incomplete")

    return ValidationResult(
        status=status,
        patch_applied=patch_applied,
        tests_passed=tests_passed,
        security_rescan_completed=(
            security is not None
            and security.status == "COMPLETED"
            and not security.scanner_errors
        ),
        original_finding_remains=(
            security.original_finding_remains if security is not None else None
        ),
        new_findings_count=(
            len(security.introduced_findings)
            if security is not None and security.status == "COMPLETED"
            else None
        ),
        original_source_preserved=original_source_preserved,
        reasons=reasons,
        tests=tests.to_dict() if tests is not None else None,
        security=security.to_dict(include_scan_results=False) if security is not None else None,
    )
