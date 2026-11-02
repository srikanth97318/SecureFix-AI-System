"""Execute the copied project's pytest suite inside Bubblewrap."""

from __future__ import annotations

import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from securefix.verification.sandbox import BubblewrapSandbox, SandboxUnavailableError


class TestExecutionStatus:
    PASSED = "PASSED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    EXECUTION_ERROR = "EXECUTION_ERROR"


@dataclass(frozen=True)
class FunctionalTestResult:
    status: str
    exit_code: int | None
    passed: int | None
    failed: int | None
    skipped: int | None
    stdout: str
    stderr: str
    duration_seconds: float | None
    timed_out: bool
    output_truncated: bool
    error: str | None
    sandbox: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class PytestRunner:
    def __init__(
        self,
        sandbox: BubblewrapSandbox | None = None,
        *,
        timeout_seconds: int = 180,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = timeout_seconds
        self.sandbox = sandbox

    def run(self, working_copy: str | Path) -> FunctionalTestResult:
        try:
            sandbox = self.sandbox or BubblewrapSandbox()
            result = sandbox.run(
                [str(Path(sys.executable).resolve()), "-m", "pytest", "-q"],
                working_copy=working_copy,
                timeout_seconds=self.timeout_seconds,
            )
        except SandboxUnavailableError as exc:
            return FunctionalTestResult(
                status=TestExecutionStatus.EXECUTION_ERROR,
                exit_code=None,
                passed=None,
                failed=None,
                skipped=None,
                stdout="",
                stderr="",
                duration_seconds=None,
                timed_out=False,
                output_truncated=False,
                error=str(exc),
                sandbox=None,
            )
        except (OSError, ValueError) as exc:
            return FunctionalTestResult(
                status=TestExecutionStatus.EXECUTION_ERROR,
                exit_code=None,
                passed=None,
                failed=None,
                skipped=None,
                stdout="",
                stderr="",
                duration_seconds=None,
                timed_out=False,
                output_truncated=False,
                error="Unable to start isolated pytest execution.",
                sandbox=None,
            )

        passed, failed, skipped = _parse_summary(result.stdout)
        if result.timed_out:
            status = TestExecutionStatus.TIMED_OUT
            error = f"pytest exceeded the {self.timeout_seconds}-second timeout"
        elif result.returncode == 0:
            status = TestExecutionStatus.PASSED
            error = None
        elif result.returncode == 1 and failed is not None:
            status = TestExecutionStatus.FAILED
            error = None
        else:
            status = TestExecutionStatus.EXECUTION_ERROR
            missing_module = re.search(
                r"ModuleNotFoundError: No module named ['\"]([^'\"]+)['\"]",
                result.stderr,
            )
            if missing_module:
                error = (
                    "Python dependency "
                    f"{missing_module.group(1)!r} is unavailable during pytest execution"
                )
            elif result.returncode == 2:
                error = "pytest could not collect or execute the test suite"
            else:
                error = (
                    f"pytest exited with status {result.returncode} "
                    "without a test summary"
                )

        return FunctionalTestResult(
            status=status,
            exit_code=result.returncode,
            passed=passed,
            failed=failed,
            skipped=skipped,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_seconds=result.duration_seconds,
            timed_out=result.timed_out,
            output_truncated=result.output_truncated,
            error=error,
            sandbox=result.sandbox,
        )


def _parse_summary(output: str) -> tuple[int | None, int | None, int | None]:
    matches = list(re.finditer(r"(?m)^\s*(.+?)\s+in\s+[\d.]+s\s*$", output))
    for match in reversed(matches):
        counts = {"passed": 0, "failed": 0, "skipped": 0}
        parsed_counts = re.findall(
            r"\b(\d+)\s+(passed|failed|skipped)\b",
            match.group(1),
        )
        if not parsed_counts:
            continue
        for count, outcome in parsed_counts:
            counts[outcome] += int(count)
        return counts["passed"], counts["failed"], counts["skipped"]
    return None, None, None
