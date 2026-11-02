"""Safe subprocess integration for the Semgrep CLI."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from securefix.sanitization import redact_sensitive_text


INSTALLATION_INSTRUCTIONS = (
    "Semgrep was not found. Install it with `python -m pip install semgrep` "
    "or follow https://semgrep.dev/docs/getting-started/."
)


class SemgrepError(RuntimeError):
    """Base error for Semgrep scan failures."""


class SemgrepNotFoundError(SemgrepError):
    """Raised when the Semgrep executable is unavailable."""


class ScannerExecutionError(SemgrepError):
    """Raised when Semgrep exits unsuccessfully or returns invalid JSON."""


class ScannerTimeoutError(SemgrepError):
    """Raised when a Semgrep scan exceeds its configured timeout."""


class SemgrepScanner:
    def __init__(
        self,
        config: str | Sequence[str] = "auto",
        timeout_seconds: int = 120,
        executable: str = "semgrep",
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        configs = [config] if isinstance(config, str) else list(config)
        if not configs or any(not item for item in configs):
            raise ValueError("At least one non-empty Semgrep configuration is required")
        self.config = config
        self.configs = configs
        self.timeout_seconds = timeout_seconds
        self.executable = executable

    def scan(self, target: str | Path) -> dict[str, Any]:
        """Run Semgrep and return its decoded JSON document."""
        target_path = Path(target).resolve()
        if not target_path.is_dir():
            raise ValueError(f"Scan target is not a directory: {target_path}")

        executable_path = shutil.which(self.executable)
        if executable_path is None:
            raise SemgrepNotFoundError(INSTALLATION_INSTRUCTIONS)

        command = [
            executable_path,
            "scan",
            *(
                argument
                for config in self.configs
                for argument in ("--config", config)
            ),
            "--json",
            "--quiet",
            "--metrics=off",
            str(target_path),
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                f"Semgrep scan exceeded the {self.timeout_seconds}-second timeout"
            ) from exc
        except OSError as exc:
            raise ScannerExecutionError(
                f"Unable to execute Semgrep: {redact_sensitive_text(str(exc))}"
            ) from exc

        if completed.returncode != 0:
            details = redact_sensitive_text(completed.stderr.strip())
            message = f"Semgrep exited with status {completed.returncode}"
            if details:
                message = f"{message}: {details}"
            raise ScannerExecutionError(message)

        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError(
                f"Semgrep returned invalid JSON at line {exc.lineno}, column {exc.colno}"
            ) from exc
        if not isinstance(result, dict):
            raise ScannerExecutionError("Semgrep JSON output must be an object")
        return result
