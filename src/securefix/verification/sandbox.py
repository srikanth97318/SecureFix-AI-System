"""Bubblewrap-backed namespace sandbox for running untrusted project tests."""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from securefix.sanitization import redact_sensitive_text


class SandboxUnavailableError(RuntimeError):
    """Raised when a real OS sandbox cannot be established."""


@dataclass(frozen=True)
class SandboxResult:
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    output_truncated: bool
    sandbox: str


class BubblewrapSandbox:
    """Run commands with read-only host mounts, no network, and a writable copy only."""

    def __init__(
        self,
        *,
        executable: str = "bwrap",
        output_limit_bytes: int = 2_000_000,
        memory_limit_bytes: int = 2_147_483_648,
        cpu_limit_seconds: int = 180,
        process_limit: int = 256,
        file_limit_bytes: int = 100_000_000,
    ) -> None:
        if min(
            output_limit_bytes,
            memory_limit_bytes,
            cpu_limit_seconds,
            process_limit,
            file_limit_bytes,
        ) <= 0:
            raise ValueError("Sandbox resource limits must be positive")
        self.executable = shutil.which(executable)
        if self.executable is None:
            raise SandboxUnavailableError(
                "Bubblewrap is required to safely execute project tests; "
                "install bwrap with working user and network namespaces."
            )
        self.output_limit_bytes = output_limit_bytes
        self.memory_limit_bytes = memory_limit_bytes
        self.cpu_limit_seconds = cpu_limit_seconds
        self.process_limit = process_limit
        self.file_limit_bytes = file_limit_bytes

    def run(
        self,
        command: Sequence[str],
        *,
        working_copy: str | Path,
        timeout_seconds: int,
    ) -> SandboxResult:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if not command or any(not isinstance(argument, str) for argument in command):
            raise ValueError("Sandbox command must be a non-empty sequence of strings")

        copy_root = Path(working_copy).resolve(strict=True)
        if not copy_root.is_dir():
            raise ValueError("Sandbox working copy must be a directory")

        bwrap_command = self._build_command(command, copy_root)
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
        started = time.monotonic()
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                process = subprocess.Popen(
                    bwrap_command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    close_fds=True,
                    env=environment,
                    shell=False,
                    start_new_session=True,
                    preexec_fn=self._apply_resource_limits,
                )
            except OSError as exc:
                raise SandboxUnavailableError(
                    "Unable to start the Bubblewrap sandbox."
                ) from None

            timed_out = False
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill_process_group(process)
                process.wait()

            duration = time.monotonic() - started
            stdout, stdout_truncated = self._read_limited(stdout_file)
            stderr, stderr_truncated = self._read_limited(stderr_file)

        return SandboxResult(
            command=list(command),
            returncode=process.returncode,
            stdout=redact_sensitive_text(stdout),
            stderr=redact_sensitive_text(stderr),
            timed_out=timed_out,
            duration_seconds=duration,
            output_truncated=stdout_truncated or stderr_truncated,
            sandbox="bubblewrap (user, PID, IPC, UTS, and network namespaces; "
            "host filesystem read-only; working copy writable; resource limits)",
        )

    def _build_command(self, command: Sequence[str], copy_root: Path) -> list[str]:
        arguments = [
            self.executable,
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/usr",
            "/usr",
        ]
        for system_path in ("/bin", "/lib", "/lib64"):
            if Path(system_path).exists():
                arguments.extend(["--ro-bind", system_path, system_path])

        exposed_paths = self._python_import_paths(copy_root)
        for import_path in exposed_paths:
            for parent in reversed(import_path.parents):
                if str(parent) in {"/", "/usr", "/bin", "/lib", "/lib64"}:
                    continue
                arguments.extend(["--dir", str(parent)])
            arguments.extend(["--ro-bind", str(import_path), str(import_path)])

        arguments.extend(
            [
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/workspace",
                "--bind",
                str(copy_root),
                "/workspace",
                "--chdir",
                "/workspace",
                "--clearenv",
            ]
        )
        for name, value in (
            ("HOME", "/tmp"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C.UTF-8"),
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1"),
            ("PYTHONPATH", os.pathsep.join(map(str, self._python_import_paths(copy_root)))),
            ("TMPDIR", "/tmp"),
        ):
            arguments.extend(["--setenv", name, value])
        arguments.extend(command)
        return arguments

    @staticmethod
    def _python_import_paths(copy_root: Path) -> list[Path]:
        paths: set[Path] = set()
        for entry in sys.path:
            if not entry:
                continue
            candidate = Path(entry)
            if not candidate.is_absolute() or not candidate.is_dir():
                continue
            resolved = candidate.resolve()
            if resolved == Path("/") or resolved.is_relative_to(copy_root):
                continue
            is_package_directory = resolved.name in {"site-packages", "dist-packages"}
            if (
                any(
                    resolved.is_relative_to(parent)
                    for parent in (Path("/workspaces"), Path("/tmp"))
                )
                and not is_package_directory
            ):
                continue
            if resolved == Path("/usr") or resolved.is_relative_to(Path("/usr")):
                continue
            paths.add(resolved)
        return sorted(paths, key=lambda path: (len(path.parts), str(path)))

    def _apply_resource_limits(self) -> None:
        resource.setrlimit(
            resource.RLIMIT_AS,
            (self.memory_limit_bytes, self.memory_limit_bytes),
        )
        resource.setrlimit(
            resource.RLIMIT_CPU,
            (self.cpu_limit_seconds, self.cpu_limit_seconds + 1),
        )
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (self.file_limit_bytes, self.file_limit_bytes),
        )
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (128, 128),
        )
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(
                resource.RLIMIT_NPROC,
                (self.process_limit, self.process_limit),
            )

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _read_limited(self, stream: tempfile.TemporaryFile) -> tuple[str, bool]:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        truncated = size > self.output_limit_bytes
        if truncated:
            stream.seek(-self.output_limit_bytes, os.SEEK_END)
            prefix = "[Earlier output truncated]\n"
        else:
            stream.seek(0)
            prefix = ""
        content = stream.read(self.output_limit_bytes).decode("utf-8", errors="replace")
        return prefix + content, truncated
