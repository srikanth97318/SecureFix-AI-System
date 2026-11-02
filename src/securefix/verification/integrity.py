"""Read-only fingerprints for checking that the original project stayed untouched."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any


def snapshot_tree(root: str | Path) -> dict[str, str]:
    project = Path(root).resolve(strict=True)
    if not project.is_dir():
        raise ValueError("Integrity snapshot target must be a directory")
    snapshot: dict[str, str] = {}
    for current, directories, filenames in os.walk(project, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories if name not in {".git", "__pycache__", ".pytest_cache"}
        )
        for name in sorted(directories + filenames):
            path = current_path / name
            relative = path.relative_to(project).as_posix()
            if path.is_symlink():
                snapshot[relative] = "symlink:" + os.readlink(path)
                continue
            if not path.is_file():
                continue
            digest = hashlib.sha256()
            with path.open("rb") as source_file:
                for block in iter(lambda: source_file.read(1024 * 1024), b""):
                    digest.update(block)
            snapshot[relative] = digest.hexdigest()
    return snapshot


def verify_tree_snapshot(
    root: str | Path,
    original: dict[str, str],
) -> dict[str, Any]:
    try:
        current = snapshot_tree(root)
    except (OSError, ValueError) as exc:
        return {
            "preserved": None,
            "changed_files": [],
            "error": "Unable to verify original project integrity.",
        }
    changed = sorted(
        path
        for path in original.keys() | current.keys()
        if original.get(path) != current.get(path)
    )
    return {
        "preserved": not changed,
        "changed_files": changed,
        "error": None,
    }
