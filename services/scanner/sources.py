from __future__ import annotations

import os
import stat
from pathlib import Path

from pydantic import ValidationError

from donkit_guard.scanning.models import Snapshot, SourceFile

EXCLUDED = {
    ".git",
    ".ssh",
    ".aws",
    ".openhack",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".terraform",
}
EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".sql",
    ".md",
    ".html",
    ".css",
    ".sh",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".php",
    ".txt",
}


def snapshot_directory(path: Path) -> Snapshot:
    """Export text source, opening each file relative to a non-following directory fd."""
    files: list[SourceFile] = []
    size = 0
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Source root must be an existing directory, not a symlink")
    for root, directories, names, fd in os.fwalk(path, follow_symlinks=False):
        directories[:] = sorted(
            d for d in directories if d.lower() not in EXCLUDED and not Path(root, d).is_symlink()
        )
        for name in sorted(names):
            relative = str(Path(root, name).relative_to(path))
            if Path(name).suffix.lower() not in EXTENSIONS and name not in (
                "Dockerfile",
                "Makefile",
            ):
                continue
            try:
                SourceFile(path=relative, content="")
            except ValidationError:
                continue
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_size > 1_000_000:
                raise ValueError(f"Source file exceeds 1 MB: {relative}")
            source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(source_fd, "rb") as source:
                raw = source.read(1_000_001)
            if len(raw) > 1_000_000:
                raise ValueError("Source file changed while exporting")
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if "\x00" in content:
                continue
            size += len(raw)
            if size > 40_000_000 or len(files) >= 10_000:
                raise ValueError("Source snapshot exceeds scan limits")
            files.append(SourceFile(path=relative, content=content))
    return Snapshot(files=files)
