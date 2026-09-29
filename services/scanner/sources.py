from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

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


@contextmanager
def source_root(path: Path) -> Iterator[int]:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Source root must be an absolute path without parent traversal")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def walk_error(error: OSError) -> None:
    raise error


def snapshot_directory(path: Path) -> Snapshot:
    """Export text source, opening each file relative to a non-following directory fd."""
    with source_root(path) as root_fd:
        return capture_directory(root_fd)


def capture_directory(root_fd: int) -> Snapshot:
    files: list[SourceFile] = []
    size = 0
    for root, directories, names, fd in os.fwalk(
        ".", dir_fd=root_fd, follow_symlinks=False, onerror=walk_error
    ):
        directories[:] = sorted(
            d
            for d in directories
            if d.lower() not in EXCLUDED
            and not stat.S_ISLNK(os.stat(d, dir_fd=fd, follow_symlinks=False).st_mode)
        )
        for name in sorted(names):
            relative = str(Path(root, name))
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
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ValueError("Source was replaced by a non-regular file")
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
