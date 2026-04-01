from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DiffFile:
    path: str
    patch: str


def split_diff(diff_text: str) -> list[DiffFile]:
    files: list[DiffFile] = []
    current_path: str | None = None
    buffer: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_path is not None:
                files.append(DiffFile(path=current_path, patch="\n".join(buffer).strip()))
            buffer = [line]
            current_path = _extract_path(line)
            continue
        if current_path is not None:
            buffer.append(line)

    if current_path is not None:
        files.append(DiffFile(path=current_path, patch="\n".join(buffer).strip()))

    return files


def _extract_path(diff_header: str) -> str:
    # diff header format: "diff --git a/foo.py b/foo.py"
    parts = diff_header.split()
    if len(parts) < 4:
        return "unknown"
    path = parts[3]
    if path.startswith("b/"):
        return path[2:]
    return path
