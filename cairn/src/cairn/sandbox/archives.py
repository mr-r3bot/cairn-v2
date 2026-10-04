"""Build in-memory tar archives for `docker put_archive`.

Mirrors the dispatcher's ContainerManager helper so the sandbox package
stays self-contained (it must be usable without the dispatcher).
"""

from __future__ import annotations

import io
import tarfile
from pathlib import PurePosixPath


def text_file_archive(path: str, content: str, mode: int = 0o644) -> tuple[str, bytes]:
    """Return (put_archive_dir, tar_bytes) placing `content` at container `path`."""
    target = PurePosixPath(path)
    if not target.is_absolute() or target.name in ("", ".", ".."):
        raise ValueError(f"container file path must be absolute: {path}")
    parts = target.parts[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"invalid container file path: {path}")

    if len(parts) == 1:
        archive_dir = "/"
        archive_parts = parts
    else:
        archive_dir = f"/{parts[0]}"
        archive_parts = parts[1:]

    payload = content.encode("utf-8")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        parent = ""
        for part in archive_parts[:-1]:
            parent = f"{parent}/{part}" if parent else part
            info = tarfile.TarInfo(parent)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)

        file_name = "/".join(archive_parts)
        info = tarfile.TarInfo(file_name)
        info.size = len(payload)
        info.mode = mode
        archive.addfile(info, io.BytesIO(payload))
    return archive_dir, stream.getvalue()
