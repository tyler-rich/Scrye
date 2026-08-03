"""Bounded reading of multipart file uploads (API-4).

Reading an ``UploadFile`` with ``await file.read()`` materializes the whole body
in memory *before* any size check runs, so a hostile or accidental oversized
upload (a multi-GB "SBOM" or "backup") can exhaust memory. :func:`read_upload_capped`
rejects an over-limit upload up front — via the reported size when available, and
otherwise by reading in bounded chunks and stopping as soon as the cap is passed —
so at most ``max_bytes`` (plus one chunk) is ever held in memory.
"""

from __future__ import annotations

from fastapi import HTTPException, UploadFile, status

#: Read granularity when streaming an upload from its spool.
_CHUNK_BYTES = 1024 * 1024


async def read_upload_capped(file: UploadFile, max_bytes: int, *, what: str) -> bytes:
    """Read ``file`` into memory, rejecting once it exceeds ``max_bytes``.

    Args:
        file: The uploaded file.
        max_bytes: Maximum accepted size in bytes.
        what: Human label for the 413 message (e.g. ``"SBOM"``).

    Returns:
        The upload's bytes (at most ``max_bytes``).

    Raises:
        HTTPException: 413 if the upload exceeds ``max_bytes``.
    """
    limit_mib = max_bytes // (1024 * 1024)
    if file.size is not None and file.size > max_bytes:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"{what} exceeds the {limit_mib} MiB limit.",
        )
    buffer = bytearray()
    while True:
        chunk = await file.read(_CHUNK_BYTES)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            raise HTTPException(
                status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"{what} exceeds the {limit_mib} MiB limit.",
            )
    return bytes(buffer)
