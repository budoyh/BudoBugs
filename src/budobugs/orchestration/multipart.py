"""Deterministic, generated-only multipart fixtures for safe program experiments."""

from __future__ import annotations

import json

from budobugs.models.agentic import HarmlessMultipartUpload

_BOUNDARY = "----BudoBugsHarmlessMultipartV1"


def build_harmless_multipart(upload: HarmlessMultipartUpload) -> tuple[bytes, str]:
    """Build one small fixture body without reading a file or accepting external bytes."""

    if upload.fixture_kind == "text":
        fixture = f"BudoBugs harmless multipart fixture\nmarker={upload.marker}\n"
        content_type = "text/plain; charset=utf-8"
    else:
        fixture = json.dumps(
            {"fixture": "budobugs-harmless-multipart", "marker": upload.marker},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        content_type = "application/json"

    rows: list[bytes] = []
    for name, value in sorted(upload.form_fields.items()):
        rows.extend(
            (
                f"--{_BOUNDARY}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode("utf-8"),
                b"\r\n",
            )
        )
    rows.extend(
        (
            f"--{_BOUNDARY}\r\n".encode(),
            f'Content-Disposition: form-data; name="{upload.file_field}"; filename="{upload.filename}"\r\n'.encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            fixture.encode("utf-8"),
            b"\r\n",
            f"--{_BOUNDARY}--\r\n".encode(),
        )
    )
    body = b"".join(rows)
    if len(body) > 2048:
        raise ValueError("harmless multipart fixture exceeds the 2 KiB safety bound")
    return body, f"multipart/form-data; boundary={_BOUNDARY}"
