"""Offline demo: a split-across-chunks form fed to the dual-sink recorder.

No network service is opened. The multipart body is built in memory and
handed to the parser in fixed-size transport chunks, including chunks that
split a single field value across several writes. Run with::

    python -m examples.dual_sink_upload.demo
"""

from __future__ import annotations

import json

from .recorder import AuditCallback, RecorderConfig, UploadRecorder
from .sinks import BusinessReceiptSink, CustomerServiceLogSink

BOUNDARY = b"demo-boundary-2026"
CHUNK_SIZE = 17


def _part(name: bytes, value: bytes, *, content_type: bytes | None = None, filename: bytes | None = None) -> bytes:
    lines = [b"--" + BOUNDARY]
    disposition = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        disposition += b'; filename="' + filename + b'"'
    lines.append(disposition)
    if content_type is not None:
        lines.append(b"Content-Type: " + content_type)
    lines.append(b"")
    lines.append(value)
    return b"\r\n".join(lines)


def build_body() -> bytes:
    """Construct a form covering every required edge case.

    Parts:
      1. normal text field whose value is longer than the chunk size;
      2. a file whose filename contains personal data (a person name);
      3. a part with an empty name attribute;
      4. a file with no Content-Type (unknown type under the allow-list);
      5. a field the audit callback rejects (and a second that makes it
         raise, exercising the audit-failure path).
    """
    parts = [
        _part(b"order_note", b"x" * 53 + b" tail-of-split-field", content_type=b"text/plain"),
        _part(
            b"id_scan",
            b"%PDF-1.4 fake scan bytes 0123456789",
            content_type=b"application/pdf",
            filename=b"Zhang Wei - passport scan 12345678.pdf",
        ),
        _part(b"", b"value-with-empty-name"),
        _part(b"mystery_blob", b"raw bytes without a type", filename=b"blob.bin"),
        _part(b"blocked_keyword", b"please block this forbidden token", content_type=b"text/plain"),
        _part(b"boom_field", b"trigger audit explosion", content_type=b"text/plain"),
    ]
    return b"\r\n".join(parts) + b"\r\n--" + BOUNDARY + b"--\r\n"


class DemoAudit:
    """Stand-in moderation hook: returns False for one token, raises for another."""

    def __call__(self, metadata: object) -> bool:
        field = getattr(metadata, "field_name", "")
        if field == "blocked_keyword":
            return False
        if field == "boom_field":
            raise RuntimeError("audit backend unavailable")
        return True


def run_demo() -> tuple[BusinessReceiptSink, CustomerServiceLogSink]:
    body = build_body()
    business = BusinessReceiptSink()
    support = CustomerServiceLogSink()
    config = RecorderConfig(allowed_content_types=frozenset({"text/plain", "application/pdf"}))
    recorder = UploadRecorder(
        BOUNDARY,
        config=config,
        business_sink=business,
        support_sink=support,
        audit=AuditCallback(DemoAudit(), reason="blocked_by_moderation"),
    )
    for offset in range(0, len(body), CHUNK_SIZE):
        recorder.ingest(body[offset : offset + CHUNK_SIZE])
    recorder.finish()
    return business, support


def main() -> None:
    business, support = run_demo()
    print("=== business receipt (reconciliation view) ===")
    print(json.dumps(business.records, indent=2, ensure_ascii=False, sort_keys=True))
    print()
    print("=== customer-service log (reference + status only) ===")
    print(json.dumps(support.records, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
