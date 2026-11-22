"""The two record sinks and a small JSONL persistence helper.

A sink is deliberately narrow: the recorder hands it already-classified
records, and each sink only serialises the fields its trust level allows.
Neither sink opens a network connection; they write to in-memory lists and,
optionally, to local JSONL files.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from .records import ConfirmedMetadata, PublicReference, RejectionInfo, RequestSummary


class JsonlSink:
    """Append JSONL records to an in-memory list and, optionally, a file.

    The file handle is owned by the caller so the same sink can be used with
    :class:`io.StringIO` in tests and a real log file in production without any
    network service.
    """

    def __init__(self, *, stream: TextIO | None = None) -> None:
        self.records: list[dict[str, Any]] = []
        self._stream = stream

    def emit(self, record: Mapping[str, Any]) -> None:
        payload = dict(record)
        self.records.append(payload)
        if self._stream is not None:
            self._stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            self._stream.write("\n")
            self._stream.flush()


class BusinessReceiptSink:
    """Trust level: may keep confirmed metadata for request reconciliation.

    It never receives raw field values or file bodies - only the
    :class:`ConfirmedMetadata` describing accepted parts and the minimum
    rejection records. Half-parsed data on failure is therefore impossible to
    end up in the receipt.
    """

    def __init__(self, *, stream: TextIO | None = None) -> None:
        self._jsonl = JsonlSink(stream=stream)

    @property
    def records(self) -> list[dict[str, Any]]:
        return self._jsonl.records

    def accept(self, metadata: ConfirmedMetadata) -> None:
        self._jsonl.emit({"kind": "confirmed", **metadata.to_receipt_dict()})

    def reject(self, info: RejectionInfo) -> None:
        self._jsonl.emit({"kind": "rejection", **info.to_receipt_dict()})

    def finish(self, summary: RequestSummary) -> None:
        self._jsonl.emit({"kind": "summary", **summary.to_receipt_dict()})


class CustomerServiceLogSink:
    """Trust level: opaque references and current processing status only.

    The sink API only accepts :class:`PublicReference` and
    :class:`RejectionInfo`, so field names, filenames, content types and raw
    values have no type-correct way to reach it.
    """

    def __init__(self, *, stream: TextIO | None = None) -> None:
        self._jsonl = JsonlSink(stream=stream)

    @property
    def records(self) -> list[dict[str, Any]]:
        return self._jsonl.records

    def reference(self, ref: PublicReference) -> None:
        self._jsonl.emit({"kind": "reference", **ref.to_log_dict()})

    def reject(self, info: RejectionInfo) -> None:
        self._jsonl.emit({"kind": "rejection", **info.to_log_dict()})

    def finish(self, summary: RequestSummary) -> None:
        self._jsonl.emit({"kind": "summary", **summary.to_log_dict()})


def write_jsonl(path: str | Path, records: list[dict[str, Any]]) -> None:
    """Persist an in-memory sink's records to a local JSONL file."""
    with Path(path).open("w", encoding="utf-8") as handle:
        sink = JsonlSink(stream=handle)
        for record in records:
            sink.emit(record)
