"""Helpers for writing receipt JSON files and retained evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from offline_receipt_compare.models import Receipt


def write_evidence(root: str | Path, relpath: str, content: bytes) -> Path:
    """Write one retained evidence artifact below the evidence root."""
    root = Path(root)
    target = root / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def write_receipts(receipts_dir: str | Path, receipts: list[Receipt]) -> Path:
    """Write all receipts as a single sorted JSON file."""
    receipts_dir = Path(receipts_dir)
    receipts_dir.mkdir(parents=True, exist_ok=True)
    payload = [receipt.to_dict() for receipt in receipts]
    path = receipts_dir / "receipts.json"
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return path
