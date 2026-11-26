#!/usr/bin/env python3
"""Generate and check the offline receipt for the bundled exchange pair."""

from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from stix2.exchange_receipt import build_exchange_receipt


HERE = Path(__file__).resolve().parent


def main() -> int:
    receipt = build_exchange_receipt(
        HERE / "identity-before.json",
        HERE / "identity-after.json",
        HERE / "gateway-disclosure.json",
    )
    output = HERE / "offline-receipt.json"
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    summary = receipt["summary"]
    print("object:", receipt["object_id"])
    print("identity preserved:", ", ".join(summary["identity_preserved"]))
    print("explicitly transformed:", ", ".join(summary["explicitly_transformed"]))
    print("unverifiable:", ", ".join(summary["unverifiable"]))
    print("order normalized:", ", ".join(summary["order_normalized"]))
    print("revision metadata:", ", ".join(summary["revision_metadata_changes"]))
    print("real updates:", ", ".join(summary["real_updates"]))
    print("wrote:", output)

    assert receipt["same_id"] is True
    assert summary["real_updates"] == ["description"]
    assert summary["real_update_count"] == 1
    assert summary["only_real_update"] == "description"
    assert summary["issues"] == []
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
