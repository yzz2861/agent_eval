"""Codec and offline replay CLI for historical TUF audits."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path
from typing import Any

from tuf.api.history import (
    AuditRequest,
    CollectedMetadata,
    TargetSpec,
    TrustAnchor,
    audit,
    request_to_dict,
)


def _decode_bytes(value: str | None, field_name: str) -> bytes | None:
    if value is None:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = f"{field_name} is not valid base64"
        raise ValueError(msg) from exc


def request_from_dict(payload: dict[str, Any]) -> AuditRequest:
    """Decode a JSON-safe audit request."""
    data = payload.get("request", payload)
    anchor_data = data["trust_anchor"]
    anchor = TrustAnchor(
        data=_decode_bytes(anchor_data["data_base64"], "trust_anchor") or b"",
        sha256=anchor_data.get("sha256"),
        collected_at=anchor_data.get("collected_at"),
        source=anchor_data.get("source", "trust-anchor"),
    )

    target_data = data.get("target", {})
    if isinstance(target_data, str):
        target = TargetSpec(target_data)
    else:
        target = TargetSpec(
            path=target_data["path"],
            data=_decode_bytes(target_data.get("data_base64"), "target"),
            require_bytes=bool(target_data.get("require_bytes", False)),
        )

    records = []
    for index, item in enumerate(data.get("records", [])):
        raw = _decode_bytes(item["data_base64"], f"records[{index}]") or b""
        records.append(
            CollectedMetadata(
                data=raw,
                collected_at=item["collected_at"],
                record_id=item.get("record_id") or f"record-{index + 1}",
                source=item.get("source", "archive"),
                sequence=item.get("sequence"),
                log_id=item.get("log_id", "collection-log"),
                name=item.get("name"),
            )
        )

    return AuditRequest(
        trust_anchor=anchor,
        records=tuple(records),
        target=target,
        as_of=data.get("as_of") or data["historical_time"],
        current_time=data.get("current_time"),
        request_id=data.get("request_id"),
    )


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def replay_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Recompute one report and compare it with an expected report."""
    request_payload = bundle.get("request", bundle)
    report = audit(request_from_dict(request_payload)).to_dict()
    expected = bundle.get("expected_report")
    match = None
    if expected is not None:
        match = _canonical(report) == _canonical(expected)
    return {
        "schema": "tuf-historical-replay-result/v1",
        "match": match,
        "report_hash": report["report_hash"],
        "expected_report_hash": (
            expected.get("report_hash") if isinstance(expected, dict) else None
        ),
        "report": report,
    }


def replay_casebook(bundle: dict[str, Any]) -> dict[str, Any]:
    """Replay every case in a portable offline casebook."""
    results = []
    all_match = True
    for case in bundle.get("cases", []):
        name = case.get("name", "case")
        result = replay_bundle(case)
        expected_verdict = case.get("expected_verdict")
        verdict = result["report"]["historical"]["verdict"]
        verdict_matches = (
            expected_verdict is None or verdict == expected_verdict
        )
        if result["match"] is False or not verdict_matches:
            all_match = False
        results.append(
            {
                "name": name,
                "match": result["match"],
                "verdict_matches": verdict_matches,
                "historical_verdict": verdict,
                "current_verdict": result["report"]["current"]["verdict"],
                "report_hash": result["report_hash"],
                "report": result["report"],
            }
        )
    return {
        "schema": "tuf-historical-casebook-result/v1",
        "all_match": all_match,
        "case_count": len(results),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the offline replay CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="?", help="JSON bundle path or -")
    parser.add_argument("--replay", dest="replay_path", help="bundle path")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    path = args.replay_path or args.bundle or "-"
    if path == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(path).read_bytes()

    bundle = json.loads(raw.decode("utf-8"))
    if "cases" in bundle:
        result: dict[str, Any] = replay_casebook(bundle)
        failed = result["all_match"] is False
    else:
        result = replay_bundle(bundle)
        failed = result["match"] is False
        if args.check and result["match"] is None:
            failed = True

    sys.stdout.write(
        json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"
    )
    return 1 if failed else 0
