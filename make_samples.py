from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import generate_archive_sample as gen

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / 'samples'


def dt(year):
    return datetime(year, 3, 1, 9, tzinfo=timezone.utc)


def write_json(path, value):
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    path.write_bytes(data)
    return data


def build_case(root, key, cert, asn1_cert):
    for name in ("segments", "commitments", "receipts"):
        (root / name).mkdir(parents=True, exist_ok=True)
    texts = [
        "archive segment zero: original signed admission record",
        "archive segment one: migrated signed catalog card",
        "archive segment two: later signed finding aid",
    ]
    blobs = [gen.build_original_cms(text, key, asn1_cert) for text in texts]
    pack = b"".join(blobs)
    (root / "segments" / "signed-materials.der").write_bytes(pack)
    ranges = []
    pos = 0
    for blob in blobs:
        ranges.append({"start": pos, "end": pos + len(blob)})
        pos += len(blob)
    previous = None
    for index, blob in enumerate(blobs):
        span = ranges[index]
        record = {
            "schema": "archive-commitment-record/v1",
            "record_id": "segment-%d" % index,
            "sequence": index,
            "created_at": dt(2021 + 2 * index).isoformat(),
            "segment": {
                "source_id": "segments/signed-materials.der",
                "basis": "raw",
                "start": span["start"],
                "end": span["end"],
                "sha256": gen.sha256_hex(blob),
                "kind": "cms-signed-data",
            },
            "predecessor": None if previous is None else {
                "receipt_id": previous["receipt_id"],
                "record_id": "segment-%d" % (index - 1),
                "sequence": index - 1,
                "token_sha256": gen.sha256_hex(previous["token"]),
                "time_stamp_response_sha256": gen.sha256_hex(previous["response"]),
                "archive_record_sha256": gen.sha256_hex(previous["record"]),
            },
        }
        record_bytes = write_json(root / "commitments" / ("segment-%d.json" % index), record)
        response, token = gen.build_timestamp_receipt(
            record_bytes, dt(2021 + 2 * index), 770130 + index, key, asn1_cert
        )
        receipt_id = "receipt-%d" % index
        (root / "receipts" / (receipt_id + ".tsr")).write_bytes(response)
        if index == 1:
            (root / "receipts" / "receipt-1.repacked-token.der").write_bytes(token)
            pem = gen.armor_pem("TIMESTAMP TOKEN", token)
            (root / "receipts" / "receipt-1.repacked-token.pem").write_bytes(pem)
        previous = {
            "receipt_id": receipt_id,
            "response": response,
            "token": token,
            "record": record_bytes,
        }
    write_json(root / "trust.json", {"all_signatures": "trusted"})


def write_json(path, value):
    data = json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
    path.write_bytes(data)
    return data
