#!/usr/bin/env python3
import json
from copy import deepcopy
from pathlib import Path

import ijson


HERE = Path(__file__).resolve().parent
SOURCE = b"""{
  "case_id": "CASE-2026-11-23",
  "observations": [
    {"kind": "temperature", "value": 21.5},
    {"kind": "pressure", "value": 1.013e2}
  ],
  "duplicate": {
    "sample": "first-reading",
    "sample": "second-reading"
  }
}
"""
SELECTIONS = [
    {"id": "pressure", "path": "observations[1].value"},
    {"id": "duplicate-first", "path": "duplicate.sample#0"},
    {"id": "duplicate-second", "path": "duplicate.sample#1"},
]


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    (HERE / "source.json").write_bytes(SOURCE)
    bundle = ijson.extract_evidence(SOURCE, SELECTIONS, numbers="decimal")
    (HERE / "trusted-root.txt").write_text(bundle.root + "\n", encoding="utf-8")
    evidence = bundle.to_jsonable()
    dump(HERE / "evidence.json", evidence)

    path_tampered = deepcopy(evidence)
    replacement_path = deepcopy(evidence["observations"][1]["path"])
    path_tampered["observations"][0]["path"] = replacement_path
    path_tampered["observations"][0]["path_string"] = ijson.format_path(
        replacement_path
    )
    dump(HERE / "evidence_path_tampered.json", path_tampered)

    duplicate_swapped = deepcopy(evidence)
    first, second = duplicate_swapped["observations"][1:3]
    for field in ("position", "order_commitment", "sibling_prefix_commitment"):
        first[field], second[field] = second[field], first[field]
    dump(HERE / "evidence_duplicate_swapped.json", duplicate_swapped)

    print("root commitment:", bundle.root)
    print("source bytes:", len(SOURCE))
    print("observations:", len(bundle.observations))


if __name__ == "__main__":
    main()
