#!/usr/bin/env python3
import json
from pathlib import Path

import ijson


HERE = Path(__file__).resolve().parent
SELECTIONS = [
    {"id": "pressure", "path": "observations[1].value"},
    {"id": "duplicate-first", "path": "duplicate.sample#0"},
    {"id": "duplicate-second", "path": "duplicate.sample#1"},
]


def main():
    source = (HERE / "source.json").read_bytes()
    trusted_root = (HERE / "trusted-root.txt").read_text(encoding="utf-8").strip()
    trusted_paths = [item["path"] for item in SELECTIONS]

    for name in (
        "evidence.json",
        "evidence_path_tampered.json",
        "evidence_duplicate_swapped.json",
    ):
        evidence = json.loads((HERE / name).read_text(encoding="utf-8"))
        result = ijson.verify_evidence(
            source,
            evidence,
            root=trusted_root,
            selections=trusted_paths,
        )
        print(json.dumps({
            "package": name,
            "ok": result.ok,
            "violated_commitments": sorted(result.violated_commitments),
            "violations": sorted({violation.message for violation in result.violations}),
        }, ensure_ascii=False))


if __name__ == "__main__":
    main()
