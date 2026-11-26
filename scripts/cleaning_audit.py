#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.cleaning_audit import audit_clean  # noqa: E402


SAMPLES = (
    {
        "id": "stripped-element",
        "html": '<div title="Author note">Hello</div>',
        "tags": ["p"],
        "attributes": {"p": []},
        "strip": True,
    },
    {
        "id": "stripped-attribute",
        "html": '<p title="Author note">Hello</p>',
        "tags": ["p"],
        "attributes": {"p": []},
        "strip": False,
    },
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate offline Bleach cleaning policy receipts."
    )
    parser.add_argument(
        "--html", help="HTML fragment to audit instead of the built-in samples."
    )
    parser.add_argument(
        "--tag", action="append", dest="tags", help="Allowed tag; repeatable."
    )
    parser.add_argument(
        "--allow-attribute",
        action="append",
        default=[],
        help="Allowed attribute on all tags; repeatable.",
    )
    parser.add_argument("--strip", action="store_true", help="Strip disallowed tags.")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.html is None:
        samples = SAMPLES
    else:
        tags = args.tags or ["p"]
        samples = [
            {
                "id": "custom-html",
                "html": args.html,
                "tags": tags,
                "attributes": {"*": args.allow_attribute},
                "strip": args.strip,
            }
        ]

    receipts = []
    for sample in samples:
        result = audit_clean(
            sample["html"],
            tags=set(sample["tags"]),
            attributes=sample["attributes"],
            strip=sample["strip"],
        )
        receipts.append({"id": sample["id"], **result})

    print(
        json.dumps(to_jsonable(receipts), indent=2, ensure_ascii=False, sort_keys=True)
    )


def to_jsonable(value):
    if isinstance(value, dict):
        return {
            ":".join(part for part in key if part is not None)
            if isinstance(key, tuple)
            else key: to_jsonable(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [to_jsonable(item) for item in value]
    return value


if __name__ == "__main__":
    main()
