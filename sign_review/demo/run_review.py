"""Runnable example: produce two re-checkable post-signature review records.

Run with: python -m sign_review.demo.run_review
The two JSON records are written under sign_review/demo/output (or a path given
on the command line).  One record clears a form for continued flow; the other
identifies the exact post-signature change that routes a form to manual review.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .. import ReviewPolicy, record_to_dict, review_pdf_bytes
from ..verifiers import StructuralStubVerifier
from .fixtures import build_all

DEFAULT_OUTPUT = Path(__file__).with_name("output")

POLICY = ReviewPolicy(
    allowed_field_fills=frozenset({"officer_name", "case_id", "review_note"}),
    allowed_field_appearance=frozenset(),
    allow_page_changes=False,
    allow_shared_resource_changes=False,
    allow_inherited_attr_changes=False,
)


def run(output_dir: Path | None = None) -> list[Path]:
    output_dir = output_dir or DEFAULT_OUTPUT
    fixture_dir = output_dir / 'fixtures'
    fixtures = build_all(fixture_dir)
    verifier = StructuralStubVerifier()
    written: list[Path] = []
    targets = (
        ('clear', 'review_record_clear.json'),
        ('manual', 'review_record_manual.json'),
    )
    for key, record_name in targets:
        data = fixtures[key].read_bytes()
        record = review_pdf_bytes(data, POLICY, verifier, source=fixtures[key].name)
        payload = record_to_dict(record)
        target = output_dir / record_name
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2,
                                     sort_keys=True), encoding='utf-8')
        written.append(target)
    return written


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    output_dir = Path(argv[0]) if argv else DEFAULT_OUTPUT
    for path in run(output_dir):
        print(f'wrote {path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
