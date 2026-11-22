"""Runnable walkthrough for the audit completeness checker.

Run with: ``python -m audit_completeness.demo`` (from the workspace root).
"""

import io

from .drivers import audit_bytes, audit_stream
from .fixtures import (
    audit_rules,
    build_full_stream,
    build_truncated_stream,
)


def _print_result(title, result):
    print(title)
    print("  intact stream:", result.intact)
    print("  complete:", len(result.complete))
    print("  type mismatches:", len(result.type_mismatched))
    print("  definitive missing:", len(result.missing))
    print("  uncollected/truncated slots:", len(result.truncated))
    for finding in result.type_mismatched:
        print("    - mismatch", finding.rule_path, "got", finding.actual_type, finding.position)
    for finding in result.missing:
        print("    - missing", finding.rule_path, finding.position)
    for truncation in result.truncated:
        print("    - uncollected", truncation.position, "::", truncation.reason)


def main():
    rules = audit_rules()
    full = build_full_stream()
    cut = build_truncated_stream()
    _print_result("[1] full short stream, synchronous short reads:",
                  audit_stream(io.BytesIO(full), rules, buf_size=32))
    push_result = audit_bytes(cut, rules, chunk_size=23)
    _print_result("[2] last batch cut open, push/coroutine chunks:", push_result)
    print("[3] completed fields still individually reviewable after the cut:")
    for finding in push_result.completed_fields():
        print("    -", finding.rule_id, finding.status, finding.position)
    sync_cut = audit_stream(io.BytesIO(cut), rules, buf_size=23)
    same = (
        [f.rule_id for f in sync_cut.completed_fields()]
        == [f.rule_id for f in push_result.completed_fields()]
        and sync_cut.stream_truncated == push_result.stream_truncated
    )
    print("[4] sync short-read == push observations:", same)


if __name__ == "__main__":
    main()
