#!/usr/bin/env python
"""
Offline, reviewable merge of several EVTX collections of the same log.

The caller supplies the known collection sources (path + provenance), either
repeatedly via --source or once via a JSON manifest. The tool never edits the
inputs and emits:
  * a full JSON report (sources, chunk coverage, era boundaries, events);
  * a JSONL stream with one merged event per line;
  * a human-readable forensic summary on stdout.

Duplicates are decided by the sha256 of the raw record bytes, so overlapping
export windows are not double counted, while same-number records produced after
a log clear are preserved side by side.
"""
from __future__ import annotations

import argparse
import json

import Evtx.Merge as merge


def _load_manifest(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        data = data.get("sources", [])
    specs = []
    for entry in data:
        specs.append(merge.SourceSpec(
            path=entry["path"],
            source_id=entry["source_id"],
            description=entry.get("description", ""),
            collected_at=entry.get("collected_at", ""),
            collector=entry.get("collector", ""),
        ))
    return specs


def _print_summary(result):
    print("EVTX offline merge summary")
    print("=" * 27)
    print("sources scanned: {}".format(len(result.sources)))
    for source in result.sources:
        unknown = [c.chunk_index for c in source.chunk_coverage if not c.coverage_known]
        print(
            "  - {id}: {n} records, {chunks} chunks, sha256={sha}".format(
                id=source.spec.source_id,
                n=len(source.provenance),
                chunks=len(source.chunk_coverage),
                sha=source.file_sha256,
            )
        )
        if unknown:
            print("      coverage UNKNOWN for chunk index(es): {}".format(unknown))
        for err in source.parse_errors:
            print("      parse note: {}".format(err))
        for note in source.truncation_notes:
            print("      coverage note: {}".format(note))

    print("merged logical events: {}".format(len(result.events)))
    duplicates = [e for e in result.events if e.is_duplicate()]
    print("events merged from multiple copies: {}".format(len(duplicates)))
    for event in merge.sort_events(duplicates):
        copies = ", ".join(
            "{}@{}#{}".format(o.source_id, hex(o.chunk_offset), o.record_num) for o in event.occurrences
        )
        print("      record_num={} era={} <- [{}]".format(event.record_num, event.global_era, copies))
        print("        basis: {}".format(event.duplicate_basis))

    print("same-number records kept side by side: {}".format(len(result.same_number_pairs)))
    for pair in result.same_number_pairs:
        print(
            "      record_num={} era={} classification={}".format(
                pair["record_num"], pair["global_era"], pair["classification"]
            )
        )
        for event in pair["events"]:
            locs = ", ".join(
                "{}@{}".format(o["source_id"], hex(o["chunk_offset"])) for o in event["occurrences"]
            )
            print("        sha256={} [{}]".format(event["sha256"], locs))

    print("era boundaries: {}".format(len(result.boundaries)))
    for boundary in result.boundaries:
        print(
            "      source={} chunk={} {} -> {} reason={}".format(
                boundary.source_id,
                boundary.chunk_index,
                boundary.previous_record_num,
                boundary.next_record_num,
                boundary.reason,
            )
        )
        print("        {}".format(boundary.rationale))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Reviewable offline merge of multiple EVTX collections."
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="ID=PATH",
        help="a known collection source, as source_id=path; repeatable",
    )
    parser.add_argument("--manifest", type=str, help="JSON manifest of sources")
    parser.add_argument("--report", required=True, help="output path for the full JSON report")
    parser.add_argument("--jsonl", type=str, help="optional output path for JSONL events")
    parser.add_argument(
        "--order",
        choices=["desc", "asc"],
        default="desc",
        help="timestamp order of the JSONL output (default: newest first)",
    )
    args = parser.parse_args(argv)

    specs = []
    if args.manifest:
        specs.extend(_load_manifest(args.manifest))
    for token in args.source:
        if "=" not in token:
            parser.error("--source expects source_id=path, got: {}".format(token))
        source_id, path = token.split("=", 1)
        specs.append(merge.SourceSpec(path=path, source_id=source_id))
    if not specs:
        parser.error("provide at least one --source or a --manifest")

    result = merge.merge_sources(specs)
    with open(args.report, "w", encoding="utf-8") as handle:
        handle.write(result.to_json())
    if args.jsonl:
        with open(args.jsonl, "w", encoding="utf-8") as handle:
            for event in merge.sort_events(result.events, order=args.order):
                handle.write(json.dumps(event.as_dict()) + "\n")
    _print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
