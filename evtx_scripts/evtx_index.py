#!/usr/bin/env python
"""Build and query an offline, policy-aware index of EVTX records."""
from __future__ import absolute_import

import argparse
import json
import sys

from Evtx.Index import (
    EVENT_TYPE_POLICY,
    FULL_POLICY,
    AccessPolicy,
    OfflineIndex,
    QueryCondition,
    build_evtx_index,
    normalize_field_name,
)


def _normalize_allow(field):
    raw = field.strip()
    if any(character in raw for character in "*?["):
        return raw
    return normalize_field_name(raw)


def _policy_from_args(args):
    if args.policy == "event-type":
        policy = EVENT_TYPE_POLICY
    elif args.policy == "limited":
        policy = AccessPolicy.limited_fields()
    else:
        policy = FULL_POLICY

    if args.allow and args.policy != "all":
        patterns = list(policy.allowed_fields)
        for field in args.allow:
            normalized = _normalize_allow(field)
            if normalized not in patterns:
                patterns.append(normalized)
        policy = AccessPolicy(
            name="%s+custom" % policy.name,
            allowed_fields=tuple(patterns),
            description=policy.description,
        )
    return policy


def _conditions_from_args(args):
    return [QueryCondition.from_text(text) for text in args.where]


def _print_json(data):
    print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))


def _print_result(result):
    if not result.available:
        print("query: unavailable")
        print(result.reason)
        for assessment in result.assessments:
            print(
                "  %s %s %r: %s%s"
                % (
                    assessment.field,
                    assessment.condition.op,
                    assessment.condition.value,
                    assessment.status,
                    " (%s)" % assessment.reason if assessment.reason else "",
                )
            )
        return 2

    print("query: available")
    print("hits: %d" % result.hit_count)
    print("condition counts: %s" % (result.condition_counts,))
    for index, hit in enumerate(result.hits, 1):
        location = hit.location
        print(
            "  %d. %s chunk=%d chunk_offset=0x%x record=%s record_offset=0x%x"
            % (
                index,
                location.source,
                location.chunk_index,
                location.chunk_offset,
                location.record_num,
                location.record_offset,
            )
        )
    return 0


def _cmd_build(args):
    policy = _policy_from_args(args)
    index = build_evtx_index(args.evtx, policy=policy, include_inactive=args.include_inactive)
    index.save(args.output)
    _print_json(
        {
            "output": args.output,
            "policy": index.policy.to_dict(),
            "coverage": index.coverage.to_dict(),
            "records_indexed": index.coverage.records_indexed,
            "fingerprint": index.fingerprint(),
        }
    )
    return 0


def _cmd_explain(args):
    index = OfflineIndex.load(args.index)
    assessments = index.assess(_conditions_from_args(args), viewer_policy=_policy_from_args(args))
    _print_json({"conditions": [assessment.to_dict() for assessment in assessments]})
    return 0


def _cmd_query(args):
    index = OfflineIndex.load(args.index)
    result = index.query(
        _conditions_from_args(args),
        viewer_policy=_policy_from_args(args),
        include_values=args.values,
        limit=args.limit,
    )
    if args.json:
        _print_json(result.to_dict())
        return 0 if result.available else 2
    return _print_result(result)


def _cmd_show(args):
    index = OfflineIndex.load(args.index)
    _print_json(index.to_dict(viewer_policy=_policy_from_args(args), include_records=not args.no_records))
    return 0


def _add_policy_arguments(parser):
    parser.add_argument(
        "--policy",
        choices=("event-type", "limited", "all"),
        default="event-type",
        help="Field projection to build or view (default: event-type)",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="FIELD",
        help="Additional field or glob to permit; may be repeated",
    )


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="Build an offline index from an EVTX file")
    build.add_argument("evtx", help="Path to the EVTX file")
    build.add_argument("-o", "--output", required=True, help="Path to write the JSON index")
    build.add_argument("--include-inactive", action="store_true", help="Include chunks beyond the file header count")
    _add_policy_arguments(build)
    build.set_defaults(func=_cmd_build)

    explain = subparsers.add_parser("explain", help="Check whether conditions can be used")
    explain.add_argument("index", help="Path to the JSON index")
    explain.add_argument("--where", action="append", required=True, metavar="CONDITION")
    _add_policy_arguments(explain)
    explain.set_defaults(func=_cmd_explain)

    query = subparsers.add_parser("query", help="Query an offline index")
    query.add_argument("index", help="Path to the JSON index")
    query.add_argument("--where", action="append", required=True, metavar="CONDITION")
    query.add_argument("--limit", type=int, default=None, help="Return at most this many hits")
    query.add_argument("--values", action="store_true", help="Include matched field values")
    query.add_argument("--json", action="store_true", help="Emit JSON")
    _add_policy_arguments(query)
    query.set_defaults(func=_cmd_query)

    show = subparsers.add_parser("show", help="Show the policy-filtered index presentation")
    show.add_argument("index", help="Path to the JSON index")
    show.add_argument("--no-records", action="store_true", help="Omit per-record details")
    _add_policy_arguments(show)
    show.set_defaults(func=_cmd_show)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
