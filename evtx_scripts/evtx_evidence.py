#!/usr/bin/env python3
"""Create and verify field-scoped EVTX evidence bundles."""

from __future__ import absolute_import

import argparse
import json
import sys

from Evtx.Evidence import (
    actor_and_org_unit_policy,
    actor_only_policy,
    create_evidence_bundle,
    load_bundle,
    verify_bundle,
)


POLICY_FACTORIES = {
    "actor-only": actor_only_policy,
    "actor-and-org-unit": actor_and_org_unit_policy,
    "narrow": actor_only_policy,
    "broad": actor_and_org_unit_policy,
}


def _create(args: argparse.Namespace) -> int:
    policy = POLICY_FACTORIES[args.policy]()
    bundle = create_evidence_bundle(
        args.evtx,
        args.output,
        policy,
        record_numbers=args.records,
        start=args.start,
        end=args.end,
        limit=args.limit,
        overwrite=args.overwrite,
    )
    print(
        json.dumps(
            {
                "bundle": bundle.path,
                "policy": bundle.manifest["policy"]["name"],
                "forensic_digest": bundle.manifest["forensic_digest"],
                "summary": bundle.manifest["summary"],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _verify(args: argparse.Namespace) -> int:
    report = verify_bundle(args.bundle, args.evtx)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def _show(args: argparse.Namespace) -> int:
    bundle = load_bundle(args.bundle)
    if args.record is None:
        payload = {
            "manifest": bundle.manifest,
            "relationships": bundle.relationships,
            "records": [record["record"] for record in bundle.records],
        }
    else:
        payload = bundle.record(args.record)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Derive or verify a field-scoped EVTX evidence bundle.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="derive a bundle from an EVTX file")
    create.add_argument("evtx", help="source EVTX file")
    create.add_argument("output", help="bundle directory to create")
    create.add_argument("--policy", choices=sorted(POLICY_FACTORIES), default="actor-only")
    create.add_argument("--records", help="record numbers or ranges, for example 4-8,17")
    create.add_argument("--start", type=int, help="first record number to include")
    create.add_argument("--end", type=int, help="last record number to include")
    create.add_argument("--limit", type=int, help="maximum number of selected records")
    create.add_argument("--overwrite", action="store_true", help="replace an existing bundle directory")
    create.set_defaults(func=_create)

    verify = subparsers.add_parser("verify", help="recompute bundle digests and optionally check the original")
    verify.add_argument("bundle", help="bundle directory")
    verify.add_argument("--evtx", help="original EVTX file for offline back-reference checks")
    verify.set_defaults(func=_verify)

    show = subparsers.add_parser("show", help="print bundle metadata or one record")
    show.add_argument("bundle", help="bundle directory")
    show.add_argument("--record", type=int, help="record number to print")
    show.set_defaults(func=_show)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
