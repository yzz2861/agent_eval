"""
Command line interface for the original-vs-derived comparison.

    python -m ole_provenance sample  OUTDIR
    python -m ole_provenance build   ORIGINAL DERIVED SIDECAR [--proofs LOG]
    python -m ole_provenance resolve SIDECAR [--json]
    python -m ole_provenance drop-proof SIDECAR PROOF_ID [--out SIDECAR]
"""

import argparse
import json
import sys

from .sample import build_sample
from .sidecar import (
    STATUS_AMBIGUOUS,
    STATUS_UNIQUE,
    STATUS_UNMATCHED,
    build_sidecar,
    drop_source_proof,
    load_sidecar,
    resolve_mapping,
    save_sidecar,
)


def _cmd_sample(args):
    build_sample(args.outdir)
    print("sample exhibits written to %s" % args.outdir)


def _cmd_build(args):
    proofs = []
    if args.proofs:
        with open(args.proofs, "r", encoding="utf-8") as handle:
            proofs = json.load(handle)["proofs"]
    sidecar = build_sidecar(args.original, args.derived, proofs=proofs,
                            note=args.note or "")
    save_sidecar(sidecar, args.sidecar)
    print("sidecar written to %s (%d source proof(s))"
          % (args.sidecar, len(sidecar["source_proofs"])))


def _format_ranges(ranges):
    return ", ".join("0x%x+%d" % (offset, length) for offset, length in ranges)


def _print_report(report, out):
    for warning in report["warnings"]:
        print("WARNING: %s" % warning, file=out)
    for resolution in report["resolutions"]:
        print("derived stream: %s" % resolution["derived_path"], file=out)
        print("  status: %s" % resolution["status"], file=out)
        print("  reason: %s" % resolution.get("reason", ""), file=out)
        for item in resolution["evidence"]:
            print("  evidence: %s" % item, file=out)
        for item in resolution["warnings"]:
            print("  WARNING: %s" % item, file=out)
        entries = []
        if resolution["status"] == STATUS_UNIQUE and resolution["match"]:
            entries = [("match", resolution["match"])]
        elif resolution["status"] in (STATUS_AMBIGUOUS, STATUS_UNMATCHED):
            entries = [("candidate #%d" % (i + 1), c)
                       for i, c in enumerate(resolution["candidates"])]
        for label, entry in entries:
            hint = " (name matches derived stream)" if entry.get("name_hint") else ""
            print("  %s: directory entry sid=%d path=%s%s"
                  % (label, entry["sid"], entry["path"], hint), file=out)
            print("    original bytes: %s" % _format_ranges(entry["byte_ranges"]),
                  file=out)


def _cmd_resolve(args):
    report = resolve_mapping(load_sidecar(args.sidecar),
                             verify_files=not args.no_verify)
    if args.json:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        _print_report(report, sys.stdout)
    ambiguous = sum(1 for r in report["resolutions"]
                    if r["status"] == STATUS_AMBIGUOUS)
    unmatched = sum(1 for r in report["resolutions"]
                    if r["status"] == STATUS_UNMATCHED)
    return 1 if (ambiguous or unmatched or report["warnings"]) else 0


def _cmd_drop_proof(args):
    sidecar = load_sidecar(args.sidecar)
    removed = drop_source_proof(sidecar, args.proof_id)
    target = args.out or args.sidecar
    save_sidecar(sidecar, target)
    print("removed proof %s (%s -> %s); sidecar updated: %s"
          % (removed["id"], removed["derived_path"],
             removed["original_path"], target))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ole_provenance",
        description="map derived OLE streams back to original directory "
                    "entries and byte ranges",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_sample = sub.add_parser("sample", help="write the demonstration exhibits")
    p_sample.add_argument("outdir")
    p_sample.set_defaults(func=_cmd_sample)

    p_build = sub.add_parser("build", help="build the mapping sidecar")
    p_build.add_argument("original")
    p_build.add_argument("derived")
    p_build.add_argument("sidecar")
    p_build.add_argument("--proofs", help="export log JSON with source proofs")
    p_build.add_argument("--note", help="free-text note for the sidecar header")
    p_build.set_defaults(func=_cmd_build)

    p_resolve = sub.add_parser("resolve", help="resolve derived streams "
                               "against the original")
    p_resolve.add_argument("sidecar")
    p_resolve.add_argument("--json", action="store_true")
    p_resolve.add_argument("--no-verify", action="store_true",
                           help="skip re-hashing both files through olefile")
    p_resolve.set_defaults(func=_cmd_resolve)

    p_drop = sub.add_parser("drop-proof", help="remove a source proof from "
                            "the sidecar")
    p_drop.add_argument("sidecar")
    p_drop.add_argument("proof_id")
    p_drop.add_argument("--out", help="write to a new file instead of "
                        "rewriting the sidecar")
    p_drop.set_defaults(func=_cmd_drop_proof)

    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
