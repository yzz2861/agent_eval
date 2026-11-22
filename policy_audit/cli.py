"""Command line entry point for the CVSS policy pre-check toolkit."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List

from .compare import compare_versions
from .policy import PolicyError, load_policy_file
from .report import build_report


def _print_summary(report: Dict) -> None:
    print("Policy: " + report["policy"])
    if report.get("description"):
        print(report["description"])
    for version_report in report["versions"]:
        print()
        print("[CVSS " + version_report["version"] + "]")
        print(
            "  legal universe: {legal_universe_size}  covered: {policy_covered_size}"
            "  uncovered: {policy_uncovered_size}".format(**version_report)
        )
        bands = ", ".join(
            band["name"] + "=" + str(band["vectors"]) + "(" + band["disposition"] + ")"
            for band in version_report["bands"]
        )
        print(f"  bands: {bands}")
        adjacency = version_report["adjacency"]
        print(
            "  single-fact edges: {single_fact_edges}  cross-band: {cross_band_edges}"
            "  band-skipping: {band_skipping_edges}  components: {connected_components}"
            "  cross-band components: {cross_band_components}".format(**adjacency)
        )
        for verdict in report["verdicts"]:
            if verdict["version"] == version_report["version"]:
                print("  verdict: " + verdict["status"])
                for finding in verdict["findings"]:
                    print(f"    - {finding}")
        for witness in version_report["band_skipping_witnesses"][:5]:
            print(
                "  skip: {fact}  {from_vector}@{from_score}[{from_band}] -> "
                "{to_vector}@{to_score}[{to_band}]".format(
                    fact=witness["fact"],
                    from_vector=witness["from"]["vector"],
                    from_score=witness["from"]["score"],
                    from_band=witness["from"]["band"],
                    to_vector=witness["to"]["vector"],
                    to_score=witness["to"]["score"],
                    to_band=witness["to"]["band"],
                )
            )


def _run_compare(policy_path: str, compare_path: str) -> int:
    policy = load_policy_file(policy_path)
    with open(compare_path, "r", encoding="utf-8") as handle:
        spec = json.load(handle)
    report = compare_versions(
        versions=spec["versions"],
        canonical_metrics=spec["canonical_metrics"],
        metric_mapping=spec["metric_mapping"],
        value_mapping=spec["value_mapping"],
        canonical_domains={k: tuple(v) for k, v in spec["canonical_domains"].items()},
        policy=policy,
        baseline=spec["baseline"],
    )
    payload = report.as_dict()
    print(
        "shared vectors: {shared_vector_count}  edges: {edge_count}  "
        "surprise edges: {surprise_edge_count}  unavailable: {unavailable_count}".format(
            **payload
        )
    )
    for edge in payload["surprise_edges"][:15]:
        print("  SURPRISE " + edge["fact"])
        for version in payload["versions"]:
            print(
                "    {0}: scores={1} bands={2}".format(version, edge["scores"][version], edge["bands"][version])
            )
    print()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description="CVSS policy pre-check")
    parser.add_argument("--policy", required=True, help="path to policy JSON")
    parser.add_argument(
        "--compare",
        help="optional cross-version comparison specification JSON",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the full report as JSON instead of a text summary",
    )
    parser.add_argument(
        "--versions",
        nargs="*",
        help="limit the audit to these CVSS versions",
    )
    args = parser.parse_args(argv)
    try:
        if args.compare:
            return _run_compare(args.policy, args.compare)
        policy = load_policy_file(args.policy)
        report = build_report(policy, args.versions)
    except (PolicyError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_summary(report)
    return 0 if all(v["status"] == "pass" for v in report["verdicts"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
