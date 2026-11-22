"""Print compact, human-readable highlights from the generated report artifacts."""

import json


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def audit_summary(path):
    report = load(path)
    print("== " + report["policy"] + " ==")
    for version in report["versions"]:
        adjacency = version["adjacency"]
        print(
            "CVSS {0}: legal={1} covered={2} uncovered={3} edges={4} cross_band={5} "
            "skipping={6} components={7}".format(
                version["version"],
                version["legal_universe_size"],
                version["policy_covered_size"],
                version["policy_uncovered_size"],
                adjacency["single_fact_edges"],
                adjacency["cross_band_edges"],
                adjacency["band_skipping_edges"],
                adjacency["connected_components"],
            )
        )
    for verdict in report["verdicts"]:
        print("verdict[" + verdict["version"] + "]: " + verdict["status"])
        for finding in verdict["findings"]:
            print("  - " + finding)


def compare_summary(path):
    report = load(path)
    print("== cross-version comparison ==")
    print(
        "shared_vectors={0} edges={1} surprise_edges={2} unavailable={3}".format(
            report["shared_vector_count"],
            report["edge_count"],
            report["surprise_edge_count"],
            report["unavailable_count"],
        )
    )
    unique = {}
    for edge in report["surprise_edges"]:
        unique.setdefault(edge["fact"], edge)
    for fact in sorted(unique):
        edge = unique[fact]
        print(
            "{0} | v2 {1} {2} | v3.1 {3} {4}".format(
                fact,
                edge["scores"]["2.0"],
                edge["bands"]["2.0"],
                edge["scores"]["3.1"],
                edge["bands"]["3.1"],
            )
        )


if __name__ == "__main__":
    audit_summary("reports/audit_full.json")
    print()
    audit_summary("reports/audit_restricted.json")
    print()
    compare_summary("reports/compare_v2_v31.json")
