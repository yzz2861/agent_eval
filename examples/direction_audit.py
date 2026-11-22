"""
Offline direction-attribution audit demo.

The fixture is built locally with dpkt; no packet is sent and no network
interface is touched.  It contains two ordinary frames with the same source
MAC at two capture points, plus one frame with only a truncated L2 header.
"""
from __future__ import print_function

import json

from dpkt.direction import build_demo


def main():
    result = build_demo()
    audit = result["audit"]

    print("capture:", result["capture"])
    print()
    print(audit.render(lang="zh"))
    print()
    print("direct conflicts:", len(audit.direct_conflicts))
    for verdict in audit.direct_conflicts:
        print("  frame %d: claim %r vs ledger %r" % (
            verdict.assessment.frame.index,
            verdict.claim.direction,
            list(verdict.ledger_directions)))
    print()
    print("machine-readable summary:")
    print(json.dumps(audit.summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
