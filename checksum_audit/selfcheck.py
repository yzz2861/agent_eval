"""Assert every synthetic case lands on the intended layered verdict."""
from __future__ import annotations

from .cases import build_cases
from .offloadcheck import audit_frame

EXPECT = {
    "L2-FCS-OK": ("verifiable_ok", "verifiable_ok", "verifiable_ok"),
    "L2-FCS-BAD": ("mismatch", "mismatch", "verifiable_ok"),
    "L2-FCS-ABSENT": ("not_present", "verifiable_ok", "verifiable_ok"),
    "L2-FCS-SHORT": ("insufficient", "verifiable_ok", "verifiable_ok"),
    "L3-IP-OK": ("not_present", "verifiable_ok", "verifiable_ok"),
    "L3-IP-BAD": ("not_present", "mismatch", "verifiable_ok"),
    "L3-IP-ZERO-EGRESS": ("not_present", "device_unfilled", "device_unfilled"),
    "L3-IP-ZERO-INGRESS": ("not_present", "mismatch", "mismatch"),
    "L3-IP-SHORT": ("not_present", "insufficient", "not_present"),
    "L4-TCP-OK": ("not_present", "verifiable_ok", "verifiable_ok"),
    "L4-TCP-BAD": ("not_present", "verifiable_ok", "mismatch"),
    "L4-TCP-ZERO-EGRESS": ("not_present", "verifiable_ok", "device_unfilled"),
    "L4-TCP-ZERO-INGRESS": ("not_present", "verifiable_ok", "mismatch"),
    "L4-TCP-SHORT": ("not_present", "verifiable_ok", "insufficient"),
    "L4-TCP-PAYLOAD-GAP": ("not_present", "verifiable_ok", "insufficient"),
    "L4-UDP-OK": ("not_present", "verifiable_ok", "verifiable_ok"),
    "L4-UDP-BAD": ("not_present", "verifiable_ok", "mismatch"),
    "L4-UDP-ZERO-LEGAL": ("not_present", "verifiable_ok", "verifiable_ok"),
    "L4-UDP-ZERO-EGRESS": ("not_present", "verifiable_ok", "device_unfilled"),
    "L4-UDP-SHORT": ("not_present", "verifiable_ok", "insufficient"),
    "L4-ICMP-OK": ("not_present", "verifiable_ok", "verifiable_ok"),
    "L4-ICMP-BAD": ("not_present", "verifiable_ok", "mismatch"),
    "L4-ICMP-SHORT": ("not_present", "verifiable_ok", "insufficient"),
}


def main():
    failures = []
    for idx, case in enumerate(build_cases(), start=1):
        audit = audit_frame(idx, case.sample, case.wire_len, case.collector)
        got = tuple(v.verdict for v in audit.verdicts)
        want = EXPECT[case.name]
        if got != want:
            failures.append((case.name, want, got))
    if failures:
        for name, want, got in failures:
            print("FAIL %s want=%s got=%s" % (name, want, got))
        raise SystemExit(1)
    print("all %d synthetic cases match expected layered verdicts" % len(EXPECT))


if __name__ == "__main__":
    main()
