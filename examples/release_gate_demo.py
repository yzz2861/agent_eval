"""End-to-end release-gate demo for universal_guard.

Run with:  .venv/bin/python examples/release_gate_demo.py

The demo builds a two-slice universal artifact whose slices have
different protection postures, feeds caller-supplied verification
results into the library, classifies every supported terminal, then
raises one slice minimum OS version and explains which terminals move.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from macholib import mach_o

from universal_guard import (
    OSVersion,
    ProtectionPolicy,
    Terminal,
    build_fat,
    evaluate,
    explain_change,
    parse_artifact,
    rewrite_minimum_os,
)
from universal_guard.synthesize import CS_ADHOC, CS_KILL, CS_RUNTIME

CPU_X86_64 = 7 | 0x01000000
CPU_ARM64 = 12 | 0x01000000
MACOS = mach_o.PLATFORM_MACOS
IOS = mach_o.PLATFORM_IOS


def main():
    specs = [
        {
            "cpu_type": CPU_X86_64,
            "cpu_subtype": 3,
            "platform": MACOS,
            "min_os": (10, 13, 0),
            "code_signature_flags": CS_ADHOC | CS_RUNTIME | CS_KILL,
            "team_id": "GUARD",
        },
        {
            "cpu_type": CPU_ARM64,
            "cpu_subtype": 0,
            "platform": MACOS,
            "min_os": (11, 0, 0),
            "code_signature_flags": CS_ADHOC,
        },
    ]
    data = build_fat(specs)
    artifact = parse_artifact(data)

    terminals = [
        Terminal("intel-catalina", CPU_X86_64, 3, MACOS,
                 OSVersion(10, 15)),
        Terminal("intel-mojave", CPU_X86_64, 3, MACOS,
                 OSVersion(10, 14)),
        Terminal("apple-bigsur", CPU_ARM64, 0, MACOS,
                 OSVersion(11, 0)),
        Terminal("apple-monterey", CPU_ARM64, 0, MACOS,
                 OSVersion(12, 0)),
        Terminal("iphone", CPU_ARM64, 0, IOS, OSVersion(15, 0)),
    ]

    # The release backend verifies signatures itself and only hands the
    # verdict to the library, bound to architecture + slice digest.
    # Here the arm64 slice fails verification on purpose.
    verifications = []
    for slc in artifact.slices:
        verified = slc.index == 0
        verifications.append(
            {
                "verified": verified,
                "digest_algorithm": "sha256",
                "digest_value": slc.digests["sha256"],
                "cpu_type": slc.cpu_type,
                "cpu_subtype": slc.architecture.masked_subtype,
                "platform": slc.platform.platform,
                "expected_cdhash": slc.code_signature.cdhash,
                "verifier": "release-backend",
                "verifier_detail": "ok" if verified else "broken seal",
            }
        )

    report = evaluate(
        data,
        terminals,
        verifications,
        policy=ProtectionPolicy(),
    )
    print("=== coverage with inconsistent slice protection ===")
    for assessment in report.terminals:
        print(
            "%-16s %-16s slice=%s reasons=%s"
            % (
                assessment.terminal_id,
                assessment.status.value,
                assessment.slice_index,
                [reason.code for reason in assessment.reasons],
            )
        )

    rewritten = rewrite_minimum_os(
        data, (10, 15, 0), cpu_type=CPU_X86_64, cpu_subtype=3
    )
    rewritten_artifact = parse_artifact(rewritten)
    refreshed = []
    for slc in rewritten_artifact.slices:
        verified = slc.index == 0
        refreshed.append(
            {
                "verified": verified,
                "digest_algorithm": "sha256",
                "digest_value": slc.digests["sha256"],
                "cpu_type": slc.cpu_type,
                "cpu_subtype": slc.architecture.masked_subtype,
                "platform": slc.platform.platform,
                "expected_cdhash": slc.code_signature.cdhash,
            }
        )
    report_after = evaluate(
        rewritten, terminals, refreshed, policy=ProtectionPolicy()
    )
    print()
    print("=== after raising x86_64 minimum OS 10.13 -> 10.15 ===")
    for line in explain_change(report, report_after):
        print(line)


if __name__ == "__main__":
    main()
