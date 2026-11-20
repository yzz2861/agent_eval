"""Shared synthetic-artifact fixtures for the test suite."""

from macholib import mach_o

from universal_guard import build_fat, parse_artifact
from universal_guard.synthesize import CS_ADHOC, CS_KILL, CS_RUNTIME

CPU_X86_64 = 7 | 0x01000000
CPU_ARM64 = 12 | 0x01000000
PLATFORM_MACOS = mach_o.PLATFORM_MACOS
PLATFORM_IOS = mach_o.PLATFORM_IOS


def two_slice_specs():
    # The x86_64 slice is hardened, kill-on-invalid and carries a team id;
    # the arm64 slice is only ad-hoc signed, so the two slices start from
    # intentionally different protection postures.
    return [
        {
            "cpu_type": CPU_X86_64,
            "cpu_subtype": 3,
            "platform": PLATFORM_MACOS,
            "min_os": (10, 13, 0),
            "code_signature_flags": CS_ADHOC | CS_RUNTIME | CS_KILL,
            "team_id": "GUARD",
        },
        {
            "cpu_type": CPU_ARM64,
            "cpu_subtype": 0,
            "platform": PLATFORM_MACOS,
            "min_os": (11, 0, 0),
            "code_signature_flags": CS_ADHOC,
        },
    ]


def build_artifact():
    return build_fat(two_slice_specs())


def parsed_artifact():
    return parse_artifact(build_artifact())


def evidence_for(artifact, verified_overrides=None):
    overrides = verified_overrides or {}
    evidence = []
    for slc in artifact.slices:
        verified = overrides.get(slc.index, True)
        evidence.append(
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
    return evidence
