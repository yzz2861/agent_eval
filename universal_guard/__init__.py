"""Release protection coverage checks for Mach-O universal artifacts.

The package answers one release-gate question: given a supported
architecture/platform matrix, the deployment scope of every slice and the
required protection attributes, which terminals are covered, which ones
are at risk and which ones lack evidence?

Signature verification is never performed here. The publishing backend
verifies signatures and hands the result to the library, which binds that
result to a concrete architecture and to the digest of the slice that was
actually inspected.
"""

from .models import (
    Architecture,
    BoundEvidence,
    CoverageReport,
    DeploymentScope,
    OSVersion,
    PlatformDeclaration,
    ProtectionPolicy,
    Reason,
    ReasonCode,
    ReportChange,
    SliceAssessment,
    SliceDigest,
    SliceInfo,
    SliceStatus,
    Terminal,
    TerminalAssessment,
    TerminalStatus,
    UniversalArtifact,
    VerificationEvidence,
)
from .parsing import parse_artifact
from .selection import (
    bind_evidence,
    diff_reports,
    evaluate,
    explain_change,
    select_slice,
    subtype_compatible,
)
from .synthesize import (
    build_fat,
    build_slice,
    build_synthetic_universal,
    rewrite_file_minimum_os,
    rewrite_minimum_os,
    write_synthetic_universal,
)

__all__ = [
    "Architecture",
    "BoundEvidence",
    "CoverageReport",
    "DeploymentScope",
    "OSVersion",
    "PlatformDeclaration",
    "ProtectionPolicy",
    "Reason",
    "ReasonCode",
    "ReportChange",
    "SliceAssessment",
    "SliceDigest",
    "SliceInfo",
    "SliceStatus",
    "Terminal",
    "TerminalAssessment",
    "TerminalStatus",
    "UniversalArtifact",
    "VerificationEvidence",
    "bind_evidence",
    "build_fat",
    "build_slice",
    "build_synthetic_universal",
    "diff_reports",
    "evaluate",
    "explain_change",
    "parse_artifact",
    "rewrite_file_minimum_os",
    "rewrite_minimum_os",
    "select_slice",
    "subtype_compatible",
    "write_synthetic_universal",
]

__version__ = "0.1.0"
