"""Data models, statuses and reason codes for release coverage checks.

The library never performs cryptographic verification itself.  Callers
supply :class:VerificationEvidence describing the result of their own
verification pipeline; the library binds that result to a concrete
architecture and to the digest of the slice that was actually inspected.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class SliceStatus(str, Enum):
    COVERED = "covered"
    AT_RISK = "at_risk"
    MISSING_EVIDENCE = "missing_evidence"


class TerminalStatus(str, Enum):
    COVERED = "covered"
    AT_RISK = "at_risk"
    MISSING_EVIDENCE = "missing_evidence"


class ReasonCode(str, Enum):
    NO_SELECTABLE_SLICE = "no_selectable_slice"
    CPU_TYPE_MISMATCH = "cpu_type_mismatch"
    CPU_SUBTYPE_INCOMPATIBLE = "cpu_subtype_incompatible"
    PLATFORM_MISMATCH = "platform_mismatch"
    OS_VERSION_BELOW_MINIMUM = "os_version_below_minimum"
    DEPLOYMENT_SCOPE_EXCLUDED = "deployment_scope_excluded"
    NO_EVIDENCE_FOR_SLICE = "no_evidence_for_slice"
    EVIDENCE_ARCH_NOT_PRESENT = "evidence_arch_not_present"
    EVIDENCE_DIGEST_MISMATCH = "evidence_digest_mismatch"
    CDHASH_MISMATCH = "cdhash_mismatch"
    SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"
    NO_CODE_SIGNATURE = "no_code_signature"
    NO_CODE_DIRECTORY = "no_code_directory"
    FAIRPLAY_ENCRYPTION_PRESENT = "fairplay_encryption_present"
    PROTECTION_ATTRIBUTE_MISSING = "protection_attribute_missing"



@dataclass(frozen=True)
class OSVersion:
    major: int
    minor: int = 0
    patch: int = 0

    @classmethod
    def parse(cls, value: Any) -> "OSVersion":
        if isinstance(value, OSVersion):
            return value
        if isinstance(value, int):
            return cls(major=value)
        if isinstance(value, (tuple, list)):
            numbers = [int(part) for part in value]
        else:
            numbers = [int(part) for part in str(value).strip().split(".")]
        while len(numbers) < 3:
            numbers.append(0)
        return cls(*numbers[:3])

    def as_tuple(self) -> Tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def packed(self) -> int:
        return (
            ((self.major & 0xFFFF) << 16)
            | ((self.minor & 0xFF) << 8)
            | (self.patch & 0xFF)
        )

    def __lt__(self, other: "OSVersion") -> bool:
        return self.as_tuple() < other.as_tuple()

    def __le__(self, other: "OSVersion") -> bool:
        return self.as_tuple() <= other.as_tuple()

    def __gt__(self, other: "OSVersion") -> bool:
        return self.as_tuple() > other.as_tuple()

    def __str__(self) -> str:
        return "%d.%d.%d" % self.as_tuple()


@dataclass(frozen=True)
class Architecture:
    cpu_type: int
    cpu_subtype: int
    name: str
    subtype_name: str

    SUBTYPE_MASK = 0x0FFFFFFF

    @property
    def masked_subtype(self) -> int:
        return self.cpu_subtype & self.SUBTYPE_MASK

    @property
    def key(self) -> Tuple[int, int]:
        return (self.cpu_type, self.masked_subtype)

    def __str__(self) -> str:
        return "%s/%s" % (self.name, self.subtype_name)


@dataclass(frozen=True)
class PlatformDeclaration:
    platform: int
    platform_name: str
    min_os: OSVersion
    sdk: OSVersion
    source_command: str


@dataclass(frozen=True)
class CodeSignatureInfo:
    present: bool
    dataoff: Optional[int] = None
    datasize: Optional[int] = None
    has_code_directory: bool = False
    cdhash_algorithm: Optional[str] = None
    cdhash: Optional[str] = None
    flags: int = 0
    flag_names: Tuple[str, ...] = ()
    identifier: Optional[str] = None
    team_id: Optional[str] = None
    has_cms_signature: bool = False
    has_entitlements: bool = False
    adhoc: bool = False
    encryption_info: Optional[Dict[str, int]] = None



@dataclass(frozen=True)
class SliceDigest:
    algorithm: str
    value: str

    def __str__(self) -> str:
        return "%s:%s" % (self.algorithm, self.value)


@dataclass(frozen=True)
class SliceInfo:
    index: int
    fat_offset: int
    fat_size: int
    architecture: Architecture
    platform: Optional[PlatformDeclaration]
    filetype: int
    filetype_name: str
    header_flags: int
    header_flag_names: Tuple[str, ...]
    segments: Tuple[Dict[str, Any], ...]
    code_signature: Optional[CodeSignatureInfo]
    digests: Dict[str, str]

    @property
    def cpu_type(self) -> int:
        return self.architecture.cpu_type

    @property
    def cpu_subtype(self) -> int:
        return self.architecture.cpu_subtype

    @property
    def protection_attributes(self) -> Dict[str, Any]:
        signature = self.code_signature
        text_segment = next(
            (segment for segment in self.segments
             if segment["name"] == "__TEXT"),
            None,
        )
        text_writable = (
            text_segment is not None
            and bool(text_segment["initprot"] & 0x2)
        )
        encrypted = bool(
            signature is not None
            and signature.encryption_info is not None
            and signature.encryption_info.get("cryptid", 0) != 0
        )
        return {
            "has_code_signature": signature is not None,
            "has_code_directory": (
                signature is not None and signature.has_code_directory
            ),
            "adhoc_signature": bool(signature and signature.adhoc),
            "hardened_runtime": bool(
                signature and "CS_RUNTIME" in signature.flag_names
            ),
            "kill_on_invalid_signature": bool(
                signature and "CS_KILL" in signature.flag_names
            ),
            "has_team_id": bool(signature and signature.team_id),
            "has_cms_signature": bool(
                signature and signature.has_cms_signature
            ),
            "pie": bool(self.header_flags & 0x200000),
            "no_heap_execution": bool(self.header_flags & 0x01000000),
            "stack_execution_allowed": bool(
                self.header_flags & 0x00020000
            ),
            "app_extension_safe": bool(self.header_flags & 0x02000000),
            "text_segment_not_writable": not text_writable,
            "fairplay_encryption": encrypted,
        }


@dataclass(frozen=True)
class UniversalArtifact:
    source: str
    is_fat: bool
    slices: Tuple[SliceInfo, ...]
    fat_alignment: Optional[int] = None



@dataclass(frozen=True)
class VerificationEvidence:
    verified: bool
    digest_algorithm: str
    digest_value: str
    cpu_type: Optional[int] = None
    cpu_subtype: Optional[int] = None
    platform: Optional[int] = None
    expected_cdhash: Optional[str] = None
    verifier: Optional[str] = None
    verifier_detail: Optional[str] = None

    @classmethod
    def from_mapping(cls, data: Dict[str, Any]) -> "VerificationEvidence":
        return cls(
            verified=bool(data["verified"]),
            digest_algorithm=data.get("digest_algorithm", "sha256"),
            digest_value=data["digest_value"],
            cpu_type=data.get("cpu_type"),
            cpu_subtype=data.get("cpu_subtype"),
            platform=data.get("platform"),
            expected_cdhash=data.get("expected_cdhash"),
            verifier=data.get("verifier"),
            verifier_detail=data.get("verifier_detail"),
        )


@dataclass(frozen=True)
class BoundEvidence:
    evidence: VerificationEvidence
    digest: SliceDigest
    digest_matches: bool
    cdhash_matches: Optional[bool]


@dataclass(frozen=True)
class Reason:
    code: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass
class SliceAssessment:
    slice_index: int
    status: SliceStatus
    reasons: List[Reason] = field(default_factory=list)
    evidence: Optional[BoundEvidence] = None
    missing_attributes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Terminal:
    terminal_id: str
    cpu_type: int
    cpu_subtype: int
    platform: int
    os_version: OSVersion
    description: str = ""

    @classmethod
    def from_mapping(cls, data: Dict[str, Any]) -> "Terminal":
        return cls(
            terminal_id=data["terminal_id"],
            cpu_type=data["cpu_type"],
            cpu_subtype=data["cpu_subtype"],
            platform=data["platform"],
            os_version=OSVersion.parse(data["os_version"]),
            description=data.get("description", ""),
        )

    @property
    def masked_subtype(self) -> int:
        return self.cpu_subtype & Architecture.SUBTYPE_MASK


@dataclass
class DeploymentScope:
    platforms: Optional[List[int]] = None
    min_os: Optional[OSVersion] = None
    max_os: Optional[OSVersion] = None
    cpu_types: Optional[List[int]] = None

    @classmethod
    def from_mapping(cls, data: Dict[str, Any]) -> "DeploymentScope":
        return cls(
            platforms=data.get("platforms"),
            min_os=(OSVersion.parse(data["min_os"])
                    if data.get("min_os") is not None else None),
            max_os=(OSVersion.parse(data["max_os"])
                    if data.get("max_os") is not None else None),
            cpu_types=data.get("cpu_types"),
        )



@dataclass
class ProtectionPolicy:
    required_attributes: Dict[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        defaults = {
            "has_code_signature": True,
            "has_code_directory": True,
            "pie": True,
            "text_segment_not_writable": True,
            "no_heap_execution": True,
            "stack_execution_allowed": False,
        }
        merged = dict(defaults)
        merged.update(self.required_attributes)
        self.required_attributes = merged


@dataclass
class TerminalAssessment:
    terminal_id: str
    status: TerminalStatus
    slice_index: Optional[int]
    reasons: List[Reason] = field(default_factory=list)
    slice_assessment: Optional[SliceAssessment] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "terminal_id": self.terminal_id,
            "status": self.status.value,
            "slice_index": self.slice_index,
            "reasons": [reason.as_dict() for reason in self.reasons],
        }


@dataclass
class CoverageReport:
    artifact: UniversalArtifact
    terminals: List[TerminalAssessment]
    slices: Dict[int, SliceAssessment]
    unmatched_evidence: List[Reason] = field(default_factory=list)
    policy: Optional[ProtectionPolicy] = None

    def by_status(self, status: TerminalStatus) -> List[TerminalAssessment]:
        return [item for item in self.terminals if item.status == status]

    @property
    def covered(self) -> List[TerminalAssessment]:
        return self.by_status(TerminalStatus.COVERED)

    @property
    def at_risk(self) -> List[TerminalAssessment]:
        return self.by_status(TerminalStatus.AT_RISK)

    @property
    def missing_evidence(self) -> List[TerminalAssessment]:
        return self.by_status(TerminalStatus.MISSING_EVIDENCE)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "artifact": self.artifact.source,
            "is_fat": self.artifact.is_fat,
            "slices": [
                {
                    "index": slc.index,
                    "architecture": str(slc.architecture),
                    "platform": (
                        slc.platform.platform_name if slc.platform else None
                    ),
                    "min_os": (
                        str(slc.platform.min_os) if slc.platform else None
                    ),
                    "sha256": slc.digests.get("sha256"),
                    "cdhash": (
                        slc.code_signature.cdhash
                        if slc.code_signature else None
                    ),
                }
                for slc in self.artifact.slices
            ],
            "terminals": [item.as_dict() for item in self.terminals],
            "unmatched_evidence": [
                reason.as_dict() for reason in self.unmatched_evidence
            ],
        }


@dataclass
class ReportChange:
    terminal_id: str
    before: Optional[TerminalAssessment]
    after: Optional[TerminalAssessment]

    @property
    def status_changed(self) -> bool:
        if self.before is None or self.after is None:
            return True
        return self.before.status != self.after.status
