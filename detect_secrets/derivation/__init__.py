"""Derived-relationship analysis backend for detect-secrets.

Candidates are only merged when a canonical, verifiable decoding
relationship exists between their raw values (URL percent-encoding, JSON
string escaping, Base64 and hexadecimal layers, within a bounded chain).
Masking, shared prefixes/suffixes and string similarity never cause merges;
unverifiable look-alikes are listed separately.

Persistence and reports store domain-separated, irreversible identities
only. Plaintext candidate values live in the in-memory analysis for the
duration of a single scan and are never written to disk. No external
verification service is used at any point.
"""
from .engine import MAX_UNVERIFIABLE
from .engine import TRANSFORM_ORDER
from .engine import analyze_observations
from .engine import analyze_secrets_collection
from .engine import build_derivation_report
from .engine import build_observation
from .engine import build_observations
from .engine import clear_plaintext
from .identity import SCHEMA_VERSION
from .identity import compute_group_identity
from .identity import compute_occurrence_identity
from .identity import compute_relationship_identity
from .identity import compute_value_identity
from .identity import mask_secret
from .models import DerivationAnalysis
from .models import DerivationGroup
from .models import DerivationReport
from .models import GroupMember
from .models import Observation
from .models import TransformStep
from .models import UnverifiableRelationship
from .report import assert_no_plaintext
from .report import build_report
from .report import load_report
from .report import save_report
from .transforms import MAX_CHAIN_DEPTH
from .transforms import TRANSFORMS
from .transforms import Base64DecodeTransform
from .transforms import DecodeResult
from .transforms import HexDecodeTransform
from .transforms import JsonUnescapeTransform
from .transforms import Transform
from .transforms import UrlDecodeTransform
from .transforms import decode_once
from .transforms import get_transform

__all__ = [
    "Base64DecodeTransform",
    "DecodeResult",
    "DerivationAnalysis",
    "DerivationGroup",
    "DerivationReport",
    "GroupMember",
    "HexDecodeTransform",
    "JsonUnescapeTransform",
    "MAX_CHAIN_DEPTH",
    "MAX_UNVERIFIABLE",
    "Observation",
    "SCHEMA_VERSION",
    "TRANSFORM_ORDER",
    "TRANSFORMS",
    "Transform",
    "TransformStep",
    "UnverifiableRelationship",
    "UrlDecodeTransform",
    "analyze_observations",
    "analyze_secrets_collection",
    "assert_no_plaintext",
    "build_derivation_report",
    "build_observation",
    "build_observations",
    "build_report",
    "clear_plaintext",
    "compute_group_identity",
    "compute_occurrence_identity",
    "compute_relationship_identity",
    "compute_value_identity",
    "decode_once",
    "get_transform",
    "load_report",
    "mask_secret",
    "save_report",
]
