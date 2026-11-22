"""Evidence dependency model for targeted report revalidation.

An *evidence reference* records exactly which registry fact a forensic
conclusion was derived from. Two flavors of fact are supported:

* a fact that was read from the hive (a key, a value or a whole subtree);
* the *absence* of a fact at report time, which is itself evidence when a
  plugin concludes "the persistence key does not exist".

References only carry registry paths and value names, so they are fully
JSON-serializable and can be re-evaluated against a supplemented hive without
keeping the original hive file around.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Optional


class EvidenceKind(str, Enum):
    """What kind of registry fact an evidence reference points at."""

    KEY = "key"
    VALUE = "value"
    SUBTREE = "subtree"
    MISSING_KEY = "missing_key"
    MISSING_VALUE = "missing_value"


# Short aliases used by the recording layer for readability.
KEY = EvidenceKind.KEY
VALUE = EvidenceKind.VALUE
SUBTREE = EvidenceKind.SUBTREE
KEY_ABSENT = EvidenceKind.MISSING_KEY
VALUE_ABSENT = EvidenceKind.MISSING_VALUE


def normalize_path(key_path: str) -> str:
    """Normalize a registry path for case-insensitive comparison.

    Windows registry key names are case-insensitive. References keep their
    original spelling for human-readable reports, but all comparisons go
    through this normalized form.
    """
    path = key_path.replace("/", "\\").strip()
    if not path.startswith("\\"):
        path = "\\" + path
    normalized = path.rstrip("\\").upper()
    return normalized or "\\"


def path_is_within(candidate: str, root: str) -> bool:
    """True if ``candidate`` is ``root`` itself or one of its descendants."""
    normalized_candidate = normalize_path(candidate)
    normalized_root = normalize_path(root)
    if normalized_root == "\\":
        return True
    return normalized_candidate == normalized_root or normalized_candidate.startswith(normalized_root + "\\")


@dataclass(frozen=True)
class EvidenceRef:
    """A single registry fact that a conclusion depends on.

    :param kind: what kind of fact this reference describes.
    :param key_path: full registry path, always stored with a leading backslash.
    :param value_name: value name; only set for value-level references. The
                       empty string denotes the key default value.
    :param observed: content observed at report time (value references only).
                     Kept for human review and for describing modifications.
    :param note: optional free-text explanation of why the fact matters.
    """

    kind: EvidenceKind
    key_path: str
    value_name: Optional[str] = None
    observed: Any = None
    note: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.key_path.startswith("\\"):
            object.__setattr__(self, "key_path", "\\" + self.key_path.lstrip("\\"))

    @property
    def is_absence(self) -> bool:
        return self.kind in (EvidenceKind.MISSING_KEY, EvidenceKind.MISSING_VALUE)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceRef":
        return cls(
            kind=EvidenceKind(data["kind"]),
            key_path=data["key_path"],
            value_name=data.get("value_name"),
            observed=data.get("observed"),
            note=data.get("note"),
        )

    @classmethod
    def key(cls, key_path: str, note: Optional[str] = None) -> "EvidenceRef":
        return cls(kind=EvidenceKind.KEY, key_path=key_path, note=note)

    @classmethod
    def value(cls, key_path: str, value_name: str, observed: Any = None, note: Optional[str] = None) -> "EvidenceRef":
        return cls(
            kind=EvidenceKind.VALUE,
            key_path=key_path,
            value_name=value_name,
            observed=observed,
            note=note,
        )

    @classmethod
    def subtree(cls, key_path: str, note: Optional[str] = None) -> "EvidenceRef":
        return cls(kind=EvidenceKind.SUBTREE, key_path=key_path, note=note)

    @classmethod
    def missing_key(cls, key_path: str, note: Optional[str] = None) -> "EvidenceRef":
        return cls(kind=EvidenceKind.MISSING_KEY, key_path=key_path, note=note)

    @classmethod
    def missing_value(cls, key_path: str, value_name: str, note: Optional[str] = None) -> "EvidenceRef":
        return cls(
            kind=EvidenceKind.MISSING_VALUE,
            key_path=key_path,
            value_name=value_name,
            note=note,
        )
