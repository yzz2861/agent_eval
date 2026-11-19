# Rule (plugin) version binding for exception decisions.
#
# An exception is bound to the rule version in effect when approved. A semver
# major bump denotes a breaking semantic change: old exceptions no longer apply
# to findings from the new rule and must be re-judged. Minor/patch bumps are
# semantically stable and carry the exception forward.
from dataclasses import dataclass
from typing import Any
from typing import Dict
import re


_SEMVER_RE = re.compile(r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")


def _parse_semver(version: str) -> tuple:
    match = _SEMVER_RE.fullmatch(version.strip())
    if not match:
        raise ValueError(f"invalid semantic version: {version!r}")
    return tuple(int(part) for part in match.groups())


@dataclass(frozen=True)
class RuleVersion:
    name: str
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, name: str, version: str) -> "RuleVersion":
        major, minor, patch = _parse_semver(version)
        return cls(name=name, major=major, minor=minor, patch=patch)

    def to_string(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.to_string()}

    def is_compatible_with(self, current: "RuleVersion") -> bool:
        # Same rule name and unchanged major version => semantics still apply.
        if self.name != current.name:
            return False
        return current.major == self.major
