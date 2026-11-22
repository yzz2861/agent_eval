"""
Policy configuration: metric allow-lists, severity bands and the missing-candidate rule.

A policy is the human-facing configuration a review board votes on. It deliberately cannot invent
vectors: the allow-list only *restricts* the kernel-proven legal universe. Any legal vector that
the allow-list excludes (or that lives on a metric value the board never listed) is reported as an
*uncovered* candidate, never silently treated as approved.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .universe import VERSIONS, LegalVector


class PolicyError(ValueError):
    """Raised when a policy configuration is internally inconsistent."""


@dataclass(frozen=True)
class Band:
    """A single severity band. ``lower`` inclusive, ``upper`` exclusive; last band open-ended."""

    name: str
    lower: float
    upper: Optional[float]
    disposition: str

    def contains(self, score: float) -> bool:
        if score < self.lower:
            return False
        return self.upper is None or score < self.upper


@dataclass(frozen=True)
class VersionPolicy:
    """Per-version policy: allowed metric values plus the ordered band table."""

    version: str
    allowed_values: Dict[str, Tuple[str, ...]]
    bands: Tuple[Band, ...]

    def band_of(self, score: float) -> Band:
        for band in self.bands:
            if band.contains(score):
                return band
        raise PolicyError(
            f"score {score} is not covered by any band in version {self.version}"
        )

    def is_allowed(self, values: Dict[str, str]) -> bool:
        for metric, value in values.items():
            if metric not in self.allowed_values:
                return False
            if value not in self.allowed_values[metric]:
                return False
        return True

    def validate_against(self, spec) -> List[str]:
        """Return human-readable problems; empty list means the policy is well-formed."""
        problems: List[str] = []
        for metric in spec.mandatory:
            if metric not in self.allowed_values:
                problems.append(
                    f"{self.version}: metric {metric} has no allowed-values entry"
                )
                continue
            unknown = sorted(set(self.allowed_values[metric]) - set(spec.domains[metric]))
            if unknown:
                problems.append(
                    f"{self.version}: metric {metric} lists non-existent values {unknown}"
                )
            if not self.allowed_values[metric]:
                problems.append(f"{self.version}: metric {metric} allows no values")
        extra = sorted(set(self.allowed_values) - set(spec.mandatory))
        if extra:
            problems.append(f"{self.version}: policy mentions unknown metrics {extra}")
        expected = 0.0
        for band in self.bands:
            if abs(band.lower - expected) > 1e-9:
                problems.append(
                    f"{self.version}: band {band.name} starts at {band.lower}, expected {expected}"
                )
            if band.upper is not None and band.upper <= band.lower:
                problems.append(f"{self.version}: band {band.name} has empty range")
            if band.upper is not None:
                expected = band.upper
        if self.bands and self.bands[-1].upper is not None:
            problems.append(
                f"{self.version}: last band {self.bands[-1].name} must be open-ended"
            )
        return problems


@dataclass
class Policy:
    """A full policy document covering one or more CVSS versions."""

    name: str
    version_policies: Dict[str, VersionPolicy]
    description: str = ""

    def version_policy(self, version: str) -> VersionPolicy:
        try:
            return self.version_policies[version]
        except KeyError as exc:
            raise PolicyError(
                f"policy {self.name!r} defines nothing for version {version}"
            ) from exc

    def partition_universe(
        self, universe: List[LegalVector]
    ) -> Tuple[List[LegalVector], List[LegalVector]]:
        """
        Split a kernel-proven universe into policy-covered vectors and uncovered candidates.

        Uncovered vectors are first-class audit output ("the board never voted on this"), not
        implicit approvals.
        """
        if not universe:
            return [], []
        version = universe[0].version
        vp = self.version_policy(version)
        covered: List[LegalVector] = []
        uncovered: List[LegalVector] = []
        for lv in universe:
            (covered if vp.is_allowed(lv.value_map) else uncovered).append(lv)
        return covered, uncovered


def _parse_band(raw: Dict) -> Band:
    return Band(
        name=str(raw["name"]),
        lower=float(raw["lower"]),
        upper=None if raw.get("upper") is None else float(raw["upper"]),
        disposition=str(raw.get("disposition", raw["name"])),
    )


def load_policy(data: Dict) -> Policy:
    """Parse and validate a policy document from a plain dictionary (e.g. parsed JSON)."""
    if "name" not in data or "versions" not in data:
        raise PolicyError("policy document needs name and versions keys")
    version_policies: Dict[str, VersionPolicy] = {}
    for version, section in data["versions"].items():
        if version not in VERSIONS:
            raise PolicyError(f"unknown CVSS version {version!r}")
        allowed = {
            metric: tuple(values) for metric, values in section["allowed_values"].items()
        }
        bands = tuple(_parse_band(raw) for raw in section["bands"])
        vp = VersionPolicy(version=version, allowed_values=allowed, bands=bands)
        problems = vp.validate_against(VERSIONS[version])
        if problems:
            raise PolicyError("; ".join(problems))
        version_policies[version] = vp
    return Policy(
        name=str(data["name"]),
        version_policies=version_policies,
        description=str(data.get("description", "")),
    )


def load_policy_file(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as handle:
        return load_policy(json.load(handle))
