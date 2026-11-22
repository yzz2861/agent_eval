"""
Finite, specification-valid metric universes for each supported CVSS version.

The Red Hat ``cvss`` library is the authoritative scoring kernel. A combination is considered a
legal candidate only if the kernel constructs it without raising. We enumerate the Cartesian
product of the *base* metric value domains and let the kernel be the gatekeeper, which means a
combination that the specification does not allow can never be synthesised into a score.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Dict, Iterable, List, Optional, Tuple

from cvss import CVSS2, CVSS3, CVSS4
from cvss.constants2 import METRICS_MANDATORY as MANDATORY_2
from cvss.constants2 import METRICS_VALUE_NAMES as NAMES_2
from cvss.constants3 import METRICS_MANDATORY as MANDATORY_3
from cvss.constants3 import METRICS_VALUE_NAMES as NAMES_3
from cvss.constants4 import METRICS_MANDATORY as MANDATORY_4
from cvss.constants4 import METRICS_VALUE_NAMES as NAMES_4
from cvss.exceptions import CVSSError


@dataclass(frozen=True)
class VersionSpec:
    """Static description of a CVSS version's base metric universe."""

    version: str
    prefix: str
    mandatory: Tuple[str, ...]
    domains: Dict[str, Tuple[str, ...]]
    cls: type

    def render(self, values: Dict[str, str]) -> str:
        """Render a metric/value mapping into a canonical full base vector string."""
        body = "/".join(f"{metric}:{values[metric]}" for metric in self.mandatory)
        return f"{self.prefix}{body}"


def _spec(version: str, prefix: str, mandatory: List[str], names, cls) -> VersionSpec:
    domains = {metric: tuple(names[metric].keys()) for metric in mandatory}
    return VersionSpec(version, prefix, tuple(mandatory), domains, cls)


VERSIONS: Dict[str, VersionSpec] = {
    "2.0": _spec("2.0", "", MANDATORY_2, NAMES_2, CVSS2),
    "3.0": _spec("3.0", "CVSS:3.0/", MANDATORY_3, NAMES_3, CVSS3),
    "3.1": _spec("3.1", "CVSS:3.1/", MANDATORY_3, NAMES_3, CVSS3),
    "4.0": _spec("4.0", "CVSS:4.0/", MANDATORY_4, NAMES_4, CVSS4),
}


@dataclass(frozen=True)
class LegalVector:
    """A single specification-valid base vector with its kernel-computed base score."""

    version: str
    vector: str
    values: Tuple[Tuple[str, str], ...]
    score: float

    @property
    def value_map(self) -> Dict[str, str]:
        return dict(self.values)


def score_vector(version: str, values: Dict[str, str]) -> float:
    """
    Compute the base score for a metric/value mapping.

    Raises ``CVSSError`` if the combination is not a legal vector. Callers must treat an exception
    as "no such candidate" rather than inventing a score.
    """
    spec = VERSIONS[version]
    if set(values) != set(spec.mandatory):
        raise CVSSError(
            f"version {version} expects metrics {spec.mandatory}, got {sorted(values)}"
        )
    for metric, value in values.items():
        if value not in spec.domains[metric]:
            raise CVSSError(
                f"version {version} metric {metric} has no legal value {value!r}"
            )
    vector = spec.render(values)
    return float(spec.cls(vector).scores()[0])


def iter_raw_combinations(version: str) -> Iterable[Dict[str, str]]:
    """Yield every Cartesian combination of the base metric value domains."""
    spec = VERSIONS[version]
    domain_values = [spec.domains[metric] for metric in spec.mandatory]
    for combo in product(*domain_values):
        yield dict(zip(spec.mandatory, combo))


def build_universe(version: str) -> List[LegalVector]:
    """
    Build the finite set of legal base vectors for a version.

    Every yielded vector has been accepted and scored by the kernel; rejected combinations are
    recorded nowhere and cannot enter later graph analysis.
    """
    spec = VERSIONS[version]
    legal: List[LegalVector] = []
    for values in iter_raw_combinations(version):
        vector = spec.render(values)
        try:
            score = float(spec.cls(vector).scores()[0])
        except CVSSError:
            # Specification-invalid combination: not a candidate and never a vote.
            continue
        legal.append(
            LegalVector(
                version=version,
                vector=vector,
                values=tuple((metric, values[metric]) for metric in spec.mandatory),
                score=score,
            )
        )
    return legal


def find_vector(version: str, values: Dict[str, str]) -> Optional[LegalVector]:
    """Return the legal vector matching ``values`` (all mandatory metrics supplied), else None."""
    spec = VERSIONS[version]
    if set(values) != set(spec.mandatory):
        return None
    vector = spec.render(values)
    try:
        score = float(spec.cls(vector).scores()[0])
    except CVSSError:
        return None
    return LegalVector(
        version=version,
        vector=vector,
        values=tuple((metric, values[metric]) for metric in spec.mandatory),
        score=score,
    )
