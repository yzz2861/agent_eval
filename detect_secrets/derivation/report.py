"""Persistence for derived-relationship analyses.

Only domain-separated, irreversible identities are written to disk. The
in-memory :class:`DerivationAnalysis` holds plaintext secret values for the
duration of the scan; this module strips them before serialization.
"""
import json
from typing import Any
from typing import Dict
from typing import Iterable

from .models import DerivationAnalysis


def build_report(
    analysis: DerivationAnalysis,
    *,
    include_unverified: bool = True,
) -> Dict[str, Any]:
    """Render a JSON-serializable report containing no plaintext secrets."""
    report = analysis.to_report().to_dict()
    if not include_unverified:
        report.pop("unverifiable_relationships", None)
    return report


def save_report(
    analysis: DerivationAnalysis,
    filename: str,
    *,
    include_unverified: bool = True,
) -> Dict[str, Any]:
    """Persist the report and return the serialized payload."""
    report = build_report(analysis, include_unverified=include_unverified)
    with open(filename, "w") as f:
        f.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def load_report(filename: str) -> Dict[str, Any]:
    """Load a previously persisted derivation report."""
    with open(filename) as f:
        return json.loads(f.read())


def assert_no_plaintext(report: Dict[str, Any], secrets: Iterable[str]) -> None:
    """Assert that none of ``secrets`` occur anywhere in the serialized report.

    Intended for tests and for callers that want an end-to-end guarantee that
    an on-disk artifact never carries raw credential material.
    """
    serialized = json.dumps(report)
    for secret in secrets:
        if secret and secret in serialized:
            raise AssertionError(
                f"plaintext secret leaked into derivation report: {secret!r}",
            )
