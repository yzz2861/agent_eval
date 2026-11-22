"""Read-only registry evidence binding inspection for python-registry.

The package ingests a case bundle containing primary hives, transaction
logs and standalone registry excerpts, verifies how every encountered
record is reached and where it lives on disk, and only groups occurrences
into the same exhibit when their source chains can be proven consistent.
"""

from .models import Artifact, RecordOccurrence, Exhibit, BindingDecision
from .inspector import inspect_bundle

__all__ = [
    "Artifact",
    "RecordOccurrence",
    "Exhibit",
    "BindingDecision",
    "inspect_bundle",
]
