"""Alternate import path for :mod:`stix2.imports`.

The feature is named after the problem it solves: resolving duplicate
identifiers during import.  Keep this module as a descriptive alias for code
that prefers to import it explicitly.
"""

from .imports import (
    AmbiguousCandidateError, AnchorError, AnchorRegistry, Attachment,
    IdentityAnchor, IdentityResolutionError, ImportedCandidate, ImportService,
    OccupancySlot, ReplayStep, Resolution, ResolutionStatus, attach_references,
    fingerprint, resolve_reference,
)

__all__ = [
    "AmbiguousCandidateError",
    "AnchorError",
    "AnchorRegistry",
    "Attachment",
    "IdentityAnchor",
    "IdentityResolutionError",
    "ImportService",
    "ImportedCandidate",
    "OccupancySlot",
    "ReplayStep",
    "Resolution",
    "ResolutionStatus",
    "attach_references",
    "fingerprint",
    "resolve_reference",
]
