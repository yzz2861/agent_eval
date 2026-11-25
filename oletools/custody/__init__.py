"""Progressive, custody-managed inspection backend for oletools.

The first inspection of a sample only observes its *structure*: embedded
objects are enumerated and fingerprinted by name, size and byte location,
but their payloads are never read.  That structural observation is sealed
into a custody manifest.

A later inspection receives the manifest together with the approvals
granted by the security team.  Only an object whose previous structural
observation is re-associated with an explicit approval may be released
(unsealed).  If the sample was replaced, or a same-named object moved to
different byte positions, the previous approval is explicitly revoked and
the object stays sealed.
"""

from oletools.custody.errors import (
    AccessDeniedError,
    ApprovalRevokedError,
    CustodyError,
    ManifestError,
)
from oletools.custody.guard import GuardedFile, RangeGate
from oletools.custody.manifest import Approval, CustodyManifest, Observation
from oletools.custody.scan import StructuralObservation, scan_file
from oletools.custody.backend import Backend, InspectionResult, ProgressiveBackend

__all__ = [
    'Backend',
    'ProgressiveBackend',
    'CustodyManifest',
    'Observation',
    'Approval',
    'StructuralObservation',
    'InspectionResult',
    'RangeGate',
    'GuardedFile',
    'CustodyError',
    'ManifestError',
    'AccessDeniedError',
    'ApprovalRevokedError',
]
