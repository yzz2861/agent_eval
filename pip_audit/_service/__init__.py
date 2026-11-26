"""
Vulnerability service interfaces and implementations for `pip-audit`.
"""

from .esms import EcosystemsService
from .freeze import (
    FreezeAdvisory,
    FreezeFixtureError,
    FreezeQuery,
    FreezeService,
    FreezeSnapshot,
    FrozenService,
    OfflineAdvisoryService,
    load_freeze_fixture,
    load_freeze_snapshot,
    snapshot_from_dict,
)
from .interface import (
    ConnectionError,
    Dependency,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from .osv import OsvService
from .pypi import PyPIService

__all__ = [
    "EcosystemsService",
    "FreezeAdvisory",
    "FreezeFixtureError",
    "FreezeQuery",
    "FreezeService",
    "FreezeSnapshot",
    "FrozenService",
    "OfflineAdvisoryService",
    "ConnectionError",
    "Dependency",
    "ResolvedDependency",
    "ServiceError",
    "SkippedDependency",
    "VulnerabilityResult",
    "VulnerabilityService",
    "OsvService",
    "PyPIService",
    "load_freeze_fixture",
    "load_freeze_snapshot",
    "snapshot_from_dict",
]
