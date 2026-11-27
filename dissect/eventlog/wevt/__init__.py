from __future__ import annotations

from dissect.eventlog.wevt.mapping import (
    EventDefinition,
    EventDefinitionCatalog,
    EventField,
    EventIdentity,
    EventLocalizer,
    FieldIdentity,
    FieldTranslation,
    LocalizedEventMap,
    MessageResource,
)
from dissect.eventlog.wevt.offline import (
    FallbackReason,
    LookupPolicy,
    LookupStep,
    OfflineResourceCatalog,
    ResourceAttempt,
    ResourceKind,
    ResourceLookup,
    ResourceManifest,
    ResourceRecord,
    ResourceSource,
)
from dissect.eventlog.wevt.wevt import CRIM, MAPS_WEVT_TYPE, TTBL_WEVT_TYPE, WEVT, WEVT_TYPE
from dissect.eventlog.wevt.wevt_object import WevtObject

__all__ = (
    "CRIM",
    "MAPS_WEVT_TYPE",
    "TTBL_WEVT_TYPE",
    "WEVT",
    "WEVT_TYPE",
    "EventDefinition",
    "EventDefinitionCatalog",
    "EventField",
    "EventIdentity",
    "EventLocalizer",
    "FallbackReason",
    "FieldIdentity",
    "FieldTranslation",
    "LocalizedEventMap",
    "LookupPolicy",
    "LookupStep",
    "MessageResource",
    "OfflineResourceCatalog",
    "ResourceAttempt",
    "ResourceKind",
    "ResourceLookup",
    "ResourceManifest",
    "ResourceRecord",
    "ResourceSource",
    "WevtObject",
)
