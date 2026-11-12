### IMPORTS
### ============================================================================
## Future

## Standard Library
import warnings

## Installed

## Application
from . import audit
from . import json
from . import utils

### CONSTANTS
### ============================================================================
ORJSON_AVAILABLE = utils.package_is_available("orjson")
MSGSPEC_AVAILABLE = utils.package_is_available("msgspec")


### AUDIT EXPORTS
### ============================================================================
# Audit logging is explicitly opt-in: importing these names does not alter the
# behaviour of JsonFormatter or register any handler.
from .audit import (  # noqa: E402  pylint: disable=wrong-import-position
    AuditAnchor,
    AuditChainError,
    AuditChainFormatter,
    AuditChainHandler,
    AuditChainVerifier,
    AuditConfigurationError,
    AuditFileHandler,
    AuditFormatter,
    AuditHandler,
    AuditHmacFormatter,
    AuditIntegrityError,
    AuditJsonFormatter,
    AuditKey,
    AuditKeyRing,
    AuditLogFormatter,
    AuditRecord,
    AuditTrailFormatter,
    AuditTrailVerifier,
    AuditVerification,
    AuditVerifier,
    AuditWriteError,
    KeyRing,
    TamperEvidentFormatter,
    TamperEvidentVerifier,
    Verifier,
    canonical_json,
    replay_chain,
    verify_audit_chain,
    verify_chain,
)
