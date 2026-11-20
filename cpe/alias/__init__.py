"""Enterprise-side alias arbitration in front of CPE name matching.

This sub-package adds an enterprise-controlled ruling interface that sits
before :class:`cpe.cpeset2_3.CPESet2_3`.  It only consumes explicit alias
relations whose source, business scope and validity period are recorded;
the original CPE equivalence judgement is reused unchanged.

Everything is in-memory: no database and no online bulletin source.
"""

from .model import (
    AliasRelation,
    Disposition,
    EdgeReason,
    EdgeStatus,
    MatchEvidence,
    MatchResult as ModelMatchResult,
    RelationConflict,
    ScopeViolation,
    scope_allows,
    scope_has_bare_wildcard,
)
from .registry import AliasRegistry
from .resolver import AliasResolver, AuthorizedChain, EdgeAttempt, Resolution
from .asset import Asset, AssetBook, Bulletin, ProductCatalog
from .arbitrator import EnterpriseArbitrator, MatchReport, MatchResult

__all__ = (
    "AliasRelation",
    "AliasRegistry",
    "AliasResolver",
    "Asset",
    "AssetBook",
    "AuthorizedChain",
    "Bulletin",
    "Disposition",
    "EdgeAttempt",
    "EdgeReason",
    "EdgeStatus",
    "EnterpriseArbitrator",
    "MatchEvidence",
    "MatchReport",
    "MatchResult",
    "ProductCatalog",
    "RelationConflict",
    "Resolution",
    "ScopeViolation",
    "scope_allows",
    "scope_has_bare_wildcard",
)
