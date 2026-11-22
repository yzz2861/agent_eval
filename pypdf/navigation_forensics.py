"""Compatibility import path for read-only navigation forensics."""

from .navigation import (
    DuplicateNameGroup,
    NamedDestinationEntry,
    NavigationChain,
    NavigationFinding,
    NavigationForensics,
    NavigationHop,
    NavigationReport,
    Source,
    analyze_navigation,
    audit_navigation,
    collect_navigation_evidence,
    inspect_navigation,
    navigation_forensics,
)

__all__ = [
    "DuplicateNameGroup",
    "NamedDestinationEntry",
    "NavigationChain",
    "NavigationFinding",
    "NavigationForensics",
    "NavigationHop",
    "NavigationReport",
    "Source",
    "analyze_navigation",
    "audit_navigation",
    "collect_navigation_evidence",
    "inspect_navigation",
    "navigation_forensics",
]
