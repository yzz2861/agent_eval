"""Data model for the diagnostic-structure leak audit.

The audit is deliberately name-agnostic: the outer type of the reported
structure is never trusted to prove that its fields cannot carry sensitive
data.  Every finding records the evidence (an expression rendered back from
the AST and a source coordinate) that explains why it was raised.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


# Provenance categories shared by the classifier and the engine.
SAFE = "safe"
FIELD_INIT = "field_init"
WHOLE_COPY = "whole_copy"
INDIRECT_REVIEW = "indirect_review"
INTERNAL = "internal_field"
UNKNOWN = "unknown"
UNSAFE = "unsafe"


class Severity(IntEnum):
    """Ordering matters: the highest severity wins for a function verdict."""

    SAFE = 0
    REVIEW = 1
    UNSAFE = 2


# Stable machine-readable codes for each kind of finding.
FIELD_FROM_SOURCE = "field_from_source"
WHOLE_STRUCT_COPY = "whole_struct_copy"
MEMCPY_COPY = "memcpy_copy"
UNBOUND_INDIRECT = "unbound_indirect_call"
UNBOUND_PROJECTION = "unbound_projection"
CONSTANT_FIELD = "constant_field"
KNOWN_PROJECTION = "known_projection"


@dataclass
class Finding:
    """A single piece of evidence collected during a function analysis."""

    severity: Severity
    code: str
    message: str
    coord: str
    function: str
    variable: str
    expression: str = ""
    source: str = ""

    def as_dict(self) -> dict:
        data = {
            "severity": self.severity.name,
            "code": self.code,
            "message": self.message,
            "location": self.coord,
            "function": self.function,
            "variable": self.variable,
        }
        if self.expression:
            data["expression"] = self.expression
        if self.source:
            data["source"] = self.source
        return data


@dataclass
class FunctionReport:
    """All findings for one analysed function plus its rolled-up verdict."""

    name: str
    coord: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> Severity:
        if not self.findings:
            return Severity.SAFE
        return max(item.severity for item in self.findings)

    def as_dict(self) -> dict:
        return {
            "function": self.name,
            "location": self.coord,
            "verdict": self.verdict.name,
            "findings": [item.as_dict() for item in self.findings],
        }
