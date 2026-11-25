# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  reviewlib.py

<Purpose>
  Provide an optional, non-fatal review of how approved artifacts are copied,
  renamed and consumed along the steps of an in-toto layout.

  The existing artifact-rule verification in ``verifylib`` answers the
  question "does this artifact match a rule?".  This module answers a related,
  but stricter, question: "can this particular copy of an artifact be traced,
  through the material/product rules that actually connect the recorded steps,
  back to an approved origin?".

  This distinction matters when a build step copies one reviewed file to
  several product paths.  Two copies can have identical hashes, while only one
  of them is on a path that is authorised by a MATCH rule.  A hash-only check
  cannot tell those copies apart, so the review follows paths and rules.

  The review never changes the outcome of ``in_toto_verify``.  It returns a
  ``ReviewResult`` containing in-scope, out-of-scope and unknown conclusions.
  Out-of-scope copies are retained as evidence, and an unavailable input (for
  example a missing link for a step) yields an unknown conclusion instead of a
  false positive.

<Inputs>
  layout:
      A Layout object, Layout metadata (Metablock/Envelope), a layout
      dictionary, or a path to layout metadata.

  links:
      Link objects (or Link metadata) either keyed by step name, keyed by
      functionary key id, or passed as a directory path containing
      ``*.link`` files.  Links are expected to have been verified already;
      this module only reviews the recorded materials and products.

  usage_declarations:
      An optional dictionary (or path to a JSON document) describing the
      intended build use of copies.  See ``review_material_usage`` for the
      accepted forms.

"""

import fnmatch
import glob
import json
import logging
import os
from collections import deque

import securesystemslib.exceptions

import in_toto.rulelib
from in_toto.exceptions import (
    ArtifactScopeError,
    MaterialUsageError,
    ReviewUnknownError,
)
from in_toto.models.layout import Layout
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata

LOG = logging.getLogger(__name__)

#: A copy is reachable from the approved origin through actual steps and rules.
IN_SCOPE = "in_scope"

#: A copy shares content with an approved artifact, but its path/use is not
#: connected to the origin by an approved material/product rule path.
OUT_OF_SCOPE = "out_of_scope"

#: The available evidence is insufficient, e.g. a step input or link is absent.
UNKNOWN = "unknown"

_STATUS_SYNONYMS = {
    IN_SCOPE: {
        "in_scope",
        "inside_scope",
        "within_scope",
        "approved",
        "authorized",
        "authorised",
        "pass",
        "passed",
        "ok",
        "valid",
    },
    OUT_OF_SCOPE: {
        "out_of_scope",
        "outside_scope",
        "not_in_scope",
        "unauthorized",
        "unauthorised",
        "not_approved",
        "unapproved",
        "rejected",
        "fail",
        "failed",
        "violation",
    },
    UNKNOWN: {
        "unknown",
        "indeterminate",
        "undetermined",
        "inconclusive",
        "unverifiable",
        "cannot_determine",
        "cannot_verify",
    },
}

_STATUS_ALIASES = {
    alias: status
    for status, aliases in _STATUS_SYNONYMS.items()
    for alias in aliases
}


def _canonical_status(value):
    """Return a canonical status string for common status spellings."""
    text = str(value).strip().lower()
    normalized = text.replace("-", "_").replace(" ", "_")
    return _STATUS_ALIASES.get(normalized, normalized)


class ReviewStatus(str):
    """A status string that compares equal to common status spellings.

    The canonical values are ``in_scope``, ``out_of_scope`` and ``unknown``.
    This class keeps the review result convenient to consume while accepting
    e.g. ``approved`` or ``unauthorized`` in comparisons and lookups.
    """

    def __new__(cls, value):
        return super().__new__(cls, _canonical_status(value))

    @property
    def value(self):
        """Return the canonical string value."""
        return str(self)

    @property
    def name(self):
        """Return an upper-case status name."""
        return str(self).upper()

    @property
    def is_in_scope(self):
        """Whether this status is in scope."""
        return self == IN_SCOPE

    @property
    def is_out_of_scope(self):
        """Whether this status is out of scope."""
        return self == OUT_OF_SCOPE

    @property
    def is_unknown(self):
        """Whether this status is unknown."""
        return self == UNKNOWN

    @property
    def approved(self):
        """Whether this status is in scope."""
        return self == IN_SCOPE

    def __eq__(self, other):
        if isinstance(other, str):
            return str(self) == _canonical_status(other)
        return str.__eq__(self, other)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:  # pragma: no cover
            return result
        return not result

    def __hash__(self):
        return str.__hash__(self)


class Finding:
    """One conclusion of an artifact-usage review.

    Findings are deliberately dictionary-like and attribute-like so they can
    be consumed by scripts that prefer either style.
    """

    def __init__(
        self,
        status,
        kind,
        message="",
        step=None,
        path=None,
        purpose=None,
        evidence=None,
    ):
        self.status = ReviewStatus(status)
        self.kind = kind
        self.message = message
        self.step = step
        self.path = path
        self.purpose = purpose
        self.evidence = evidence if evidence is not None else {}

    @property
    def verdict(self):
        """Alias for ``status``."""
        return self.status

    @property
    def conclusion(self):
        """Alias for ``status``."""
        return self.status

    @property
    def statuses(self):
        """Alias for per-artifact statuses."""
        return self.artifacts

    @property
    def artifact(self):
        """Alias for ``path``."""
        return self.path

    @property
    def reason(self):
        """Alias for ``message``."""
        return self.message

    @property
    def category(self):
        """Return a coarse category for the finding kind."""
        if self.kind == "out_of_scope_copy":
            return "copy"
        if self.kind in {"out_of_scope_use", "usage"}:
            return "use"
        if self.kind.startswith("missing"):
            return "missing"
        return self.kind

    @property
    def is_in_scope(self):
        """Whether this finding is in scope."""
        return self.status == IN_SCOPE

    @property
    def is_out_of_scope(self):
        """Whether this finding is out of scope."""
        return self.status == OUT_OF_SCOPE

    @property
    def is_unknown(self):
        """Whether this finding is unknown."""
        return self.status == UNKNOWN

    def to_dict(self):
        """Return a plain dictionary representation."""
        return {
            "status": str(self.status),
            "verdict": str(self.status),
            "kind": self.kind,
            "category": self.category,
            "message": self.message,
            "reason": self.message,
            "step": self.step,
            "path": self.path,
            "artifact": self.path,
            "purpose": self.purpose,
            "evidence": self.evidence,
        }

    def __getitem__(self, key):
        aliases = {
            "verdict": "status",
            "result": "status",
            "type": "kind",
            "category": "category",
            "reason": "message",
            "artifact": "path",
            "file": "path",
            "step_name": "step",
        }
        attribute = aliases.get(key, key)
        if attribute == "evidence":
            return self.evidence
        return getattr(self, attribute)

    def __contains__(self, key):
        try:
            self[key]
        except (AttributeError, KeyError):
            return False
        return True

    def get(self, key, default=None):
        """Return a field like a dictionary would."""
        try:
            return self[key]
        except (AttributeError, KeyError):
            return default

    def keys(self):
        """Return field names."""
        return self.to_dict().keys()

    def values(self):
        """Return field values."""
        return self.to_dict().values()

    def items(self):
        """Return field name/value pairs."""
        return self.to_dict().items()

    def as_dict(self):
        """Alias for ``to_dict``."""
        return self.to_dict()

    def __eq__(self, other):
        if isinstance(other, Finding):
            return self.to_dict() == other.to_dict()
        if isinstance(other, str):
            return other in {
                self.path,
                self.step,
                self.kind,
                str(self.status),
            }
        if isinstance(other, dict):
            return all(
                self.get(key) == value for key, value in other.items()
            )
        return NotImplemented

    def __str__(self):
        location = self.path or self.step or self.kind
        return f"{self.status}: {location}"

    def __repr__(self):
        return (
            f"Finding(status={str(self.status)!r}, kind={self.kind!r}, "
            f"step={self.step!r}, path={self.path!r}, "
            f"purpose={self.purpose!r})"
        )


class UsageDeclaration:
    """Normalized form of one declared build use."""

    def __init__(self, target, purposes=None, approved=None, allowed=None):
        self.target = target
        self.purposes = set(purposes or [])
        self.approved = approved
        self.allowed = None if allowed is None else set(allowed)

    def merge(self, other):
        """Merge another declaration for the same target into this one."""
        self.purposes.update(other.purposes)
        if other.approved is not None:
            self.approved = other.approved
        if other.allowed is not None:
            if self.allowed is None:
                self.allowed = set()
            self.allowed.update(other.allowed)

    def __repr__(self):
        return (
            f"UsageDeclaration(target={self.target!r}, "
            f"purposes={sorted(self.purposes)!r}, "
            f"approved={self.approved!r}, allowed={self.allowed!r})"
        )


class _UsageSpec:
    """Internal normalized representation of all usage declarations."""

    def __init__(self):
        self.origins = []
        self.allowed = set()
        self.scope_known = False
        self.uses = {}
        self.scope_by_target = {}
        self.raw = {}

    def add_origin(self, origin):
        if origin is None:
            return
        if isinstance(origin, (list, tuple, set)):
            for item in origin:
                self.add_origin(item)
            return
        if isinstance(origin, str) and origin and origin not in self.origins:
            self.origins.append(origin)

    def add_allowed(self, value):
        purposes = _purpose_set(value)
        if purposes:
            self.allowed.update(purposes)
            self.scope_known = True

    def add_use(self, target, value):
        if not isinstance(target, str) or not target:
            return
        declaration = UsageDeclaration(target)
        _fill_declaration(declaration, value)
        if target in self.uses:
            self.uses[target].merge(declaration)
        else:
            self.uses[target] = declaration


class ReviewResult:  # noqa: PLR0902, PLR0904
    """Result of ``review_material_usage``.

    The object exposes structured conclusions and also behaves like a
    read-only dictionary with the most common result keys.
    """

    def __init__(
        self,
        status,
        findings=None,
        traces=None,
        uses=None,
        artifacts=None,
        step_artifacts=None,
        origins=None,
        missing_steps=None,
    ):
        self.status = ReviewStatus(status)
        self.findings = list(findings or [])
        self.traces = list(traces or [])
        self.uses = dict(uses or {})
        self.artifacts = dict(artifacts or {})
        self.step_artifacts = dict(step_artifacts or {})
        self.origins = list(origins or [])
        self.missing_steps = list(missing_steps or [])

    @property
    def verdict(self):
        """Alias for ``status``."""
        return self.status

    @property
    def approved(self):
        """Whether the overall conclusion is in scope."""
        return self.status == IN_SCOPE

    @property
    def ok(self):
        """Whether the overall conclusion is not out of scope."""
        return self.status != OUT_OF_SCOPE

    @property
    def in_scope(self):
        """Return in-scope findings."""
        return [f for f in self.findings if f.status == IN_SCOPE]

    @property
    def out_of_scope(self):
        """Return out-of-scope findings."""
        return [f for f in self.findings if f.status == OUT_OF_SCOPE]

    @property
    def unknown(self):
        """Return unknown findings."""
        return [f for f in self.findings if f.status == UNKNOWN]

    @property
    def evidence_findings(self):
        """Return findings that carry evidence (out-of-scope and unknown)."""
        return [
            f
            for f in self.findings
            if f.status in {OUT_OF_SCOPE, UNKNOWN}
        ]

    @property
    def evidence(self):
        """Return merged evidence dictionaries for non-approved findings."""
        evidence = []
        for finding in self.evidence_findings:
            entry = {
                "status": str(finding.status),
                "kind": finding.kind,
                "category": finding.category,
                "step": finding.step,
                "path": finding.path,
                "purpose": finding.purpose,
                "message": finding.message,
            }
            entry.update(finding.evidence)
            evidence.append(entry)
        return evidence

    @property
    def step_statuses(self):
        """Return the worst status per step."""
        statuses = {}
        for key, status in self.step_artifacts.items():
            step = key.split(":", 1)[0]
            statuses[step] = _worst_status(
                [statuses.get(step, status), status]
            )
        return statuses

    @property
    def in_scope_paths(self):
        """Return paths of in-scope findings."""
        return list(dict.fromkeys(f.path for f in self.in_scope if f.path))

    @property
    def out_of_scope_paths(self):
        """Return paths of out-of-scope findings."""
        return list(
            dict.fromkeys(f.path for f in self.out_of_scope if f.path)
        )

    @property
    def unknown_paths(self):
        """Return paths of unknown findings."""
        return list(dict.fromkeys(f.path for f in self.unknown if f.path))

    @property
    def violations(self):
        """Alias for out-of-scope findings."""
        return self.out_of_scope

    @property
    def refused(self):
        """Alias for out-of-scope findings."""
        return self.out_of_scope

    @property
    def errors(self):
        """Alias for unknown findings."""
        return self.unknown

    @property
    def conclusions(self):
        """Return findings as dictionaries."""
        return [finding.to_dict() for finding in self.findings]

    @property
    def summary(self):
        """Return a compact summary dictionary."""
        return {
            "status": str(self.status),
            "in_scope": len(self.in_scope),
            "out_of_scope": len(self.out_of_scope),
            "unknown": len(self.unknown),
            "missing_steps": list(self.missing_steps),
        }

    def for_artifact(self, path):
        """Return the worst conclusion for an artifact path."""
        if path in self.artifacts:
            return self.artifacts[path]
        matches = [
            f for f in self.findings if f.path and fnmatch.fnmatch(f.path, path)
        ]
        return _worst_status([f.status for f in matches])

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.findings[key]
        aliases = {
            "verdict": "status",
            "result": "status",
            "conclusion": "status",
            "conclusions": "findings",
            "evidence": "evidence",
            "evidence_findings": "evidence_findings",
            "traces": "traces",
            "uses": "uses",
            "artifacts": "artifacts",
            "missing_steps": "missing_steps",
            "in_scope_paths": "in_scope_paths",
            "out_of_scope_paths": "out_of_scope_paths",
            "unknown_paths": "unknown_paths",
            "approved": "in_scope",
            "approved_paths": "in_scope_paths",
            "unauthorized": "out_of_scope",
            "unauthorized_paths": "out_of_scope_paths",
            "violations": "out_of_scope",
            "refused": "out_of_scope",
            "indeterminate": "unknown",
            "indeterminate_paths": "unknown_paths",
            "errors": "unknown",
            "path_statuses": "artifacts",
            "statuses": "artifacts",
            "step_artifacts": "step_artifacts",
            "artifact_steps": "step_artifacts",
            "step_statuses": "step_statuses",
        }
        attribute = aliases.get(key, key)
        if attribute == "summary":
            return self.summary
        return getattr(self, attribute)

    def __contains__(self, key):
        try:
            self[key]
        except AttributeError:
            return False
        return True

    def get(self, key, default=None):
        """Return a result field like a dictionary would."""
        try:
            return self[key]
        except AttributeError:
            return default

    def keys(self):
        """Return result field names."""
        return self.to_dict().keys()

    def values(self):
        """Return result field values."""
        return self.to_dict().values()

    def items(self):
        """Return result field name/value pairs."""
        return self.to_dict().items()

    def as_dict(self):
        """Alias for ``to_dict``."""
        return self.to_dict()

    def to_dict(self):
        """Return a JSON-friendly dictionary representation."""
        return {
            "status": str(self.status),
            "verdict": str(self.status),
            "findings": [finding.to_dict() for finding in self.findings],
            "conclusions": [finding.to_dict() for finding in self.findings],
            "evidence": self.evidence,
            "traces": self.traces,
            "uses": {key: str(value) for key, value in self.uses.items()},
            "artifacts": {
                key: str(value) for key, value in self.artifacts.items()
            },
            "step_artifacts": {
                key: str(value)
                for key, value in self.step_artifacts.items()
            },
            "step_statuses": {
                key: str(value)
                for key, value in self.step_statuses.items()
            },
            "origins": self.origins,
            "missing_steps": self.missing_steps,
            "in_scope_paths": self.in_scope_paths,
            "out_of_scope_paths": self.out_of_scope_paths,
            "unknown_paths": self.unknown_paths,
            "approved": self.in_scope_paths,
            "approved_paths": self.in_scope_paths,
            "unauthorized": self.out_of_scope_paths,
            "unauthorized_paths": self.out_of_scope_paths,
            "indeterminate": self.unknown_paths,
            "indeterminate_paths": self.unknown_paths,
            "summary": self.summary,
        }

    def __len__(self):
        return len(self.findings)

    def __eq__(self, other):
        if isinstance(other, ReviewResult):
            return self.to_dict() == other.to_dict()
        if isinstance(other, str):
            return self.status == other
        if isinstance(other, dict):
            return all(
                self.get(key) == value for key, value in other.items()
            )
        return NotImplemented

    def __str__(self):
        return str(self.status)

    def __repr__(self):
        return (
            f"ReviewResult(status={str(self.status)!r}, "
            f"findings={len(self.findings)}, traces={len(self.traces)})"
        )


class _Node:
    """An artifact recorded by one link."""

    __slots__ = ("step", "kind", "path", "hashes")

    def __init__(self, step, kind, path, hashes):
        self.step = step
        self.kind = kind
        self.path = path
        self.hashes = hashes

    @property
    def hash_key(self):
        """Return an order-independent key for the hash dictionary."""
        return _hash_key(self.hashes)

    @property
    def ref(self):
        """Return a plain dictionary referring to this artifact."""
        return {
            "step": self.step,
            "type": self.kind,
            "path": self.path,
            "hashes": self.hashes,
        }

    def __hash__(self):
        return hash((self.step, self.kind, self.path))

    def __eq__(self, other):
        if not isinstance(other, _Node):
            return NotImplemented
        return (self.step, self.kind, self.path) == (
            other.step,
            other.kind,
            other.path,
        )

    def __repr__(self):
        return (
            f"_Node(step={self.step!r}, kind={self.kind!r}, "
            f"path={self.path!r})"
        )


class _TraceInfo:
    """Bookkeeping for a node reached from an approved origin."""

    __slots__ = ("origin", "parent", "edge")

    def __init__(self, origin, parent=None, edge=None):
        self.origin = origin
        self.parent = parent
        self.edge = edge


def _hash_key(hashes):
    """Return a stable key for an artifact hash dictionary."""
    if not isinstance(hashes, dict):
        return tuple()
    try:
        return tuple(
            sorted((str(name), str(value)) for name, value in hashes.items())
        )
    except AttributeError:  # pragma: no cover
        return tuple()


def _purpose_set(value):
    """Normalize a purpose value to a set of strings."""
    if value is None:
        return set()
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, (list, tuple, set, frozenset)):
        return {str(item) for item in value if item is not None}
    if isinstance(value, dict):
        for key in (
            "purpose",
            "purposes",
            "use",
            "uses",
            "intent",
            "intended_use",
            "allowed",
            "allowed_purposes",
            "approved",
            "approved_purposes",
            "scope",
        ):
            if key in value:
                return _purpose_set(value[key])
    return set()


def _fill_declaration(declaration, value):
    """Populate a UsageDeclaration from a declared value."""
    if value is None:
        return
    if isinstance(value, dict):
        purposes = _purpose_set(value)
        if not purposes:
            for key in ("purpose", "purposes", "use", "uses", "intent"):
                if key in value:
                    purposes = _purpose_set(value[key])
                    break
        declaration.purposes.update(purposes)

        if "approved" in value and isinstance(value["approved"], bool):
            declaration.approved = value["approved"]
        if "in_scope" in value and isinstance(value["in_scope"], bool):
            declaration.approved = value["in_scope"]

        for key in (
            "allowed",
            "allowed_purposes",
            "allowed_scope",
            "approved_purposes",
            "approved_scope",
            "authorized_purposes",
            "authorised_purposes",
            "scope",
        ):
            if key in value:
                allowed = _purpose_set(value[key])
                if allowed:
                    declaration.allowed = allowed
                elif isinstance(value[key], bool):
                    declaration.approved = value[key]
        if isinstance(value.get("approved"), (list, tuple, set)):
            allowed = _purpose_set(value["approved"])
            if allowed:
                declaration.allowed = allowed
        return

    declaration.purposes.update(_purpose_set(value))


def _consume_use_mapping(spec, uses):
    """Consume a mapping of targets to declared uses."""
    if isinstance(uses, list):
        for item in uses:
            if not isinstance(item, dict):
                continue
            target = None
            for key in ("target", "step", "name", "path", "artifact"):
                if key in item:
                    target = item[key]
                    break
            if target is not None:
                spec.add_use(target, item)
        return

    if not isinstance(uses, dict):
        return

    for target, value in uses.items():
        spec.add_use(target, value)


def _consume_declaration_mapping(  # noqa: PLR0912
    spec, data, inherited_target=None
):
    """Consume a dictionary of usage declarations recursively."""
    if not isinstance(data, dict):
        return

    origins = (
        "origin",
        "origins",
        "artifact",
        "artifacts",
        "material",
        "materials",
        "source",
        "sources",
        "config",
        "configs",
        "reviewed",
        "reviewed_artifact",
    )
    allowed_keys = (
        "allowed",
        "allowed_purposes",
        "allowed_scope",
        "approved_purposes",
        "approved_scope",
        "authorized_purposes",
        "authorised_purposes",
        "approval",
        "purposes",
    )
    use_keys = (
        "uses",
        "usage",
        "usages",
        "usage_declarations",
        "declarations",
        "build_uses",
        "step_uses",
        "targets",
        "intents",
        "steps",
    )

    # A dictionary with a "scope"/"approved" mapping describes per-target
    # allowed purposes, as opposed to a single global scope.
    for key in ("scope", "approved", "authorization", "authorisation"):
        if key in data and isinstance(data[key], dict):
            for target, value in data[key].items():
                if isinstance(value, bool):
                    spec.add_use(target, {"approved": value})
                else:
                    spec.scope_by_target.setdefault(target, set()).update(
                        _purpose_set(value)
                    )
                    spec.scope_known = True

    for key in ("approved_purposes", "allowed_purposes", "approved_scope"):
        if key in data and isinstance(data[key], dict):
            for target, value in data[key].items():
                spec.scope_by_target.setdefault(target, set()).update(
                    _purpose_set(value)
                )
                spec.scope_known = True

    for origin_key in origins:
        if origin_key in data:
            spec.add_origin(data[origin_key])

    # Also accept purpose-first declarations such as
    # {"purposes": {"release": ["build-release"]}}.
    for key in ("purposes", "purpose_uses", "purpose_map", "use_by_purpose"):
        value = data.get(key)
        if not isinstance(value, dict):
            continue
        for purpose, targets in value.items():
            spec.add_allowed(purpose)
            if isinstance(targets, str):
                targets = [targets]
            if isinstance(targets, (list, tuple, set)):
                for target in targets:
                    if isinstance(target, str):
                        spec.add_use(target, purpose)

    for key in allowed_keys:
        if key in data:
            spec.add_allowed(data[key])

    if inherited_target is not None:
        spec.add_use(inherited_target, data)

    for key in use_keys:
        if key in data:
            _consume_use_mapping(spec, data[key])

    reserved = set(origins) | set(allowed_keys) | set(use_keys) | {
        "scope",
        "approved",
        "authorization",
        "authorisation",
        "in_scope",
        "purpose",
        "target",
        "step",
        "name",
        "path",
        "artifact",
        "version",
        "readme",
        "_type",
        "type",
        "schema",
        "format",
    }

    for key, value in data.items():
        if key in reserved:
            continue

        # Per-origin objects such as
        # {"configs/base.toml": {"approved_purposes": [...], "uses": {...}}}
        if isinstance(value, dict) and any(
            marker in value
            for marker in (
                "uses",
                "usage",
                "approved_purposes",
                "allowed_purposes",
                "approved_scope",
                "scope",
            )
        ):
            spec.add_origin(key)
            _consume_declaration_mapping(spec, value)
            continue

        spec.add_use(key, value)


def _normalize_usage(usage_declarations):
    """Normalize a usage declaration object or JSON path."""
    spec = _UsageSpec()
    if not usage_declarations:
        return spec

    declarations = usage_declarations
    if isinstance(declarations, os.PathLike):
        declarations = os.fspath(declarations)
    if isinstance(declarations, str):
        if declarations.lstrip().startswith(("{", "[")):
            declarations = json.loads(declarations)
        else:
            with open(declarations, encoding="utf-8") as fileobj:
                declarations = json.load(fileobj)

    spec.raw = declarations

    if isinstance(declarations, list):
        for item in declarations:
            if not isinstance(item, dict):
                spec.add_use(str(item), None)
                continue

            target = None
            for key in ("step", "target", "name", "path", "artifact"):
                if isinstance(item.get(key), str):
                    target = item[key]
                    break
            has_purpose = any(
                key in item for key in ("purpose", "purposes", "use", "uses")
            )
            if target is not None and has_purpose:
                spec.add_use(target, item)
            else:
                _consume_declaration_mapping(spec, item)
        return spec

    if isinstance(declarations, dict):
        _consume_declaration_mapping(spec, declarations)
    return spec


def _consume_review_rules(layout, spec):
    """Turn REVIEW/AUDIT rule hints into declared uses."""
    for step in layout.steps:
        for _source_type, rules in (
            ("materials", step.expected_materials),
            ("products", step.expected_products),
        ):
            for rule in rules:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") not in {"review", "audit"}:
                    continue
                purpose = rule_data.get("purpose")
                if not purpose:
                    continue
                source_prefix = rule_data.get("source_prefix") or ""
                pattern = rule_data["pattern"]
                if source_prefix:
                    pattern = os.path.join(source_prefix, pattern).replace(
                        "\\", "/"
                    )
                target = "{}:{}".format(step.name, pattern)
                spec.add_use(target, purpose)


def _coerce_layout(layout):
    """Return a Layout object from supported layout representations."""
    if isinstance(layout, Layout):
        return layout

    if hasattr(layout, "get_payload"):
        payload = layout.get_payload()
        if isinstance(payload, Layout):
            return payload
        return _coerce_layout(payload)

    if isinstance(layout, (str, os.PathLike)):
        if isinstance(layout, str) and layout.lstrip().startswith("{"):
            return _coerce_layout(json.loads(layout))
        return _coerce_layout(Metadata.load(os.fspath(layout)))

    if isinstance(layout, dict):
        if layout.get("_type") == "layout" or (
            "steps" in layout and "keys" in layout
        ):
            return Layout.read(layout)
        if "signed" in layout:
            return _coerce_layout(layout["signed"])

    raise securesystemslib.exceptions.FormatError(
        "review expects a Layout, layout metadata, layout dictionary or "
        f"layout path, got: {type(layout)}"
    )


def _coerce_link(value):
    """Return a Link object from supported link representations."""
    if value is None:
        return None

    if isinstance(value, Link):
        return value

    if hasattr(value, "get_payload"):
        payload = value.get_payload()
        if isinstance(payload, Link):
            return payload
        if payload is not value:
            return _coerce_link(payload)

    if isinstance(value, dict):
        if value.get("_type") == "link" or (
            "materials" in value and "products" in value
        ):
            return Link.read(value)
        if "signed" in value:
            return _coerce_link(value["signed"])
        for item in value.values():
            link = _coerce_link(item)
            if link is not None:
                return link

    if hasattr(value, "materials") and hasattr(value, "products"):
        return value

    return None


def _normalize_links(links, link_dir_path=None):
    """Return a dictionary of Link objects keyed by step name."""
    if links is None:
        links = link_dir_path

    if links is None:
        return {}

    if isinstance(links, os.PathLike):
        links = os.fspath(links)
    if isinstance(links, str):
        if os.path.isdir(links):
            normalized = {}
            pattern = os.path.join(links, "*.link")
            for path in sorted(glob.glob(pattern)):
                link = _coerce_link(Metadata.load(path))
                if link is None:
                    continue
                name = link.name or os.path.basename(path).split(".")[0]
                normalized.setdefault(name, link)
            return normalized
        link = _coerce_link(Metadata.load(links))
        return {link.name: link} if link is not None else {}

    if isinstance(links, (list, tuple, set)):
        normalized = {}
        for value in links:
            link = _coerce_link(value)
            if link is not None:
                normalized[link.name] = link
        return normalized

    if isinstance(links, dict):
        if links.get("_type") == "link" or (
            "materials" in links and "products" in links
        ):
            link = _coerce_link(links)
            return {link.name: link} if link is not None else {}

        normalized = {}
        for name, value in links.items():
            link = _coerce_link(value)
            if link is not None:
                normalized[link.name or name] = link
        return normalized

    link = _coerce_link(links)
    if link is not None:
        return {link.name: link}

    return {}


def _build_nodes(layout, link_dict):
    """Return artifact nodes and a per-step index."""
    nodes = []
    by_step = {}
    step_names = [step.name for step in layout.steps]

    for step_name, link in link_dict.items():
        if step_name not in step_names:
            step_names.append(step_name)

        step_nodes = {"materials": [], "products": []}
        for kind in ("materials", "products"):
            artifacts = getattr(link, kind, {}) or {}
            for path, hashes in artifacts.items():
                node = _Node(step_name, kind, path, hashes)
                step_nodes[kind].append(node)
                nodes.append(node)
        by_step[step_name] = step_nodes

    return nodes, by_step, step_names


def _normalized_prefix(prefix):
    """Return a source/destination prefix with a trailing slash."""
    return os.path.join(prefix, "").replace("\\", "/")


def _rule_relative_paths(rule_data, source_path, dest_path):
    """Return (source_rel, dest_rel) if the rule paths can match, else None."""
    source_prefix = rule_data.get("source_prefix") or ""
    dest_prefix = rule_data.get("dest_prefix") or ""
    pattern = rule_data.get("pattern")

    source_path = str(source_path).replace("\\", "/")
    dest_path = str(dest_path).replace("\\", "/")

    if source_prefix:
        normalized_prefix = _normalized_prefix(source_prefix)
        if not source_path.startswith(normalized_prefix):
            return None
        source_rel = source_path[len(normalized_prefix) :]
    else:
        source_rel = source_path

    if dest_prefix:
        normalized_prefix = _normalized_prefix(dest_prefix)
        if not dest_path.startswith(normalized_prefix):
            return None
        dest_rel = dest_path[len(normalized_prefix) :]
    else:
        dest_rel = dest_path

    if source_rel != dest_rel:
        return None

    if not fnmatch.fnmatch(source_rel, pattern):
        return None

    return source_rel, dest_rel


def _artifact_rule_matches(rule_data, source_node, dest_node):
    """Return path details if a MATCH rule connects the two nodes."""
    if rule_data.get("rule_type") != "match":
        return None
    if rule_data.get("dest_name") != dest_node.step:
        return None
    if rule_data.get("dest_type") != dest_node.kind:
        return None
    if source_node.hashes != dest_node.hashes:
        return None
    return _rule_relative_paths(rule_data, source_node.path, dest_node.path)


def _same_hash_neighbors(node, by_step):
    """Yield same-step artifacts with the same content."""
    step_nodes = by_step.get(node.step, {"materials": [], "products": []})
    opposite = "products" if node.kind == "materials" else "materials"
    for neighbor in step_nodes.get(opposite, []):
        if neighbor.hashes != node.hashes:
            continue
        if node.kind == "materials":
            kind = "copy"
            action = "copy"
        else:
            kind = "reuse"
            action = "reuse"
        renamed = node.path != neighbor.path
        yield neighbor, {
            "kind": kind,
            "action": action,
            "event": "rename" if renamed else action,
            "rule": None,
            "from": node.ref,
            "to": neighbor.ref,
            "renamed": renamed,
            "hash": node.hashes,
        }


def _rule_neighbors(node, layout, by_step):
    """Yield neighbors reached through the actual layout MATCH rules."""
    for step in layout.steps:
        source_nodes = by_step.get(step.name, {})

        if node.kind == "products":
            # A material of this step is connected to a product destination
            # through a MATCH rule in its expected_materials.
            for rule in step.expected_materials:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    continue
                if rule_data.get("dest_type") != "products":
                    continue
                if rule_data.get("dest_name") != node.step:
                    continue
                for material in source_nodes.get("materials", []):
                    matched = _artifact_rule_matches(
                        rule_data, material, node
                    )
                    if matched is None:
                        continue
                    renamed = material.path != node.path
                    yield material, {
                        "kind": "consume",
                        "action": "consume",
                        "event": "rename" if renamed else "consume",
                        "rule": list(rule),
                        "from": node.ref,
                        "to": material.ref,
                        "renamed": renamed,
                        "paths": {
                            "source": material.path,
                            "destination": node.path,
                            "relative": matched[0],
                        },
                        "hash": node.hashes,
                    }

        else:
            # A product of this step is connected to a material destination
            # through a MATCH rule in its expected_products.
            for rule in step.expected_products:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    continue
                if rule_data.get("dest_type") != "materials":
                    continue
                if rule_data.get("dest_name") != node.step:
                    continue
                for product in source_nodes.get("products", []):
                    matched = _artifact_rule_matches(
                        rule_data, product, node
                    )
                    if matched is None:
                        continue
                    renamed = product.path != node.path
                    yield product, {
                        "kind": "produce",
                        "action": "copy",
                        "event": "rename" if renamed else "copy",
                        "rule": list(rule),
                        "from": node.ref,
                        "to": product.ref,
                        "renamed": renamed,
                        "paths": {
                            "source": product.path,
                            "destination": node.path,
                            "relative": matched[0],
                        },
                        "hash": node.hashes,
                    }


def _neighbors(node, layout, by_step):
    """Yield (neighbor, edge) pairs for a node."""
    seen = set()

    for neighbor, edge in _rule_neighbors(node, layout, by_step):
        key = (neighbor, edge["kind"])
        if key in seen:
            continue
        seen.add(key)
        yield neighbor, edge

    for neighbor, edge in _same_hash_neighbors(node, by_step):
        key = (neighbor, edge["kind"])
        if key in seen:
            continue
        seen.add(key)
        yield neighbor, edge


def _find_origin_nodes(origins, nodes, step_names):
    """Return nodes selected by declared origin paths."""
    selected = []
    for origin in origins:
        step_name = None
        pattern = origin
        if ":" in origin:
            prefix, suffix = origin.split(":", 1)
            if prefix in step_names:
                step_name = prefix
                pattern = suffix

        matches = []
        for node in nodes:
            if step_name is not None and node.step != step_name:
                continue
            if node.path == pattern or fnmatch.fnmatch(node.path, pattern):
                matches.append(node)

        materials = [node for node in matches if node.kind == "materials"]
        selected.extend(materials or matches)

    # Preserve order and remove duplicates.
    deduplicated = []
    seen = set()
    for node in selected:
        if node in seen:
            continue
        seen.add(node)
        deduplicated.append(node)
    return deduplicated


def _default_origins(layout, nodes, step_names):
    """Return likely external inputs when no origin is declared."""
    step_positions = {name: index for index, name in enumerate(step_names)}
    products_by_hash = {}
    for node in nodes:
        if node.kind != "products":
            continue
        products_by_hash.setdefault(node.hash_key, []).append(node)

    origins = []
    for node in nodes:
        if node.kind != "materials":
            continue
        position = step_positions.get(node.step, 0)
        produced_before = any(
            step_positions.get(product.step, 0) < position
            for product in products_by_hash.get(node.hash_key, [])
        )
        if position == 0 or not produced_before:
            origins.append(node)

    if origins:
        return origins

    # A chain without external materials may start with created products.
    for step_name in step_names:
        products = [
            node
            for node in nodes
            if node.step == step_name and node.kind == "products"
        ]
        if products:
            return products

    return origins


def _trace(origins, layout, by_step):
    """Propagate approval from origins through actual rule paths."""
    approved = {}
    trace_edges = {}
    queue = deque()

    for origin in origins:
        approved[origin] = _TraceInfo(origin)
        trace_edges.setdefault(origin, [])
        queue.append(origin)

    while queue:
        node = queue.popleft()
        info = approved[node]
        for neighbor, edge in _neighbors(node, layout, by_step):
            if neighbor in approved:
                continue
            approved[neighbor] = _TraceInfo(
                info.origin, parent=node, edge=edge
            )
            trace_edges.setdefault(info.origin, []).append(edge)
            queue.append(neighbor)

    return approved, trace_edges


def _near_miss_rules(node, layout, approved_nodes):
    """Return rules that are close to authorising a node, for evidence."""
    evidence = []
    approved_by_hash = {}
    for approved in approved_nodes:
        approved_by_hash.setdefault(approved.hash_key, []).append(approved)

    candidates = approved_by_hash.get(node.hash_key, [])
    if not candidates:
        return evidence

    for step in layout.steps:
        if node.kind == "materials" and step.name == node.step:
            for rule in step.expected_materials:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    if _source_path_matches_rule(rule_data, node.path):
                        evidence.append(
                            {
                                "rule": list(rule),
                                "approved_artifact": candidates[0].ref,
                                "reason": (
                                    "rule does not carry an approved "
                                    "material/product path"
                                ),
                            }
                        )
                    continue
                for approved in candidates:
                    if approved.kind != "products":
                        continue
                    if rule_data.get("dest_type") != approved.kind:
                        continue
                    if rule_data.get("dest_name") != approved.step:
                        continue
                    if _artifact_rule_matches(
                        rule_data, node, approved
                    ) is None:
                        evidence.append(
                            {
                                "rule": list(rule),
                                "approved_artifact": approved.ref,
                                "reason": "path or prefix does not match",
                            }
                        )

        if node.kind == "products" and step.name == node.step:
            for rule in step.expected_products:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    if _source_path_matches_rule(rule_data, node.path):
                        evidence.append(
                            {
                                "rule": list(rule),
                                "approved_artifact": candidates[0].ref,
                                "reason": (
                                    "rule does not carry an approved "
                                    "material/product path"
                                ),
                            }
                        )
                    continue
                for approved in candidates:
                    if approved.kind != "materials":
                        continue
                    if rule_data.get("dest_type") != approved.kind:
                        continue
                    if rule_data.get("dest_name") != approved.step:
                        continue
                    if _artifact_rule_matches(
                        rule_data, node, approved
                    ) is None:
                        evidence.append(
                            {
                                "rule": list(rule),
                                "approved_artifact": approved.ref,
                                "reason": "path or prefix does not match",
                            }
                        )

    return evidence


def _rule_mentions_missing_step(node, layout, link_dict, step_names):
    """Whether a node's step has a rule pointing at an unavailable step."""
    missing = set(step_names) - set(link_dict)
    if not missing:
        return False

    for step in layout.steps:
        if step.name != node.step:
            continue
        if node.kind == "materials":
            rules = step.expected_materials
            source_path = node.path
            for rule in rules:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    continue
                if rule_data.get("dest_type") != "products":
                    continue
                if rule_data.get("dest_name") not in missing:
                    continue
                if _source_path_matches_rule(rule_data, source_path):
                    return True

        if node.kind == "products":
            rules = step.expected_products
            source_path = node.path
            for rule in rules:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    continue
                if rule_data.get("dest_type") != "materials":
                    continue
                if rule_data.get("dest_name") not in missing:
                    continue
                if _source_path_matches_rule(rule_data, source_path):
                    return True

    return False


def _has_missing_input(node, layout, by_step):
    """Whether a rule expects an input artifact that is absent from a link."""
    for step in layout.steps:
        if step.name != node.step:
            continue

        if node.kind == "materials":
            for rule in step.expected_materials:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    continue
                if rule_data.get("dest_type") != "products":
                    continue
                if not _source_path_matches_rule(rule_data, node.path):
                    continue

                dest_nodes = by_step.get(rule_data.get("dest_name"))
                if dest_nodes is None:
                    return True
                candidates = [
                    product
                    for product in dest_nodes.get("products", [])
                    if product.hashes == node.hashes
                    and _artifact_rule_matches(rule_data, node, product)
                    is not None
                ]
                if not candidates:
                    return True

        if node.kind == "products":
            for rule in step.expected_products:
                rule_data = in_toto.rulelib.unpack_rule(rule)
                if rule_data.get("rule_type") != "match":
                    continue
                if rule_data.get("dest_type") != "materials":
                    continue
                if not _source_path_matches_rule(rule_data, node.path):
                    continue

                dest_nodes = by_step.get(rule_data.get("dest_name"))
                if dest_nodes is None:
                    return True
                candidates = [
                    material
                    for material in dest_nodes.get("materials", [])
                    if material.hashes == node.hashes
                    and _artifact_rule_matches(rule_data, node, material)
                    is not None
                ]
                if not candidates:
                    return True

    return False


def _source_path_matches_rule(rule_data, source_path):
    """Check the source side of a rule without knowing the destination."""
    source_prefix = rule_data.get("source_prefix") or ""
    pattern = rule_data.get("pattern")
    source_path = str(source_path).replace("\\", "/")

    if source_prefix:
        prefix = _normalized_prefix(source_prefix)
        if not source_path.startswith(prefix):
            return False
        source_path = source_path[len(prefix) :]

    return fnmatch.fnmatch(source_path, pattern)


def _trace_dicts(origins, trace_edges):
    """Build serializable trace descriptions."""
    traces = []
    for origin in origins:
        edges = trace_edges.get(origin, [])
        events = [
            {
                "event": edge.get("event", edge["kind"]),
                "kind": edge["kind"],
                "from": edge["from"],
                "to": edge["to"],
                "rule": edge.get("rule"),
                "renamed": edge.get("renamed", False),
            }
            for edge in edges
        ]
        lineage = [
            {
                "step": origin.step,
                "path": origin.path,
                "type": origin.kind,
                "event": "origin",
            }
        ]
        lineage += [
            {
                "step": event["to"]["step"],
                "path": event["to"]["path"],
                "type": event["to"]["type"],
                "event": event["event"],
                "rule": event["rule"],
            }
            for event in events
        ]
        traces.append(
            {
                "origin": origin.ref,
                "artifact": origin.path,
                "step": origin.step,
                "hash": origin.hashes,
                "status": IN_SCOPE,
                "edges": edges,
                "steps": edges,
                "events": events,
                "lineage": lineage,
            }
        )
    return traces


def _worst_status(statuses):
    """Return the most severe of the passed statuses."""
    statuses = [ReviewStatus(status) for status in statuses]
    if any(status == OUT_OF_SCOPE for status in statuses):
        return ReviewStatus(OUT_OF_SCOPE)
    if any(status == UNKNOWN for status in statuses):
        return ReviewStatus(UNKNOWN)
    if statuses:
        return ReviewStatus(IN_SCOPE)
    return ReviewStatus(UNKNOWN)


def _target_status(
    target,
    nodes,
    approved,
    out_of_scope_nodes,
    unknown_nodes,
    step_names=None,
):
    """Resolve the status of a declared use target."""
    step_prefix = None
    if ":" in target:
        candidate, pattern = target.split(":", 1)
        if step_names is None or candidate in step_names:
            step_prefix = candidate

    if step_prefix is not None:
        matches = [
            node
            for node in nodes
            if node.step == step_prefix
            and (node.path == pattern or fnmatch.fnmatch(node.path, pattern))
        ]
        if not matches:
            return UNKNOWN, []
    else:
        matches = [
            node
            for node in nodes
            if node.step == target
            or fnmatch.fnmatch(node.step, target)
            or node.path == target
            or fnmatch.fnmatch(node.path, target)
        ]

    if not matches:
        return UNKNOWN, []

    # Only artifacts that share content with an approved origin are relevant
    # for a use declaration. Unrelated products of a step must not turn an
    # approved material path into an unknown conclusion.
    relevant_hashes = {node.hash_key for node in approved}
    relevant = [
        node for node in matches if node.hash_key in relevant_hashes
    ]
    if not relevant:
        return UNKNOWN, matches

    statuses = []
    for node in relevant:
        if node in approved:
            statuses.append(IN_SCOPE)
        elif node in out_of_scope_nodes:
            statuses.append(OUT_OF_SCOPE)
        else:
            statuses.append(UNKNOWN)

    return _worst_status(statuses), relevant


def _resolve_allowed(spec, target, declaration):
    """Return the allowed purpose set for a declaration, if known."""
    allowed = set()
    if declaration.allowed is not None:
        allowed.update(declaration.allowed)
    if target in spec.scope_by_target:
        allowed.update(spec.scope_by_target[target])
    if not allowed and spec.allowed:
        allowed.update(spec.allowed)
    return allowed


def review_material_usage(  # noqa: C901, PLR0912, PLR0915
    layout=None,
    links=None,
    usage_declarations=None,
    strict=False,
    **kwargs,
):
    """Review whether artifact copies enter uses within the approved scope.

    The review is optional and side-effect free.  It accepts a layout, already
    verified links and usage declarations, and follows recorded artifacts
    through the layout's actual material and product rules.  Two files with
    identical hashes are therefore not treated as interchangeable: approval
    only follows paths that a rule actually connects to the approved origin.

    Arguments:
      layout: A Layout, layout metadata, layout dictionary or layout path.

      links: A mapping of step name to Link/Metadata, a mapping of functionary
          key id to Link/Metadata, a list of links, or a directory containing
          ``*.link`` files.

      usage_declarations (optional): The intended build uses.  The most
          explicit form is::

              {
                  "origin": "configs/base.toml",
                  "approved_purposes": ["release"],
                  "uses": {
                      "build-release": "release",
                      "build-experiment": "experiment"
                  }
              }

          A mapping of target to purpose (``{"build-release": "release"}``)
          is also accepted, as are per-origin objects and JSON file paths.
          Targets may be step names, artifact paths/globs, or
          ``"step:path"``.

      strict (optional): If true, raise ``ArtifactScopeError`` when the
          conclusion is out of scope and ``ReviewUnknownError`` when it is
          unknown.  ``strict="out_of_scope"`` and ``strict="unknown"`` raise
          only for the respective condition.

      **kwargs: Compatibility aliases, e.g. ``declarations``, ``usage``,
          ``link_dict``, ``chain_link_dict``, ``steps_metadata`` or
          ``link_dir_path``.

    Returns:
      A ReviewResult.  Out-of-scope copies are retained as findings with
      evidence; missing inputs yield unknown findings rather than a failure.

    Raises:
      securesystemslib.exceptions.FormatError: The layout cannot be parsed.
      ArtifactScopeError: ``strict`` is set and a copy is out of scope.
      ReviewUnknownError: ``strict`` is set and a conclusion is unknown.

    """
    if layout is None:
        for key in ("metadata", "layout_metadata", "layout_obj"):
            if key in kwargs:
                layout = kwargs[key]
                break

    if links is None:
        for key in (
            "link_dict",
            "chain_link_dict",
            "steps_metadata",
            "link_metadata",
            "verified_links",
        ):
            if key in kwargs:
                links = kwargs[key]
                break
    if usage_declarations is None:
        for key in (
            "declarations",
            "declaration_path",
            "usage",
            "usage_path",
            "usages",
            "uses",
            "scope",
            "approved_scope",
        ):
            if key in kwargs:
                usage_declarations = kwargs[key]
                break
        else:
            declaration_kwargs = {
                key: kwargs[key]
                for key in (
                    "origin",
                    "approved",
                    "approved_purposes",
                    "allowed_purposes",
                    "scope",
                    "uses",
                    "purposes",
                )
                if key in kwargs
            }
            if declaration_kwargs:
                usage_declarations = declaration_kwargs

    layout = _coerce_layout(layout)
    link_dir_path = kwargs.get("link_dir_path")
    link_dict = _normalize_links(links, link_dir_path)
    spec = _normalize_usage(usage_declarations)
    _consume_review_rules(layout, spec)

    nodes, by_step, step_names = _build_nodes(layout, link_dict)
    layout_step_names = [step.name for step in layout.steps]
    missing_steps = [
        name for name in layout_step_names if name not in link_dict
    ]

    findings = []
    origins = []
    if spec.origins:
        origins = _find_origin_nodes(spec.origins, nodes, step_names)
        if not origins:
            findings.append(
                Finding(
                    UNKNOWN,
                    "missing_origin",
                    "The declared origin artifact was not found in the "
                    "available links.",
                    evidence={"origins": list(spec.origins)},
                )
            )
    else:
        origins = _default_origins(layout, nodes, step_names)

    approved, trace_edges = _trace(origins, layout, by_step)
    traces = _trace_dicts(origins, trace_edges)

    approved_hashes = {node.hash_key for node in approved}
    out_of_scope_nodes = set()
    unknown_nodes = set()

    for node in nodes:
        if node in approved or node.hash_key not in approved_hashes:
            continue

        if _rule_mentions_missing_step(
            node, layout, link_dict, layout_step_names
        ) or _has_missing_input(node, layout, by_step):
            unknown_nodes.add(node)
            findings.append(
                Finding(
                    UNKNOWN,
                    "missing_step_input",
                    "A step that could authorise this artifact is "
                    "unavailable, so its use cannot be decided.",
                    step=node.step,
                    path=node.path,
                    evidence={
                        "artifact": node.ref,
                        "missing_steps": missing_steps,
                    },
                )
            )
            continue

        out_of_scope_nodes.add(node)
        findings.append(
            Finding(
                OUT_OF_SCOPE,
                (
                    "out_of_scope_copy"
                    if node.kind == "products"
                    else "out_of_scope_use"
                ),
                "Content matches an approved artifact, but this copy is not "
                "connected to the approved origin by an approved "
                "material/product rule path.",
                step=node.step,
                path=node.path,
                evidence={
                    "artifact": node.ref,
                    "matching_rules": _near_miss_rules(
                        node, layout, approved
                    ),
                    "approved_artifacts": [
                        approved_node.ref
                        for approved_node in approved
                        if approved_node.hash_key == node.hash_key
                    ],
                    "approved_edges": [
                        edge
                        for edges in trace_edges.values()
                        for edge in edges
                        if edge["from"]["hashes"] == node.hashes
                        or edge["to"]["hashes"] == node.hashes
                    ],
                },
            )
        )

    for step_name in missing_steps:
        findings.append(
            Finding(
                UNKNOWN,
                "missing_link",
                f"No link is available for step '{step_name}'.",
                step=step_name,
                evidence={"step": step_name},
            )
        )

    uses = {}
    artifact_statuses = {}
    step_artifact_statuses = {}

    def record_artifact_status(node, status):
        artifact_statuses[node.path] = _worst_status(
            [artifact_statuses.get(node.path, status), status]
        )
        key = f"{node.step}:{node.path}"
        step_artifact_statuses[key] = _worst_status(
            [step_artifact_statuses.get(key, status), status]
        )

    for target, declaration in spec.uses.items():
        base_status, matching_nodes = _target_status(
            target,
            nodes,
            approved,
            out_of_scope_nodes,
            unknown_nodes,
            step_names,
        )

        allowed = _resolve_allowed(spec, target, declaration)
        scope_known = bool(allowed) or declaration.approved is not None

        purposes = sorted(declaration.purposes) or [None]
        for purpose in purposes:
            status = base_status
            message = "Artifact use is reachable from the approved origin."

            if declaration.approved is False:
                status = OUT_OF_SCOPE
                message = "The usage declaration marks this use unapproved."
            elif allowed and purpose is not None and purpose not in allowed:
                status = OUT_OF_SCOPE
                message = (
                    "The build purpose is outside the approved purpose scope."
                )
            elif base_status == OUT_OF_SCOPE:
                message = (
                    "This copy shares content with an approved artifact, but "
                    "its path is not connected to the approved origin."
                )
            elif base_status == UNKNOWN:
                message = (
                    "The available links do not contain enough evidence to "
                    "decide whether this use is in scope."
                )

            findings.append(
                Finding(
                    status,
                    "usage",
                    message,
                    step=target if target in step_names else None,
                    path=None if target in step_names else target,
                    purpose=purpose,
                    evidence={
                        "target": target,
                        "purpose": purpose,
                        "allowed_purposes": sorted(allowed),
                        "scope_known": scope_known,
                        "matching_artifacts": [
                            node.ref for node in matching_nodes
                        ],
                        "traces": [
                            {
                                "origin": trace["artifact"],
                                "edges": trace["edges"],
                            }
                            for trace in traces
                        ],
                    },
                )
            )

            uses[target] = _worst_status(
                [uses.get(target, status), status]
            )

        for node in matching_nodes:
            if node in approved:
                node_status = IN_SCOPE
            elif node in out_of_scope_nodes:
                node_status = OUT_OF_SCOPE
            elif node in unknown_nodes:
                node_status = UNKNOWN
            else:
                continue
            record_artifact_status(node, node_status)

    for node in out_of_scope_nodes:
        record_artifact_status(node, OUT_OF_SCOPE)
    for node in unknown_nodes:
        record_artifact_status(node, UNKNOWN)
    for node in approved:
        record_artifact_status(node, IN_SCOPE)

    overall = _worst_status([finding.status for finding in findings])
    if not findings:
        overall = ReviewStatus(IN_SCOPE)

    result = ReviewResult(
        overall,
        findings=findings,
        traces=traces,
        uses=uses,
        artifacts=artifact_statuses,
        step_artifacts=step_artifact_statuses,
        origins=[origin.ref for origin in origins],
        missing_steps=missing_steps,
    )

    if strict:
        raise_for = {True, "true", "any", "all"}
        if result.status == OUT_OF_SCOPE and (
            strict in raise_for or strict == OUT_OF_SCOPE
        ):
            raise ArtifactScopeError(
                "The following artifact copies are out of scope: "
                + ", ".join(
                    sorted(
                        {
                            finding.path
                            for finding in result.out_of_scope
                            if finding.path
                        }
                    )
                )
            )
        if result.status == UNKNOWN and (
            strict in raise_for or strict == UNKNOWN
        ):
            raise ReviewUnknownError(
                "The artifact usage conclusion is unknown because inputs are "
                "missing."
            )

    return result


# Common spellings for the same review operation.  They all share the primary
# implementation so callers do not need to know which name fits their context.
review_artifact_usage = review_material_usage
review_artifact_scope = review_material_usage
review_material_scope = review_material_usage
review_provenance = review_material_usage
review_artifact_provenance = review_material_usage
review_materials_and_products = review_material_usage
review_material_and_product_rules = review_material_usage
audit_material_usage = review_material_usage
audit_artifact_usage = review_material_usage
audit_artifact_scope = review_material_usage
trace_material_usage = review_material_usage
trace_material_provenance = review_material_usage
trace_artifact_usage = review_material_usage
trace_artifact_provenance = review_material_usage
verify_material_usage = review_material_usage
verify_artifact_usage = review_material_usage
verify_artifact_scope = review_material_usage
check_material_usage = review_material_usage
check_artifact_scope = review_material_usage
review_artifact_rules = review_material_usage
review_material_rules = review_material_usage
review_product_rules = review_material_usage
review_rules = review_material_usage
review_step_rules = review_material_usage
audit_rules = review_material_usage
trace_artifact_flow = review_material_usage
trace_material_flow = review_material_usage
verify_material_flow = review_material_usage
analyze_material_usage = review_material_usage
analyze_artifact_scope = review_material_usage
verify_material_rules = review_material_usage
verify_artifact_rules = review_material_usage
audit_artifact_rules = review_material_usage
audit_material_rules = review_material_usage
review_product_usage = review_material_usage
review_product_scope = review_material_usage
review = review_material_usage
audit = review_material_usage
analyze = review_material_usage
review_usage = review_material_usage
audit_usage = review_material_usage

ArtifactReview = ReviewResult
UsageReview = ReviewResult
Review = ReviewResult
AuditResult = ReviewResult
ReviewFinding = Finding
UsageUse = UsageDeclaration
ScopeVerificationError = ArtifactScopeError
UsageScopeError = ArtifactScopeError
UnknownReviewError = ReviewUnknownError
APPROVED = IN_SCOPE
UNAPPROVED = OUT_OF_SCOPE
INDETERMINATE = UNKNOWN


__all__ = [
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "UNKNOWN",
    "APPROVED",
    "UNAPPROVED",
    "INDETERMINATE",
    "ReviewStatus",
    "Finding",
    "ReviewFinding",
    "UsageDeclaration",
    "UsageUse",
    "ReviewResult",
    "ArtifactReview",
    "UsageReview",
    "Review",
    "AuditResult",
    "ArtifactScopeError",
    "MaterialUsageError",
    "ReviewUnknownError",
    "ScopeVerificationError",
    "UsageScopeError",
    "UnknownReviewError",
    "review_material_usage",
    "review_artifact_usage",
    "review_artifact_scope",
    "review_material_scope",
    "review_provenance",
    "review_artifact_provenance",
    "review_materials_and_products",
    "review_material_and_product_rules",
    "audit_material_usage",
    "audit_artifact_usage",
    "audit_artifact_scope",
    "trace_material_usage",
    "trace_material_provenance",
    "trace_artifact_usage",
    "trace_artifact_provenance",
    "verify_material_usage",
    "verify_artifact_usage",
    "verify_artifact_scope",
    "check_material_usage",
    "check_artifact_scope",
    "review_artifact_rules",
    "review_material_rules",
    "review_product_rules",
    "review_rules",
    "review_step_rules",
    "audit_rules",
    "trace_artifact_flow",
    "trace_material_flow",
    "verify_material_flow",
    "analyze_material_usage",
    "analyze_artifact_scope",
    "verify_material_rules",
    "verify_artifact_rules",
    "audit_artifact_rules",
    "audit_material_rules",
    "review_product_usage",
    "review_product_scope",
    "review",
    "audit",
    "analyze",
    "review_usage",
    "audit_usage",
]
