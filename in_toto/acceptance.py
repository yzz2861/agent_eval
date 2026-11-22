# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  acceptance.py

<Purpose>
  Optional completeness acceptance on top of in-toto verification.

  Regular in-toto verification proves that the artifacts a step *did* report
  satisfy the layout's artifact rules. It has no notion of the scope that was
  searched when a link was recorded. Consequently, an empty artifact table is
  accepted just like a non-empty one, even if the table is empty because the
  recorded scope was wrong or too narrow.

  This module adds an opt-in check for "this artifact class must not exist".
  The check consumes a signed enumeration declaration (see below) together
  with the step's artifact commitments to tell three situations apart:

  ``confirmed_none``
      A complete and signed enumeration covered the relevant scope, exclusions
      do not mask the forbidden artifact class, and no forbidden artifact was
      observed.

  ``allowed_omission``
      The relevant scope was not enumerated, but the step did not commit to
      producing artifacts there, or a reason-bearing exclusion explains the
      omission without hiding the forbidden artifact class.

  ``evidence_missing``
      The artifact table is empty (or silent), but the signed evidence is not
      sufficient to conclude that the relevant scope was actually searched.

  ``artifacts_present`` is reported separately for a non-empty observation of
  the forbidden artifact class.

  The signed declaration is a reserved key in ``Link.byproducts`` (and for
  convenience also accepted in ``Link.environment``). Both fields are part of
  the signed link payload, so a declaration cannot be added or changed without
  invalidating the link signature::

      {
        "artifact_enumeration": {
          "products": {
            "boundary": ["dist", "build/release"],
            "complete": true,
            "exclusions": [
              {
                "pattern": "**/*.map",
                "reason": "source maps are not part of the release bundle"
              }
            ]
          },
          "materials": {
            "boundary": ["src"],
            "complete": true
          }
        }
      }

  ``boundary`` lists the paths/prefixes that were enumerated. ``complete``
  asserts that enumeration inside the boundary did not silently stop early.
  ``exclusions`` list patterns that were intentionally not recorded, each with
  a human-readable reason. A declaration may also use ``mode: "complete"``
  instead of ``complete: true``.

"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from in_toto import rulelib
from in_toto.exceptions import AcceptanceError

ENUMERATION_KEY = "artifact_enumeration"

CONFIRMED_NONE = "confirmed_none"
ALLOWED_OMISSION = "allowed_omission"
EVIDENCE_MISSING = "evidence_missing"
ARTIFACTS_PRESENT = "artifacts_present"

ACCEPTED = frozenset({CONFIRMED_NONE, ALLOWED_OMISSION})
DIRECTIONS = frozenset({"products", "materials", "both"})

_WILDCARD_RE = re.compile(r"[*?\[]")
_UNKNOWN = object()


def _normalize_path(path):
    """Normalize a path for scope and boundary comparisons."""
    path = str(path).replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if path in {"", "."}:
        return "."
    path = path.rstrip("/")
    return path or "/"


def _under(path, prefix):
    """Return True if ``path`` is ``prefix`` or below it."""
    path = _normalize_path(path)
    prefix = _normalize_path(prefix)
    if prefix in {".", "/"}:
        return True
    return path == prefix or path.startswith(prefix + "/")


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _static_prefix(pattern):
    """Return the non-glob path prefix of a rule or exclusion pattern."""
    pattern = str(pattern).replace("\\", "/")
    match = _WILDCARD_RE.search(pattern)
    if match is None:
        return _normalize_path(pattern)
    head = pattern[: match.start()].rstrip("/")
    return _normalize_path(head or ".")


def _match_path(path, pattern):
    """Match an artifact path against a gitignore-like glob pattern."""
    path = _normalize_path(path)
    pattern = str(pattern).replace("\\", "/")

    candidates = [pattern]
    if pattern.startswith("**/"):
        candidates.append(pattern[3:])

    for candidate in candidates:
        if _WILDCARD_RE.search(candidate):
            if fnmatch.fnmatchcase(path, candidate):
                return True
        elif _under(path, candidate):
            return True

    return False


def _glob_samples(pattern):
    """Return representative strings for a glob pattern.

    This is a deliberately small heuristic used only to decide whether an
    exclusion pattern could possibly overlap a forbidden artifact pattern.
    """
    pattern = str(pattern).replace("\\", "/")
    variants = {pattern}
    if pattern.startswith("**/"):
        variants.add(pattern[3:])

    samples = set()
    for variant in variants:
        sample = variant.replace("**/", "")
        sample = re.sub(r"\[[^\]]*\]", "x", sample)
        sample = sample.replace("*", "x").replace("?", "x")
        samples.add(sample)

        dirname, _, basename = sample.rpartition("/")
        if dirname:
            samples.add(f"{dirname}/x/{basename}")
        else:
            samples.add(f"x/{basename}")

    return samples


def _patterns_may_intersect(first, second):
    """Best-effort overlap test for two glob patterns."""
    if any(_match_path(sample, second) for sample in _glob_samples(first)):
        return True
    return any(_match_path(sample, first) for sample in _glob_samples(second))


@dataclass(frozen=True)
class Exclusion:
    """A signed note about artifacts that were intentionally not recorded."""

    patterns: tuple
    reason: str = ""

    @property
    def valid(self):
        """An exclusion only explains an omission if it carries a reason."""
        return bool(self.patterns) and bool(self.reason.strip())

    def to_dict(self):
        return {"patterns": list(self.patterns), "reason": self.reason}


@dataclass
class Declaration:
    """Parsed signed enumeration declaration for one artifact direction."""

    direction: str
    boundary: list
    complete: bool
    exclusions: list

    def covers(self, scope_entry):
        """Return True if the complete boundary covers ``scope_entry``."""
        if not self.complete:
            return False
        return any(_under(scope_entry, entry) for entry in self.boundary)


def _parse_exclusion(raw):
    if isinstance(raw, str):
        return Exclusion((raw,), "")
    if not isinstance(raw, dict):
        return Exclusion((), "")

    patterns = _as_list(raw.get("patterns") or raw.get("pattern"))
    reason = raw.get("reason") or raw.get("note") or ""
    return Exclusion(tuple(patterns), str(reason))


def _parse_declaration(raw, direction):
    if not isinstance(raw, dict):
        return None

    section = raw.get(direction)
    if not isinstance(section, dict):
        direct_keys = {
            "boundary",
            "paths",
            "scope",
            "complete",
            "mode",
            "enumeration",
            "exclusions",
        }
        if not direct_keys.intersection(raw):
            return None
        section = raw

    boundary = [
        _normalize_path(path)
        for path in _as_list(
            section.get("boundary")
            or section.get("paths")
            or section.get("scope")
        )
    ]

    complete = bool(section.get("complete"))
    mode = section.get("mode") or section.get("enumeration")
    if not complete and isinstance(mode, str):
        complete = mode.lower() == "complete"

    exclusions = [
        _parse_exclusion(item) for item in _as_list(section.get("exclusions"))
    ]

    return Declaration(direction, boundary, complete, exclusions)


def get_declaration(link, direction):
    """Return a link's signed declaration for ``direction``, if any."""
    for container_name in ("byproducts", "environment"):
        container = getattr(link, container_name, None) or {}
        declaration = _parse_declaration(
            container.get(ENUMERATION_KEY), direction
        )
        if declaration is not None:
            return declaration
    return None


def build_enumeration_declaration(
    boundary,
    exclude_patterns=None,
    exclusion_reasons=None,
    complete=True,
    direction=None,
):
    """Build a signed-declaration dictionary for one artifact direction.

    ``exclusion_reasons`` may map an exclude pattern to a human-readable
    reason. Patterns without a reason are still recorded, but they do not
    explain an omission during acceptance.

    If ``direction`` is passed the declaration is nested under that artifact
    direction, ready to be stored as the value of
    ``byproducts["artifact_enumeration"]``. Otherwise the bare section is
    returned.
    """
    exclusion_reasons = exclusion_reasons or {}
    exclusions = [
        {
            "pattern": pattern,
            "reason": exclusion_reasons.get(pattern, ""),
        }
        for pattern in _as_list(exclude_patterns)
    ]

    declaration = {
        "boundary": [_normalize_path(path) for path in _as_list(boundary)],
        "complete": bool(complete),
        "exclusions": exclusions,
    }
    if direction is not None:
        return {direction: declaration}
    return declaration


@dataclass
class ArtifactAbsenceCheck:
    """Configuration for an artifact absence completeness check.

    Attributes:
      patterns: Glob patterns describing the forbidden artifact class, e.g.
          ``["*.debug", "**/*.debug"]``.

      scope: Paths/prefixes that the release check cares about. The acceptance
          layer only counts evidence that covers these paths.

      direction: One of ``products``, ``materials`` or ``both``.

      allow_forbidden_exclusions: If True, a reason-bearing exclusion that may
          hide the forbidden artifact class is accepted as an allowed omission.
          By default such an exclusion makes the evidence insufficient, because
          excluded debug artifacts cannot be distinguished from absent ones.

      allow_omission: If False, ``allowed_omission`` is also treated as a
          failure by :meth:`AcceptanceReport.ok`.

    """

    patterns: list
    scope: list = field(default_factory=lambda: ["."])
    direction: str = "products"
    allow_forbidden_exclusions: bool = False
    allow_omission: bool = True

    def __post_init__(self):
        self.patterns = [str(item) for item in _as_list(self.patterns)]
        self.scope = [_normalize_path(item) for item in _as_list(self.scope)]
        self.direction = str(self.direction).lower()

        if not self.patterns:
            raise ValueError("'patterns' must contain at least one pattern")
        if not self.scope:
            raise ValueError("'scope' must contain at least one path")
        if self.direction not in DIRECTIONS:
            raise ValueError(
                "'direction' must be one of 'products', 'materials', 'both'"
            )

    @property
    def directions(self):
        if self.direction == "both":
            return ["products", "materials"]
        return [self.direction]

    def to_dict(self):
        return {
            "patterns": list(self.patterns),
            "scope": list(self.scope),
            "direction": self.direction,
            "allow_forbidden_exclusions": self.allow_forbidden_exclusions,
            "allow_omission": self.allow_omission,
        }


# A more explicit alias for callers that prefer the "completeness" wording.
CompletenessCheck = ArtifactAbsenceCheck


@dataclass
class Observation:
    """Assessment of one independent artifact observation."""

    source: str
    step: str
    direction: str
    status: str
    reason: str
    observed_count: int = 0
    forbidden_count: int = 0
    boundary: list = field(default_factory=list)
    complete: bool = False
    exclusions: list = field(default_factory=list)
    required_scope: list = field(default_factory=list)
    covered_scope: list = field(default_factory=list)
    allowed_scope: list = field(default_factory=list)
    missing_scope: list = field(default_factory=list)
    missing_evidence: list = field(default_factory=list)

    def to_dict(self):
        return {
            "source": self.source,
            "step": self.step,
            "direction": self.direction,
            "status": self.status,
            "reason": self.reason,
            "observed_count": self.observed_count,
            "forbidden_count": self.forbidden_count,
            "boundary": list(self.boundary),
            "complete": self.complete,
            "exclusions": [item.to_dict() for item in self.exclusions],
            "required_scope": list(self.required_scope),
            "covered_scope": list(self.covered_scope),
            "allowed_scope": list(self.allowed_scope),
            "missing_scope": list(self.missing_scope),
            "missing_evidence": list(self.missing_evidence),
        }


@dataclass
class StepAssessment:
    """Aggregated assessment of one Step across independent observations."""

    step: str
    status: str
    reason: str
    observations: list = field(default_factory=list)
    required_scope: list = field(default_factory=list)
    covered_scope: list = field(default_factory=list)
    allowed_scope: list = field(default_factory=list)
    missing_scope: list = field(default_factory=list)
    missing_evidence: list = field(default_factory=list)

    def to_dict(self):
        return {
            "step": self.step,
            "status": self.status,
            "reason": self.reason,
            "required_scope": list(self.required_scope),
            "covered_scope": list(self.covered_scope),
            "allowed_scope": list(self.allowed_scope),
            "missing_scope": list(self.missing_scope),
            "missing_evidence": list(self.missing_evidence),
            "observations": [item.to_dict() for item in self.observations],
        }


@dataclass
class AcceptanceReport:
    """Auditable result of an artifact absence check."""

    check: ArtifactAbsenceCheck
    steps: list = field(default_factory=list)
    links: list = field(default_factory=list)

    @property
    def status(self):
        statuses = [step.status for step in self.steps]
        statuses += [link.status for link in self.links]

        if ARTIFACTS_PRESENT in statuses:
            return ARTIFACTS_PRESENT
        # A single unproven observation is not cancelled by other evidence.
        if EVIDENCE_MISSING in statuses:
            return EVIDENCE_MISSING
        if statuses and all(status == CONFIRMED_NONE for status in statuses):
            return CONFIRMED_NONE
        if statuses:
            return ALLOWED_OMISSION
        return CONFIRMED_NONE

    def ok(self, require_confirmed=False):
        if self.status == ARTIFACTS_PRESENT:
            return False
        if self.status == EVIDENCE_MISSING:
            return False
        if require_confirmed:
            return self.status == CONFIRMED_NONE
        if self.status == ALLOWED_OMISSION:
            return self.check.allow_omission
        return True

    def to_dict(self):
        return {
            "status": self.status,
            "passed": self.ok(),
            "check": self.check.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "links": [link.to_dict() for link in self.links],
        }

    def format_text(self):
        """Return a human-readable audit report."""
        lines = [
            "Artifact absence acceptance",
            "  forbid: {}".format(", ".join(self.check.patterns)),
            "  scope: {}".format(", ".join(self.check.scope)),
            f"  direction: {self.check.direction}",
            "  overall: {} ({})".format(
                self.status, "pass" if self.ok() else "fail"
            ),
        ]

        for step in self.steps:
            lines.append(f"- step '{step.step}': {step.status} - {step.reason}")
            for observation in step.observations:
                lines.extend(_format_observation(observation, "    "))
            observation_needs = {
                item
                for observation in step.observations
                for item in observation.missing_evidence
            }
            lines.extend(
                f"    needs: {item}"
                for item in step.missing_evidence
                if item not in observation_needs
            )

        for observation in self.links:
            lines.append(f"- {observation.source}: {observation.status}")
            lines.extend(_format_observation(observation, "    ", header=False))

        return "\n".join(lines)


def _format_observation(observation, indent, header=True):
    prefix = " " * len(indent)
    lines = []
    if header:
        lines.append(
            f"{indent}- {observation.source}: {observation.status} - {observation.reason}"
        )
    else:
        lines.append(f"{prefix}{observation.status} - {observation.reason}")

    lines.append(
        f"{prefix}  observed: {observation.observed_count} artifact(s), {observation.forbidden_count} forbidden"
    )

    lines.append(
        "{}  signed boundary: {}; complete: {}".format(
            prefix,
            observation.boundary or "<missing>",
            observation.complete,
        )
    )

    if observation.exclusions:
        lines.append(f"{prefix}  exclusion notes:")
        lines.extend(
            "{}    {} (reason: {})".format(
                prefix,
                ", ".join(exclusion.patterns),
                exclusion.reason or "<missing>",
            )
            for exclusion in observation.exclusions
        )

    lines.extend(
        f"{prefix}  needs: {item}" for item in observation.missing_evidence
    )

    return lines


def _forbidden_artifacts(observed, check):
    return sorted(
        path
        for path in observed
        if any(_under(path, scope) for scope in check.scope)
        and any(_match_path(path, pattern) for pattern in check.patterns)
    )


def _exclusion_masks(exclusion, check):
    return any(
        _patterns_may_intersect(exclusion_pattern, forbidden)
        for exclusion_pattern in exclusion.patterns
        for forbidden in check.patterns
    )


def _exclusion_explains_scope(exclusion, scope_entry, check):
    if not exclusion.valid or _exclusion_masks(exclusion, check):
        return False
    # An exclusion may explain a missing scope only if it actually describes
    # that scope. A narrower exclusion (for example ``dist/**/*.map``) does not
    # explain why ``dist`` itself was not enumerated.
    return any(
        _match_path(scope_entry, pattern) for pattern in exclusion.patterns
    )


def _required_scope(check_scope, commitments):
    """Return the parts of ``check_scope`` covered by step commitments.

    ``commitments`` is ``_UNKNOWN`` when no step is available, in which case
    the whole check scope is required. An empty list means the step made no
    positive artifact commitment, so nothing in scope has to be enumerated.
    """
    if commitments is _UNKNOWN:
        return list(check_scope), False

    if not commitments:
        return [], True

    required = []
    for pattern in commitments:
        prefix = _static_prefix(pattern)
        for scope_entry in check_scope:
            if _under(prefix, scope_entry):
                required.append(prefix)
            elif _under(scope_entry, prefix):
                required.append(scope_entry)

    return _dedupe(required), False


def _dedupe(items):
    result = []
    for item in items:
        if item not in result:
            result.append(item)
    return result


def _missing_enumeration_evidence(direction, scope, include_complete=True):
    evidence = [
        "signed artifact_enumeration.{}.boundary covering: {}".format(
            direction, ", ".join(scope) or "<scope>"
        )
    ]
    if include_complete:
        evidence.append(f"artifact_enumeration.{direction}.complete = true")
    return evidence


def classify_observation(  # noqa: C901, PLR0911, PLR0912, PLR0913
    observed,
    declaration,
    check,
    commitments=_UNKNOWN,
    direction="products",
    source="observation",
    step="",
):
    """Classify one artifact observation against ``check``.

    Each observation is judged independently, using its own signed boundary.
    """
    observed = observed or {}
    forbidden = _forbidden_artifacts(observed, check)
    required_scope, no_commitment = _required_scope(check.scope, commitments)

    common = {
        "source": source,
        "step": step,
        "direction": direction,
        "observed_count": len(observed),
        "forbidden_count": len(forbidden),
        "required_scope": required_scope,
    }

    if forbidden:
        return Observation(
            status=ARTIFACTS_PRESENT,
            reason="forbidden artifact(s) observed: {}".format(
                ", ".join(forbidden)
            ),
            **common,
        )

    if no_commitment or not required_scope:
        return Observation(
            status=ALLOWED_OMISSION,
            reason=(
                f"step has no positive {direction} commitment in the checked "
                "scope; omission is allowed"
            ),
            allowed_scope=list(check.scope),
            **common,
        )

    if declaration is None:
        return Observation(
            status=EVIDENCE_MISSING,
            reason="no signed artifact enumeration declaration",
            missing_scope=list(required_scope),
            missing_evidence=_missing_enumeration_evidence(
                direction, required_scope
            ),
            **common,
        )

    common["boundary"] = list(declaration.boundary)
    common["complete"] = declaration.complete
    common["exclusions"] = list(declaration.exclusions)

    masking_exclusions = [
        exclusion
        for exclusion in declaration.exclusions
        if _exclusion_masks(exclusion, check)
    ]
    invalid_masking = [
        exclusion for exclusion in masking_exclusions if not exclusion.valid
    ]
    if invalid_masking:
        return Observation(
            status=EVIDENCE_MISSING,
            reason=(
                "signed exclusion may hide the forbidden artifact class "
                "and has no reason"
            ),
            missing_scope=list(required_scope),
            missing_evidence=[
                "reason for exclusion pattern(s): {}".format(
                    ", ".join(
                        pattern
                        for exclusion in invalid_masking
                        for pattern in exclusion.patterns
                    )
                ),
                "or a policy that explicitly accepts omitted forbidden "
                "artifacts",
            ],
            **common,
        )

    if masking_exclusions and not check.allow_forbidden_exclusions:
        return Observation(
            status=EVIDENCE_MISSING,
            reason=(
                "signed exclusion may hide the forbidden artifact class; "
                "absence cannot be distinguished from omission"
            ),
            missing_scope=list(required_scope),
            missing_evidence=[
                "an enumeration that does not exclude {}".format(
                    ", ".join(
                        pattern
                        for exclusion in masking_exclusions
                        for pattern in exclusion.patterns
                    )
                ),
            ],
            **common,
        )

    if masking_exclusions and check.allow_forbidden_exclusions:
        if not declaration.complete:
            return Observation(
                status=EVIDENCE_MISSING,
                reason=(
                    "policy accepts the exclusion, but enumeration is not "
                    "declared complete"
                ),
                missing_scope=list(required_scope),
                missing_evidence=[
                    f"artifact_enumeration.{direction}.complete = true"
                ],
                **common,
            )
        return Observation(
            status=ALLOWED_OMISSION,
            reason="policy accepts the reason-bearing exclusion",
            allowed_scope=list(required_scope),
            **common,
        )

    covered_scope = []
    allowed_scope = []
    missing_scope = []
    missing_evidence = []

    for scope_entry in required_scope:
        if declaration.covers(scope_entry):
            covered_scope.append(scope_entry)
            continue

        explained = any(
            _exclusion_explains_scope(exclusion, scope_entry, check)
            for exclusion in declaration.exclusions
        )
        if explained:
            allowed_scope.append(scope_entry)
            continue

        missing_scope.append(scope_entry)

    if missing_scope:
        if not declaration.boundary:
            missing_evidence.extend(
                _missing_enumeration_evidence(
                    direction,
                    missing_scope,
                    include_complete=not declaration.complete,
                )
            )
        else:
            if not declaration.complete:
                missing_evidence.append(
                    f"artifact_enumeration.{direction}.complete = true"
                )
            not_covered = [
                scope_entry
                for scope_entry in missing_scope
                if not any(
                    _under(scope_entry, boundary)
                    for boundary in declaration.boundary
                )
            ]
            if not_covered:
                missing_evidence.append(
                    "signed artifact_enumeration.{}.boundary covering: "
                    "{}".format(direction, ", ".join(not_covered))
                )

        return Observation(
            status=EVIDENCE_MISSING,
            reason="signed enumeration does not cover the relevant scope",
            covered_scope=covered_scope,
            allowed_scope=allowed_scope,
            missing_scope=missing_scope,
            missing_evidence=_dedupe(missing_evidence),
            **common,
        )

    if allowed_scope:
        status = ALLOWED_OMISSION
        reason = (
            "scope is covered by reason-bearing exclusions that do not "
            "hide the forbidden artifact class"
        )
    else:
        status = CONFIRMED_NONE
        reason = (
            "complete signed enumeration covers the relevant scope and no "
            "forbidden artifact was observed"
        )

    return Observation(
        status=status,
        reason=reason,
        covered_scope=covered_scope,
        allowed_scope=allowed_scope,
        **common,
    )


def _positive_commitments(rules, direction):
    positive_rules = {
        "products": {"create", "modify", "require", "match"},
        "materials": {"modify", "require", "match"},
    }[direction]

    patterns = []
    for rule in rules or []:
        rule_data = rulelib.unpack_rule(rule)
        if rule_data["rule_type"] in positive_rules:
            patterns.append(rule_data["pattern"])
    return patterns


def step_commitments(step, direction):
    if direction == "products":
        return _positive_commitments(step.expected_products, direction)
    return _positive_commitments(step.expected_materials, direction)


def _link_label(keyid):
    if not keyid:
        return "link"
    return f"link {str(keyid)[:8]}"


@dataclass
class _Observer:
    step: object
    direction: str
    rule: dict


def _find_observers(layout, target_step):
    observers = []
    seen = set()
    for step in layout.steps:
        if step.name == target_step:
            continue

        for direction, rules in (
            ("materials", step.expected_materials),
            ("products", step.expected_products),
        ):
            for rule in rules:
                rule_data = rulelib.unpack_rule(rule)
                if (
                    rule_data["rule_type"] == "match"
                    and rule_data["dest_name"] == target_step
                    and rule_data["dest_type"] == "products"
                ):
                    key = (step.name, direction)
                    if key in seen:
                        continue
                    seen.add(key)
                    observers.append(_Observer(step, direction, rule_data))
    return observers


def _aggregate_step(  # noqa: C901, PLR0912
    step, observations, check, required_scope
):
    statuses = [observation.status for observation in observations]
    if ARTIFACTS_PRESENT in statuses:
        present = [
            observation
            for observation in observations
            if observation.status == ARTIFACTS_PRESENT
        ]
        return StepAssessment(
            step=step.name,
            status=ARTIFACTS_PRESENT,
            reason="; ".join(item.reason for item in present),
            observations=observations,
            required_scope=required_scope,
        )

    if not required_scope:
        return StepAssessment(
            step=step.name,
            status=ALLOWED_OMISSION,
            reason=(
                "step makes no positive artifact commitment in the checked "
                "scope; omission is allowed"
            ),
            observations=observations,
            allowed_scope=list(check.scope),
        )

    covered = []
    allowed = []
    missing = []
    missing_evidence = []

    for scope_entry in required_scope:
        if any(
            scope_entry in observation.covered_scope
            for observation in observations
        ):
            covered.append(scope_entry)
        elif any(
            scope_entry in observation.allowed_scope
            for observation in observations
        ):
            allowed.append(scope_entry)
        else:
            missing.append(scope_entry)

    if missing:
        for observation in observations:
            for entry in observation.missing_scope:
                if entry in missing and observation.missing_evidence:
                    missing_evidence.extend(observation.missing_evidence)
        if not missing_evidence:
            for direction in check.directions:
                missing_evidence.extend(
                    _missing_enumeration_evidence(direction, missing)
                )

        return StepAssessment(
            step=step.name,
            status=EVIDENCE_MISSING,
            reason="no independent observation proves absence in scope",
            observations=observations,
            required_scope=required_scope,
            covered_scope=covered,
            allowed_scope=allowed,
            missing_scope=missing,
            missing_evidence=_dedupe(missing_evidence),
        )

    if allowed:
        status = ALLOWED_OMISSION
        reason = "scope is accounted for by allowed omissions"
    else:
        status = CONFIRMED_NONE
        reason = "complete signed enumeration covers the relevant scope"

    return StepAssessment(
        step=step.name,
        status=status,
        reason=reason,
        observations=observations,
        required_scope=required_scope,
        covered_scope=covered,
        allowed_scope=allowed,
    )


def audit_layout(layout, chain_link_dict, check):
    """Audit artifact absence for all steps of a verified layout.

    ``chain_link_dict`` maps step names to verified links per functionary,
    e.g. ``{<step>: {<keyid>: <Link>}}``. Every link is treated as an
    independent observation and judged by its own signed boundary.

    For convenience a reduced mapping ``{<step>: <Link>}`` is accepted too.
    """
    steps = []
    for step in layout.steps:
        observations = []
        link_dict = chain_link_dict.get(step.name, {})

        for direction in check.directions:
            commitments = step_commitments(step, direction)
            for keyid, link in _links_for_step(link_dict):
                observations.append(
                    classify_observation(
                        getattr(link, direction),
                        get_declaration(link, direction),
                        check,
                        commitments=commitments,
                        direction=direction,
                        source=f"{step.name} {direction} [{_link_label(keyid)}]",
                        step=step.name,
                    )
                )

        if "products" in check.directions:
            for observer in _find_observers(layout, step.name):
                observer_links = chain_link_dict.get(observer.step.name, {})
                for keyid, link in _links_for_step(observer_links):
                    observations.append(
                        classify_observation(
                            getattr(link, observer.direction),
                            get_declaration(link, observer.direction),
                            check,
                            commitments=_UNKNOWN,
                            direction=observer.direction,
                            source=(
                                f"{observer.step.name} {observer.direction} [{_link_label(keyid)}] observing {step.name}"
                            ),
                            step=step.name,
                        )
                    )

        required_scope = []
        for direction in check.directions:
            direction_scope, _missing = _required_scope(
                check.scope, step_commitments(step, direction)
            )
            required_scope.extend(direction_scope)
        required_scope = _dedupe(required_scope)
        steps.append(_aggregate_step(step, observations, check, required_scope))

    return AcceptanceReport(check, steps=steps)


def _links_for_step(link_dict):
    """Return (keyid, link) pairs for nested or reduced link mappings."""
    if hasattr(link_dict, "materials"):
        return [("", link_dict)]
    return list(link_dict.items())


def audit_link(link, check, step=None, label=None):
    """Audit one standalone link (or one link against a Step)."""
    observations = []
    for direction in check.directions:
        commitments = _UNKNOWN
        if step is not None:
            commitments = step_commitments(step, direction)

        name = label or getattr(link, "name", "") or "link"
        observations.append(
            classify_observation(
                getattr(link, direction),
                get_declaration(link, direction),
                check,
                commitments=commitments,
                direction=direction,
                source=name,
                step=getattr(step, "name", ""),
            )
        )

    if len(observations) == 1:
        return observations[0]

    statuses = {observation.status for observation in observations}
    if ARTIFACTS_PRESENT in statuses:
        status = ARTIFACTS_PRESENT
    elif EVIDENCE_MISSING in statuses:
        status = EVIDENCE_MISSING
    elif statuses == {CONFIRMED_NONE}:
        status = CONFIRMED_NONE
    else:
        status = ALLOWED_OMISSION

    return Observation(
        source=label or getattr(link, "name", "") or "link",
        step=getattr(step, "name", ""),
        direction=check.direction,
        status=status,
        reason="; ".join(
            f"{item.direction}: {item.status}" for item in observations
        ),
    )


def audit_metadata(
    metadata, check, verification_key=None, step=None, label=None
):
    """Verify (optionally) and audit a link Metadata object."""
    if verification_key is not None:
        metadata.verify_signature(verification_key)

    link = metadata.get_payload()
    if getattr(link, "type_", None) != "link":
        raise AcceptanceError("can only audit link metadata")

    if label is None and getattr(metadata, "signatures", None):
        signature = metadata.signatures[0]
        if isinstance(signature, dict):
            keyid = signature.get("keyid")
        else:
            keyid = getattr(signature, "keyid", None)
        label = "{} [{}]".format(
            getattr(link, "name", "") or "link", _link_label(keyid)
        )

    return audit_link(link, check, step=step, label=label)


def verify_artifact_absence(
    layout,
    chain_link_dict,
    check,
    require_confirmed=False,
    raise_on_failure=True,
):
    """Run the optional completeness acceptance on a verified layout.

    Raises:
      AcceptanceError: If the report does not pass and ``raise_on_failure``
          is True. The exception message contains the full audit report.
    """
    report = audit_layout(layout, chain_link_dict, check)
    if raise_on_failure and not report.ok(require_confirmed=require_confirmed):
        raise AcceptanceError(report.format_text())
    return report


def format_report(report):
    """Return the textual audit representation of ``report``."""
    return report.format_text()
