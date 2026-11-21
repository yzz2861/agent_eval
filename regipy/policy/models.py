"""Data models for evidence-bound policy explanations.

The objects in this module deliberately keep provenance separate from
interpretation.  A :class:`PolicyRecord` is only an observation read from a
specific piece of evidence.  A :class:`PolicyExplanation` is the result of
binding that observation to a delegated role context and applying an explicit
rule.  This separation is what makes the output reviewable.
"""

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from regipy.exceptions import PolicyContextException

MACHINE_SCOPE = "machine"
USER_SCOPE = "user"
ANY_SCOPE = "any"
SCOPE_VALUES = (MACHINE_SCOPE, USER_SCOPE, ANY_SCOPE)
ROLE_KINDS = (MACHINE_SCOPE, USER_SCOPE)

PER_SCOPE = "per_scope"
MACHINE_PRECEDENCE = "machine_precedence"
ALL_SCOPES_REQUIRED = "all_scopes_required"
COMBINATION_VALUES = (PER_SCOPE, MACHINE_PRECEDENCE, ALL_SCOPES_REQUIRED)

STATUS_APPLIED = "applied"
STATUS_OBSERVED = "observed"


def _json_safe(value: Any) -> Any:
    """Convert common forensic values to deterministic JSON-friendly values."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return value


def stable_id(prefix: str, payload: Any) -> str:
    raw = json.dumps(_json_safe(payload), sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def value_key(value: Any) -> str:
    return json.dumps(_json_safe(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def value_candidates(value: Any) -> set:
    """Return the string forms a rule author might reasonably use as a value key."""
    candidates = {value_key(value), str(value), str(value).lower()}
    if isinstance(value, bool) or isinstance(value, float) and value.is_integer():
        candidates.add(str(int(value)))
    return candidates


def normalize_path(path: Optional[str]) -> str:
    if not path:
        return "\\"
    normalized = str(path).replace("/", "\\").strip()
    if not normalized.startswith("\\"):
        normalized = "\\" + normalized
    return normalized


def canonical_policy_key(key_path: str, scope: Optional[str] = None) -> str:
    """Normalize machine/user registry paths to a shared policy identity.

    The same Windows policy is often stored below ``HKLM\\...\\Policies`` and
    ``HKCU\\Software\\...\\Policies``.  Stripping the hive-specific prefixes and
    the legacy ``Microsoft\\Windows\\CurrentVersion`` segment lets the two
    observations correlate without pretending that they have the same meaning.
    """
    parts = [part for part in normalize_path(key_path).strip("\\").split("\\") if part]
    if parts and parts[0].lower() == "software":
        parts = parts[1:]
    if parts and parts[0].lower() == "wow6432node":
        parts = parts[1:]

    lower = [part.lower() for part in parts]
    if len(lower) >= 4 and lower[:4] == ["microsoft", "windows", "currentversion", "policies"]:
        parts = ["Policies"] + parts[4:]
    lower = [part.lower() for part in parts]
    if lower and lower[0].startswith("controlset") and lower[0][10:].isdigit():
        parts = parts[1:]

    return "\\".join(part.lower() for part in parts)


def canonical_policy_id(key_path: str, value_name: str, scope: Optional[str] = None) -> str:
    return f"{canonical_policy_key(key_path, scope=scope)}::{value_name.lower()}"


def _entity_items(value: Any, id_key: str, single_keys: tuple[str, ...]) -> list[Any]:
    if isinstance(value, dict) and any(key in value for key in single_keys):
        return [value]
    if isinstance(value, dict):
        result = []
        for item_id, item in value.items():
            entry = dict(item or {})
            entry.setdefault(id_key, item_id)
            result.append(entry)
        return result
    return value


@dataclass
class Evidence:
    """A piece of evidence from which policy records were taken."""

    evidence_id: str
    hive_path: Optional[str] = None
    hive_type: Optional[str] = None
    scope: Optional[str] = None
    sha256: Optional[str] = None
    description: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise PolicyContextException("evidence_id must not be empty")
        if self.scope is not None:
            self.scope = str(self.scope).lower()
            if self.scope not in (MACHINE_SCOPE, USER_SCOPE):
                raise PolicyContextException(
                    f"evidence {self.evidence_id!r} has invalid scope {self.scope!r}; expected 'machine' or 'user'"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "hive_path": self.hive_path,
            "hive_type": self.hive_type,
            "scope": self.scope,
            "sha256": self.sha256,
            "description": self.description,
            "metadata": _json_safe(self.metadata),
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Evidence":
        if not isinstance(data, dict):
            raise PolicyContextException("evidence entries must be objects")
        return cls(
            evidence_id=str(data.get("evidence_id") or data.get("id") or ""),
            hive_path=data.get("hive_path") or data.get("path"),
            hive_type=data.get("hive_type") or data.get("type"),
            scope=data.get("scope"),
            sha256=data.get("sha256"),
            description=data.get("description"),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class RoleContext:
    """The limited role context supplied by the delegating party.

    ``kind`` is the policy scope in which the role lives (machine or user).
    ``login_context`` is intentionally free-form so callers can preserve the
    delegator's terminology (for example ``interactive``, ``service`` or
    ``network``).  ``evidence_ids`` is the explicit binding between this role
    and the evidence files it may consume.
    """

    role_id: str
    kind: str
    evidence_ids: list[str] = field(default_factory=list)
    login_context: Optional[str] = None
    account: Optional[str] = None
    sid: Optional[str] = None
    attributes: dict[str, Any] = field(default_factory=dict)
    source: str = "delegated"
    notes: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.role_id:
            raise PolicyContextException("role_id must not be empty")
        self.kind = str(self.kind).lower()
        if self.kind not in ROLE_KINDS:
            raise PolicyContextException(f"role {self.role_id!r} has invalid kind {self.kind!r}; expected 'machine' or 'user'")
        if isinstance(self.evidence_ids, str):
            self.evidence_ids = [self.evidence_ids]
        self.evidence_ids = list(dict.fromkeys(str(item) for item in self.evidence_ids if item))
        self.source = self.source or "delegated"

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_id": self.role_id,
            "kind": self.kind,
            "evidence_ids": list(self.evidence_ids),
            "login_context": self.login_context,
            "account": self.account,
            "sid": self.sid,
            "attributes": _json_safe(self.attributes),
            "source": self.source,
            "notes": self.notes,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "RoleContext":
        if not isinstance(data, dict):
            raise PolicyContextException("role entries must be objects")
        evidence_ids: Any = data.get("evidence_ids")
        if evidence_ids is None:
            evidence_ids = []
            if data.get("evidence_id"):
                evidence_ids.append(data["evidence_id"])
            if data.get("machine_evidence_id"):
                evidence_ids.append(data["machine_evidence_id"])
        return cls(
            role_id=str(data.get("role_id") or data.get("id") or ""),
            kind=str(data.get("kind") or data.get("role_kind") or data.get("scope") or ""),
            evidence_ids=evidence_ids,
            login_context=data.get("login_context") or data.get("logon_context"),
            account=data.get("account"),
            sid=data.get("sid"),
            attributes=dict(data.get("attributes") or {}),
            source=data.get("source") or "delegated",
            notes=data.get("notes"),
        )


@dataclass
class PolicyRecord:
    """One raw policy value observed in one piece of evidence."""

    evidence_id: str
    key_path: str
    value_name: str
    value: Any
    policy_id: str = ""
    scope: str = ANY_SCOPE
    value_type: Optional[str] = None
    last_write: Optional[str] = None
    source: str = "synthetic"
    record_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise PolicyContextException("policy record evidence_id must not be empty")
        if not self.value_name:
            raise PolicyContextException("policy record value_name must not be empty")
        self.scope = str(self.scope).lower()
        if self.scope not in SCOPE_VALUES:
            raise PolicyContextException(
                f"policy record scope {self.scope!r} is invalid; expected one of {', '.join(SCOPE_VALUES)}"
            )
        self.key_path = normalize_path(self.key_path)
        if not self.policy_id:
            self.policy_id = canonical_policy_id(self.key_path, self.value_name, scope=self.scope)
        if not self.record_id:
            self.record_id = stable_id(
                "record",
                {
                    "policy_id": self.policy_id,
                    "evidence_id": self.evidence_id,
                    "scope": self.scope,
                    "key_path": self.key_path,
                    "value_name": self.value_name,
                    "value": self.value,
                },
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "record_id": self.record_id,
            "evidence_id": self.evidence_id,
            "scope": self.scope,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "value": _json_safe(self.value),
            "value_type": self.value_type,
            "last_write": self.last_write,
            "source": self.source,
            "metadata": _json_safe(self.metadata),
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "PolicyRecord":
        if not isinstance(data, dict):
            raise PolicyContextException("policy records must be objects")
        value_name = data.get("value_name") or data.get("name")
        if not value_name:
            raise PolicyContextException("policy record is missing value_name")
        return cls(
            policy_id=str(data.get("policy_id") or data.get("policy") or ""),
            evidence_id=str(data.get("evidence_id") or data.get("evidence") or ""),
            scope=str(data.get("scope") or data.get("hive_scope") or ANY_SCOPE).lower(),
            key_path=str(data.get("key_path") or data.get("key") or "\\"),
            value_name=str(value_name),
            value=data.get("value"),
            value_type=data.get("value_type") or data.get("type"),
            last_write=data.get("last_write") or data.get("timestamp"),
            source=data.get("source") or "synthetic",
            record_id=str(data.get("record_id") or ""),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class PolicyRule:
    """An explicit, reviewable interpretation rule.

    ``combination`` controls what happens when more than one scope contributes
    to the same policy:

    * ``per_scope`` - each observation is explained separately and qualified by
      its scope.
    * ``machine_precedence`` - a machine observation wins over a user
      observation, which is retained as overridden evidence.
    * ``all_scopes_required`` - the policy is effective only when every
      required scope is present and all values are in ``in_effect_values``.
    """

    rule_id: str
    policy_id: Optional[str] = None
    value_name: Optional[str] = None
    key_path_contains: Optional[str] = None
    scope: str = ANY_SCOPE
    conclusion_by_value: dict[str, Any] = field(default_factory=dict)
    default_conclusion: Optional[Any] = None
    scope_qualifiers: dict[str, str] = field(default_factory=dict)
    applies_to_login_contexts: Optional[list[str]] = None
    applies_to_role_kinds: Optional[list[str]] = None
    required_role_attributes: dict[str, Any] = field(default_factory=dict)
    combination: str = PER_SCOPE
    required_scopes: list[str] = field(default_factory=list)
    in_effect_values: list[Any] = field(default_factory=list)
    conclusion_when_combined: Optional[Any] = None
    conclusion_when_not_combined: Optional[Any] = None
    description: str = ""
    reference: Optional[str] = None
    precedence: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id:
            self.rule_id = self.policy_id or self.value_name or "rule"
        self.scope = str(self.scope or ANY_SCOPE).lower()
        if self.scope not in SCOPE_VALUES:
            raise PolicyContextException(f"rule {self.rule_id!r} has invalid scope {self.scope!r}")
        self.combination = str(self.combination or PER_SCOPE).lower()
        if self.combination not in COMBINATION_VALUES:
            raise PolicyContextException(
                f"rule {self.rule_id!r} has invalid combination {self.combination!r}; "
                f"expected one of {', '.join(COMBINATION_VALUES)}"
            )
        if isinstance(self.conclusion_by_value, list):
            converted: dict[str, Any] = {}
            for item in self.conclusion_by_value:
                if not isinstance(item, dict) or "value" not in item:
                    raise PolicyContextException(
                        f"rule {self.rule_id!r} conclusion_by_value list entries need value/conclusion"
                    )
                converted[value_key(item["value"])] = item.get("conclusion")
            self.conclusion_by_value = converted
        if self.applies_to_login_contexts is not None:
            self.applies_to_login_contexts = [str(item).lower() for item in self.applies_to_login_contexts]
        if self.applies_to_role_kinds is not None:
            self.applies_to_role_kinds = [str(item).lower() for item in self.applies_to_role_kinds]
        self.required_role_attributes = dict(self.required_role_attributes or {})
        if not self.required_scopes:
            self.required_scopes = []
        else:
            self.required_scopes = [str(item).lower() for item in self.required_scopes]

    def _lookup(self) -> dict[str, Any]:
        lookup: dict[str, Any] = {}
        for key, conclusion in self.conclusion_by_value.items():
            for candidate in value_candidates(key):
                lookup.setdefault(candidate, conclusion)
            if isinstance(key, str):
                lookup.setdefault(key, conclusion)
                try:
                    parsed = json.loads(key)
                except (TypeError, ValueError):
                    parsed = key
                for candidate in value_candidates(parsed):
                    lookup.setdefault(candidate, conclusion)
        return lookup

    def interpret(self, value: Any) -> tuple[bool, Any]:
        lookup = self._lookup()
        for candidate in value_candidates(value):
            if candidate in lookup:
                return True, lookup[candidate]
        if self.default_conclusion is not None:
            return True, self.default_conclusion
        return False, None

    def value_is_in_effect(self, value: Any) -> bool:
        if not self.in_effect_values:
            return False
        lookup = set()
        for item in self.in_effect_values:
            lookup.update(value_candidates(item))
        return bool(value_candidates(value) & lookup)

    def match_score(self, record: PolicyRecord) -> int:
        score = 0
        if self.policy_id:
            score += 8
        if self.value_name:
            score += 4
        if self.key_path_contains:
            score += 2
        if self.scope != ANY_SCOPE:
            score += 1
        return score

    def matches_record(self, record: PolicyRecord) -> bool:
        if self.scope != ANY_SCOPE and record.scope != self.scope:
            return False
        if self.policy_id and record.policy_id.lower() != self.policy_id.lower():
            return False
        if self.value_name and record.value_name.lower() != self.value_name.lower():
            return False
        if self.key_path_contains:
            needle = normalize_path(self.key_path_contains).lower()
            if needle not in normalize_path(record.key_path).lower():
                return False
        return True

    def scope_qualifier(self, scope: str) -> str:
        qualifier = self.scope_qualifiers.get(scope)
        if qualifier:
            return qualifier
        if scope == MACHINE_SCOPE:
            return "machine scope: host-wide, independent of which user is logged on"
        if scope == USER_SCOPE:
            return "user scope: only this user's logon context, not other users on the host"
        return "scope not specified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "policy_id": self.policy_id,
            "value_name": self.value_name,
            "key_path_contains": self.key_path_contains,
            "scope": self.scope,
            "conclusion_by_value": _json_safe(self.conclusion_by_value),
            "default_conclusion": _json_safe(self.default_conclusion),
            "scope_qualifiers": dict(self.scope_qualifiers),
            "applies_to_login_contexts": self.applies_to_login_contexts,
            "applies_to_role_kinds": self.applies_to_role_kinds,
            "required_role_attributes": _json_safe(self.required_role_attributes),
            "combination": self.combination,
            "required_scopes": list(self.required_scopes),
            "in_effect_values": _json_safe(self.in_effect_values),
            "conclusion_when_combined": _json_safe(self.conclusion_when_combined),
            "conclusion_when_not_combined": _json_safe(self.conclusion_when_not_combined),
            "description": self.description,
            "reference": self.reference,
            "precedence": self.precedence,
            "metadata": _json_safe(self.metadata),
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "PolicyRule":
        if not isinstance(data, dict):
            raise PolicyContextException("rules must be objects")
        conclusion_by_value = data.get("conclusion_by_value")
        if conclusion_by_value is None:
            conclusion_by_value = data.get("values")
        if conclusion_by_value is None:
            conclusion_by_value = {}
        return cls(
            rule_id=str(data.get("rule_id") or data.get("id") or data.get("policy_id") or data.get("name") or "rule"),
            policy_id=data.get("policy_id") or data.get("policy"),
            value_name=data.get("value_name") or data.get("value"),
            key_path_contains=data.get("key_path_contains") or data.get("key_path"),
            scope=str(data.get("scope") or ANY_SCOPE),
            conclusion_by_value=conclusion_by_value,
            default_conclusion=data.get("default_conclusion"),
            scope_qualifiers=dict(data.get("scope_qualifiers") or {}),
            applies_to_login_contexts=data.get("applies_to_login_contexts"),
            applies_to_role_kinds=data.get("applies_to_role_kinds"),
            required_role_attributes=dict(data.get("required_role_attributes") or {}),
            combination=str(data.get("combination") or PER_SCOPE),
            required_scopes=list(data.get("required_scopes") or []),
            in_effect_values=list(data.get("in_effect_values") or []),
            conclusion_when_combined=data.get("conclusion_when_combined"),
            conclusion_when_not_combined=data.get("conclusion_when_not_combined"),
            description=data.get("description") or "",
            reference=data.get("reference"),
            precedence=int(data.get("precedence") or 0),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class PolicyExplanation:
    """A conclusion tied to one role and one or more evidence items."""

    policy_id: str
    role_id: str
    role_kind: str
    status: str
    conclusion: Any
    login_context: Optional[str] = None
    conclusion_code: Optional[str] = None
    interpretation: str = "rule"
    rule_id: Optional[str] = None
    combination: str = PER_SCOPE
    combination_expression: Optional[str] = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    conditions: list[dict[str, Any]] = field(default_factory=list)
    condition_logic: str = "all_of"
    overridden_by: Optional[str] = None
    explanation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "role_id": self.role_id,
            "role_kind": self.role_kind,
            "login_context": self.login_context,
            "status": self.status,
            "conclusion": _json_safe(self.conclusion),
            "conclusion_code": self.conclusion_code,
            "interpretation": self.interpretation,
            "rule_id": self.rule_id,
            "combination": self.combination,
            "combination_expression": self.combination_expression,
            "evidence": _json_safe(self.evidence),
            "conditions": _json_safe(self.conditions),
            "condition_logic": self.condition_logic,
            "overridden_by": self.overridden_by,
            "explanation": self.explanation,
            "metadata": _json_safe(self.metadata),
        }


@dataclass
class UnboundContext:
    """A context that could not be safely bound or interpreted."""

    reason: str
    detail: str
    role_id: Optional[str] = None
    policy_id: Optional[str] = None
    evidence_id: Optional[str] = None
    record_id: Optional[str] = None
    related: dict[str, Any] = field(default_factory=dict)
    context_id: str = ""

    def __post_init__(self) -> None:
        if not self.context_id:
            self.context_id = stable_id(
                "unbound",
                {
                    "reason": self.reason,
                    "role_id": self.role_id,
                    "policy_id": self.policy_id,
                    "evidence_id": self.evidence_id,
                    "record_id": self.record_id,
                },
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "reason": self.reason,
            "detail": self.detail,
            "role_id": self.role_id,
            "policy_id": self.policy_id,
            "evidence_id": self.evidence_id,
            "record_id": self.record_id,
            "related": _json_safe(self.related),
        }


@dataclass
class PolicyReport:
    explanations: list[PolicyExplanation] = field(default_factory=list)
    unbound_contexts: list[UnboundContext] = field(default_factory=list)
    roles: list[RoleContext] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    records: list[PolicyRecord] = field(default_factory=list)
    shared_evidence_ids: list[str] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)
    schema_version: str = "1.0"
    generated_by: str = "regipy.policy"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> dict[str, Any]:
        by_reason: dict[str, int] = {}
        for item in self.unbound_contexts:
            by_reason[item.reason] = by_reason.get(item.reason, 0) + 1
        by_status: dict[str, int] = {}
        for item in self.explanations:
            by_status[item.status] = by_status.get(item.status, 0) + 1
        return {
            "roles": len(self.roles),
            "evidence": len(self.evidence),
            "records": len(self.records),
            "explanations": len(self.explanations),
            "explanations_by_status": dict(sorted(by_status.items())),
            "unbound_contexts": len(self.unbound_contexts),
            "unbound_by_reason": dict(sorted(by_reason.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_by": self.generated_by,
            "summary": self.summary,
            "shared_evidence_ids": list(self.shared_evidence_ids),
            "roles": [role.to_dict() for role in self.roles],
            "evidence": [item.to_dict() for item in self.evidence],
            "records": [item.to_dict() for item in self.records],
            "rules": [rule.to_dict() for rule in self.rules],
            "explanations": [item.to_dict() for item in self.explanations],
            "unbound_contexts": [item.to_dict() for item in self.unbound_contexts],
            "metadata": _json_safe(self.metadata),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def to_markdown(self) -> str:
        from regipy.policy.render import render_markdown

        return render_markdown(self)


@dataclass
class PolicyContext:
    """The complete input to a policy explanation run."""

    roles: list[RoleContext] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    records: list[PolicyRecord] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)
    shared_evidence_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "PolicyContext":
        if not isinstance(data, dict):
            raise PolicyContextException("policy context must be a JSON object")
        raw_roles = _entity_items(data.get("roles") or data.get("role_contexts") or [], "role_id", ("role_id", "id", "kind"))
        raw_evidence = data.get("evidence") or data.get("evidences") or []
        raw_records = _entity_items(
            data.get("records") or data.get("policy_records") or data.get("policies") or [],
            "record_id",
            ("record_id", "id", "value_name", "key_path", "key"),
        )
        raw_rules = _entity_items(data.get("rules") or [], "rule_id", ("rule_id", "id", "policy_id", "value_name", "values"))

        evidence: list[Evidence] = []
        if isinstance(raw_evidence, dict) and "evidence_id" in raw_evidence:
            evidence = [Evidence.from_mapping(raw_evidence)]
        elif isinstance(raw_evidence, dict):
            for evidence_id, value in raw_evidence.items():
                item = dict(value or {})
                item.setdefault("evidence_id", evidence_id)
                evidence.append(Evidence.from_mapping(item))
        else:
            evidence = [Evidence.from_mapping(item) for item in raw_evidence]

        return cls(
            roles=[RoleContext.from_mapping(item) for item in raw_roles],
            evidence=evidence,
            records=[PolicyRecord.from_mapping(item) for item in raw_records],
            rules=[PolicyRule.from_mapping(item) for item in raw_rules],
            shared_evidence_ids=list(data.get("shared_evidence_ids") or data.get("shared_evidence") or []),
            metadata=dict(data.get("metadata") or {}),
        )

    @classmethod
    def from_json(cls, payload: str) -> "PolicyContext":
        try:
            data = json.loads(payload)
        except ValueError as exc:
            raise PolicyContextException(f"invalid policy context JSON: {exc}") from exc
        return cls.from_mapping(data)

    @classmethod
    def from_json_file(cls, path: str) -> "PolicyContext":
        with open(path, encoding="utf-8") as handle:
            return cls.from_json(handle.read())


def load_roles(data: Any) -> tuple[list[RoleContext], list[str]]:
    """Load roles from a list or a ``{"roles": ..., "shared_evidence_ids": ...}`` object."""
    if isinstance(data, list):
        return [RoleContext.from_mapping(item) for item in data], []
    if isinstance(data, dict):
        if "roles" not in data and "role_contexts" not in data and "role_id" in data:
            return [RoleContext.from_mapping(data)], []
        raw_roles = _entity_items(data.get("roles") or data.get("role_contexts") or [], "role_id", ("role_id", "id", "kind"))
        shared = list(data.get("shared_evidence_ids") or data.get("shared_evidence") or [])
        return [RoleContext.from_mapping(item) for item in raw_roles], shared
    raise PolicyContextException("roles payload must be a list or an object with a 'roles' key")


def load_rules(data: Any) -> list[PolicyRule]:
    if isinstance(data, list):
        return [PolicyRule.from_mapping(item) for item in data]
    if isinstance(data, dict):
        if "rules" not in data and any(key in data for key in ("rule_id", "id", "policy_id", "value_name", "values")):
            return [PolicyRule.from_mapping(data)]
        raw_rules = data.get("rules") if "rules" in data else data
        return [
            PolicyRule.from_mapping(item)
            for item in _entity_items(raw_rules, "rule_id", ("rule_id", "id", "policy_id", "value_name", "values"))
        ]
    raise PolicyContextException("rules payload must be a list or an object with a 'rules' key")


def load_records(data: Any) -> list[PolicyRecord]:
    if isinstance(data, list):
        return [PolicyRecord.from_mapping(item) for item in data]
    if isinstance(data, dict):
        if "records" not in data and "policy_records" not in data and "value_name" in data:
            return [PolicyRecord.from_mapping(data)]
        raw_records = data.get("records") if "records" in data else data.get("policy_records", data)
        return [
            PolicyRecord.from_mapping(item)
            for item in _entity_items(raw_records, "record_id", ("record_id", "id", "value_name", "key_path", "key"))
        ]
    raise PolicyContextException("records payload must be a list or an object with a 'records' key")


def load_evidence(data: Any) -> list[Evidence]:
    if isinstance(data, list):
        return [Evidence.from_mapping(item) for item in data]
    if isinstance(data, dict):
        if "evidence" not in data and "evidence_id" in data:
            return [Evidence.from_mapping(data)]
        raw_evidence = data.get("evidence") if "evidence" in data else data
        if isinstance(raw_evidence, dict):
            result = []
            for evidence_id, value in raw_evidence.items():
                item = dict(value or {})
                item.setdefault("evidence_id", evidence_id)
                result.append(Evidence.from_mapping(item))
            return result
        return [Evidence.from_mapping(item) for item in raw_evidence]
    raise PolicyContextException("evidence payload must be a list or an object")


PolicyValue = Union[str, int, float, bool, bytes, dt.datetime, list[Any], dict[str, Any], None]
