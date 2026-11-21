"""Evidence-bound policy explanation engine.

The engine never infers a role from a hive filename.  A record can only be
used for a role when the role explicitly binds the record's evidence id, or
when the evidence id is shared across roles.  Everything that cannot be bound
that way is emitted under ``unbound_contexts`` instead of being silently
folded into a conclusion.
"""

import json
from collections.abc import Iterable
from typing import Any, Optional

from regipy.policy.models import (
    ALL_SCOPES_REQUIRED,
    ANY_SCOPE,
    MACHINE_PRECEDENCE,
    MACHINE_SCOPE,
    PER_SCOPE,
    USER_SCOPE,
    Evidence,
    PolicyContext,
    PolicyExplanation,
    PolicyRecord,
    PolicyReport,
    PolicyRule,
    RoleContext,
    UnboundContext,
    _json_safe,
    value_key,
)
from regipy.policy.rules import default_rules as builtin_default_rules

REASON_ROLE_WITHOUT_EVIDENCE = "role_without_evidence"
REASON_UNKNOWN_EVIDENCE = "unknown_evidence"
REASON_UNSPECIFIED_SCOPE = "unspecified_scope"
REASON_SCOPE_ROLE_MISMATCH = "scope_role_mismatch"
REASON_ROLE_KIND_NOT_APPLICABLE = "role_kind_not_applicable"
REASON_MISSING_LOGIN_CONTEXT = "missing_login_context"
REASON_LOGIN_CONTEXT_NOT_APPLICABLE = "login_context_not_applicable"
REASON_ROLE_ATTRIBUTE_MISMATCH = "role_attribute_mismatch"
REASON_NO_MATCHING_RULE = "no_matching_rule"
REASON_AMBIGUOUS_RULE = "ambiguous_rule"
REASON_UNSUPPORTED_VALUE = "unsupported_value"
REASON_CONFLICTING_RECORDS = "conflicting_records"
REASON_INCOMPLETE_COMBINATION = "incomplete_combination"
REASON_ORPHAN_RECORD = "orphan_record"


def _format_value(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True)


def _condition(kind: str, expression: str, satisfied: bool, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": kind,
        "expression": expression,
        "satisfied": bool(satisfied),
    }
    result.update(extra)
    return result


def _evidence_ref(record: PolicyRecord, evidence_by_id: dict[str, Evidence], selection: str) -> dict[str, Any]:
    evidence = evidence_by_id.get(record.evidence_id)
    return {
        "record_id": record.record_id,
        "evidence_id": record.evidence_id,
        "hive_path": evidence.hive_path if evidence else None,
        "hive_type": evidence.hive_type if evidence else None,
        "evidence_scope": evidence.scope if evidence else None,
        "record_scope": record.scope,
        "key_path": record.key_path,
        "value_name": record.value_name,
        "value": _json_safe(record.value),
        "value_type": record.value_type,
        "last_write": record.last_write,
        "sha256": evidence.sha256 if evidence else None,
        "selection": selection,
        "source": record.source,
    }


def _role_conditions(role: RoleContext, evidence_ids: Iterable[str]) -> list[dict[str, Any]]:
    conditions = [_condition("role", f"role.kind == {role.kind!r}", True, role_id=role.role_id)]
    if role.login_context is not None:
        conditions.append(
            _condition(
                "login_context",
                f"role.login_context == {role.login_context!r}",
                True,
                role_id=role.role_id,
                login_context=role.login_context,
            )
        )
    for key, value in role.attributes.items():
        conditions.append(
            _condition(
                "role_attribute",
                f"role.attributes[{key!r}] == {value!r}",
                True,
                role_id=role.role_id,
                attribute=key,
                value=value,
            )
        )
    for evidence_id in evidence_ids:
        conditions.append(
            _condition(
                "evidence_binding",
                f"evidence {evidence_id!r} is bound to role {role.role_id!r}",
                True,
                role_id=role.role_id,
                evidence_id=evidence_id,
            )
        )
    return conditions


def _value_condition(record: PolicyRecord, satisfied: bool = True) -> dict[str, Any]:
    return _condition(
        "value",
        f"{record.value_name} == {_format_value(record.value)}",
        satisfied,
        evidence_id=record.evidence_id,
        record_id=record.record_id,
        value=record.value,
        value_type=record.value_type,
    )


def _compose_conclusion(base: Any, qualifier: str, role: RoleContext) -> Any:
    if isinstance(base, str):
        return f"{base} [{qualifier}; role={role.role_id}]"
    return {
        "conclusion": _json_safe(base),
        "scope_qualifier": qualifier,
        "role_id": role.role_id,
    }


def _conclusion_code(base: Any) -> str:
    return base if isinstance(base, str) else value_key(base)


def _select_rule(
    records: list[PolicyRecord], rules: list[PolicyRule]
) -> tuple[Optional[PolicyRule], Optional[list[PolicyRule]]]:
    candidates = []
    for rule in rules:
        matched = [record for record in records if rule.matches_record(record)]
        if not matched:
            continue
        candidates.append(
            (
                rule.precedence,
                len(matched),
                max(rule.match_score(record) for record in matched),
                rule,
            )
        )
    if not candidates:
        return None, None

    candidates.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    top = candidates[0]
    ties = [item for item in candidates[1:] if item[:3] == top[:3]]
    if ties:
        return None, [top[3]] + [item[3] for item in ties]
    return top[3], None


def _rule_applicability(rule: PolicyRule, role: RoleContext) -> tuple[Optional[str], Optional[str]]:
    if rule.applies_to_role_kinds and role.kind not in rule.applies_to_role_kinds:
        return (
            REASON_ROLE_KIND_NOT_APPLICABLE,
            f"rule {rule.rule_id!r} applies only to role kinds {rule.applies_to_role_kinds!r}, not {role.kind!r}",
        )
    for key, expected in rule.required_role_attributes.items():
        actual = role.attributes.get(key)
        if actual != expected:
            return (
                REASON_ROLE_ATTRIBUTE_MISMATCH,
                f"rule {rule.rule_id!r} requires role attribute {key!r}={expected!r}, but role {role.role_id!r} has {actual!r}",
            )
    if rule.applies_to_login_contexts:
        if not role.login_context:
            return (
                REASON_MISSING_LOGIN_CONTEXT,
                f"rule {rule.rule_id!r} requires one of {rule.applies_to_login_contexts!r} "
                f"but role {role.role_id!r} has no login_context",
            )
        if role.login_context.lower() not in rule.applies_to_login_contexts:
            return (
                REASON_LOGIN_CONTEXT_NOT_APPLICABLE,
                f"rule {rule.rule_id!r} applies only to login contexts "
                f"{rule.applies_to_login_contexts!r}; role {role.role_id!r} is {role.login_context!r}",
            )
    return None, None


class PolicyExplainer:
    """Reusable wrapper around :func:`build_policy_report`."""

    def __init__(
        self,
        context: PolicyContext,
        *,
        rules: Optional[Iterable[PolicyRule]] = None,
        strict_rules: bool = False,
        include_observed: bool = True,
    ) -> None:
        self.context = context
        self.rules = list(rules) if rules is not None else None
        self.strict_rules = strict_rules
        self.include_observed = include_observed

    def run(self) -> PolicyReport:
        return build_policy_report(
            self.context,
            rules=self.rules,
            strict_rules=self.strict_rules,
            include_observed=self.include_observed,
        )

    def explain(self) -> PolicyReport:
        return self.run()


def build_policy_report(
    context: PolicyContext,
    *,
    rules: Optional[Iterable[PolicyRule]] = None,
    strict_rules: bool = False,
    include_observed: bool = True,
) -> PolicyReport:
    """Bind policy records to delegated roles and produce reviewable explanations.

    ``strict_rules=True`` turns records without a matching rule into unbound
    contexts instead of raw ``observed`` explanations.  ``include_observed``
    only controls the non-strict fallback.
    """

    if rules is not None:
        active_rules = list(rules)
    elif context.rules:
        active_rules = list(context.rules)
    else:
        active_rules = builtin_default_rules()

    evidence_by_id: dict[str, Evidence] = {}
    for evidence in context.evidence:
        if evidence.evidence_id in evidence_by_id:
            raise ValueError(f"duplicate evidence_id: {evidence.evidence_id}")
        evidence_by_id[evidence.evidence_id] = evidence

    role_ids = set()
    for role in context.roles:
        if role.role_id in role_ids:
            raise ValueError(f"duplicate role_id: {role.role_id}")
        role_ids.add(role.role_id)

    explanations: list[PolicyExplanation] = []
    unbound_contexts: list[UnboundContext] = []
    seen_unbound = set()

    def add_unbound(
        reason: str,
        detail: str,
        *,
        role: Optional[RoleContext] = None,
        policy_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        record: Optional[PolicyRecord] = None,
        related: Optional[dict[str, Any]] = None,
    ) -> None:
        item = UnboundContext(
            reason=reason,
            detail=detail,
            role_id=role.role_id if role else None,
            policy_id=policy_id,
            evidence_id=evidence_id or (record.evidence_id if record else None),
            record_id=record.record_id if record else None,
            related=related or {},
        )
        key = (item.reason, item.role_id, item.policy_id, item.evidence_id, item.record_id)
        if key in seen_unbound:
            return
        seen_unbound.add(key)
        unbound_contexts.append(item)

    shared_evidence_ids = list(dict.fromkeys(context.shared_evidence_ids))
    for evidence_id in shared_evidence_ids:
        if evidence_id not in evidence_by_id:
            add_unbound(
                REASON_UNKNOWN_EVIDENCE,
                f"shared evidence id {evidence_id!r} is not present in the evidence list",
                evidence_id=evidence_id,
            )

    records: list[PolicyRecord] = []
    for record in context.records:
        if record.evidence_id not in evidence_by_id:
            add_unbound(
                REASON_UNKNOWN_EVIDENCE,
                f"record {record.record_id} references evidence {record.evidence_id!r}, which is not present",
                policy_id=record.policy_id,
                evidence_id=record.evidence_id,
                record=record,
                related={"record": record.to_dict()},
            )
            continue

        if record.scope == ANY_SCOPE:
            evidence_scope = evidence_by_id[record.evidence_id].scope
            if evidence_scope in (MACHINE_SCOPE, USER_SCOPE):
                record.scope = evidence_scope
            else:
                add_unbound(
                    REASON_UNSPECIFIED_SCOPE,
                    f"record {record.record_id} has scope 'any' and evidence {record.evidence_id!r} "
                    "does not declare a machine/user scope",
                    policy_id=record.policy_id,
                    evidence_id=record.evidence_id,
                    record=record,
                    related={"record": record.to_dict()},
                )
                continue
        records.append(record)

    role_bound_evidence: dict[str, list[str]] = {}
    for role in context.roles:
        requested_ids = list(dict.fromkeys(list(role.evidence_ids) + shared_evidence_ids))
        if not requested_ids:
            add_unbound(
                REASON_ROLE_WITHOUT_EVIDENCE,
                f"role {role.role_id!r} has no evidence binding; no policy can be attributed to it",
                role=role,
            )
            role_bound_evidence[role.role_id] = []
            continue

        valid_ids = []
        for evidence_id in requested_ids:
            if evidence_id in evidence_by_id:
                valid_ids.append(evidence_id)
            else:
                add_unbound(
                    REASON_UNKNOWN_EVIDENCE,
                    f"role {role.role_id!r} references evidence {evidence_id!r}, which is not present",
                    role=role,
                    evidence_id=evidence_id,
                )
        role_bound_evidence[role.role_id] = valid_ids

    records_by_policy: dict[str, list[PolicyRecord]] = {}
    for record in records:
        records_by_policy.setdefault(record.policy_id, []).append(record)
    for policy_records in records_by_policy.values():
        policy_records.sort(key=lambda item: (item.evidence_id, item.scope, item.record_id))

    def observed_explanation(
        role: RoleContext,
        record: PolicyRecord,
        rule: Optional[PolicyRule],
        bound_evidence_ids: list[str],
    ) -> PolicyExplanation:
        qualifier = (
            rule.scope_qualifier(record.scope)
            if rule is not None
            else (
                "machine scope: host-wide, independent of which user is logged on"
                if record.scope == MACHINE_SCOPE
                else "user scope: only this user's logon context, not other users on the host"
            )
        )
        base = (
            f"Observed {record.value_name}={_format_value(record.value)}; "
            "no interpretation rule matched, so this is a raw observation, not a policy conclusion"
        )
        conditions = _role_conditions(role, bound_evidence_ids)
        conditions.extend(
            [
                _condition(
                    "scope",
                    f"record.scope == {record.scope!r}",
                    True,
                    record_id=record.record_id,
                    evidence_id=record.evidence_id,
                ),
                _value_condition(record),
                _condition("rule", "no interpretation rule matched", True),
            ]
        )
        return PolicyExplanation(
            policy_id=record.policy_id,
            role_id=role.role_id,
            role_kind=role.kind,
            login_context=role.login_context,
            status="observed",
            conclusion=_compose_conclusion(base, qualifier, role),
            conclusion_code=None,
            interpretation="raw_observation",
            rule_id=rule.rule_id if rule is not None else None,
            combination=rule.combination if rule is not None else PER_SCOPE,
            combination_expression=f"record.scope == {record.scope!r}",
            evidence=[_evidence_ref(record, evidence_by_id, "selected")],
            conditions=conditions,
            condition_logic="all_of",
            explanation=(
                f"Role {role.role_id!r} is bound to {record.evidence_id!r}, which contains "
                f"{record.key_path} {record.value_name}={_format_value(record.value)}. "
                "The value is preserved for review but has no validated interpretation."
            ),
        )

    def append_per_scope_explanation(
        role: RoleContext,
        policy_id: str,
        rule: PolicyRule,
        record: PolicyRecord,
        base: Any,
        bound_evidence_ids: list[str],
    ) -> None:
        conditions = _role_conditions(role, bound_evidence_ids)
        conditions.extend(
            [
                _condition(
                    "scope",
                    f"record.scope == {record.scope!r}",
                    True,
                    record_id=record.record_id,
                    evidence_id=record.evidence_id,
                ),
                _value_condition(record),
                _condition(
                    "rule",
                    f"rule {rule.rule_id!r} matched the record",
                    True,
                    rule_id=rule.rule_id,
                ),
            ]
        )
        qualifier = rule.scope_qualifier(record.scope)
        explanations.append(
            PolicyExplanation(
                policy_id=policy_id,
                role_id=role.role_id,
                role_kind=role.kind,
                login_context=role.login_context,
                status="applied",
                conclusion=_compose_conclusion(base, qualifier, role),
                conclusion_code=_conclusion_code(base),
                interpretation="rule",
                rule_id=rule.rule_id,
                combination=rule.combination,
                combination_expression=f"record.scope == {record.scope!r}",
                evidence=[_evidence_ref(record, evidence_by_id, "selected")],
                conditions=conditions,
                condition_logic="all_of",
                explanation=(
                    f"Rule {rule.rule_id!r} interprets {record.value_name}="
                    f"{_format_value(record.value)} from {record.evidence_id!r} "
                    f"({record.key_path}) for role {role.role_id!r}. "
                    f"Scope qualifier: {qualifier}."
                ),
            )
        )

    for role in context.roles:
        bound_evidence_ids = role_bound_evidence.get(role.role_id, [])
        if not bound_evidence_ids:
            continue
        bound_set = set(bound_evidence_ids)

        for policy_id in sorted(records_by_policy):
            policy_records = records_by_policy[policy_id]
            applicable = [record for record in policy_records if record.evidence_id in bound_set]
            if not applicable:
                continue

            compatible: list[PolicyRecord] = []
            for record in applicable:
                if record.scope == USER_SCOPE and role.kind == MACHINE_SCOPE:
                    add_unbound(
                        REASON_SCOPE_ROLE_MISMATCH,
                        f"user-scope record {record.record_id} cannot be applied to machine role {role.role_id!r}",
                        role=role,
                        policy_id=policy_id,
                        record=record,
                        related={"record": record.to_dict()},
                    )
                    continue
                compatible.append(record)
            if not compatible:
                continue

            rule, ambiguous_rules = _select_rule(compatible, active_rules)
            if ambiguous_rules is not None:
                record_rules: list[tuple[PolicyRecord, PolicyRule]] = []
                record_issues: list[tuple[PolicyRecord, list[PolicyRule]]] = []
                unmatched_records: list[PolicyRecord] = []
                for record in compatible:
                    record_rule, record_ambiguous = _select_rule([record], active_rules)
                    if record_ambiguous is not None:
                        record_issues.append((record, record_ambiguous))
                    elif record_rule is None:
                        unmatched_records.append(record)
                    else:
                        record_rules.append((record, record_rule))

                if not record_issues and record_rules and all(item.combination == PER_SCOPE for _, item in record_rules):
                    for record, record_rule in record_rules:
                        reason, detail = _rule_applicability(record_rule, role)
                        if reason is not None:
                            add_unbound(
                                reason,
                                detail or "",
                                role=role,
                                policy_id=policy_id,
                                record=record,
                                related={"rule_id": record_rule.rule_id, "record": record.to_dict()},
                            )
                            continue
                        ok, base = record_rule.interpret(record.value)
                        if not ok:
                            add_unbound(
                                REASON_UNSUPPORTED_VALUE,
                                f"rule {record_rule.rule_id!r} has no interpretation for "
                                f"{record.value_name}={_format_value(record.value)}",
                                role=role,
                                policy_id=policy_id,
                                record=record,
                                related={"rule_id": record_rule.rule_id, "record": record.to_dict()},
                            )
                            continue
                        append_per_scope_explanation(role, policy_id, record_rule, record, base, bound_evidence_ids)
                    for record in unmatched_records:
                        if strict_rules:
                            add_unbound(
                                REASON_NO_MATCHING_RULE,
                                f"no rule matches {record.value_name!r} at {record.key_path} for policy {policy_id!r}",
                                role=role,
                                policy_id=policy_id,
                                record=record,
                                related={"record": record.to_dict()},
                            )
                        elif include_observed:
                            explanations.append(observed_explanation(role, record, None, bound_evidence_ids))
                    continue

                add_unbound(
                    REASON_AMBIGUOUS_RULE,
                    f"multiple rules match policy {policy_id!r} for role {role.role_id!r}: "
                    f"{[item.rule_id for item in ambiguous_rules]!r}",
                    role=role,
                    policy_id=policy_id,
                    evidence_id=compatible[0].evidence_id,
                    related={
                        "rule_ids": [item.rule_id for item in ambiguous_rules],
                        "records": [record.to_dict() for record in compatible],
                    },
                )
                continue

            if rule is None:
                for record in compatible:
                    if strict_rules:
                        add_unbound(
                            REASON_NO_MATCHING_RULE,
                            f"no rule matches {record.value_name!r} at {record.key_path} for policy {policy_id!r}",
                            role=role,
                            policy_id=policy_id,
                            record=record,
                            related={"record": record.to_dict()},
                        )
                    elif include_observed:
                        explanations.append(observed_explanation(role, record, None, bound_evidence_ids))
                continue

            reason, detail = _rule_applicability(rule, role)
            if reason is not None:
                add_unbound(
                    reason,
                    detail or "",
                    role=role,
                    policy_id=policy_id,
                    evidence_id=compatible[0].evidence_id,
                    related={
                        "rule_id": rule.rule_id,
                        "rule_applies_to_login_contexts": rule.applies_to_login_contexts,
                        "rule_applies_to_role_kinds": rule.applies_to_role_kinds,
                        "records": [record.to_dict() for record in compatible],
                    },
                )
                continue

            matching = [record for record in compatible if rule.matches_record(record)]
            for record in compatible:
                if record not in matching:
                    add_unbound(
                        REASON_NO_MATCHING_RULE,
                        f"record {record.record_id} does not match the selected rule {rule.rule_id!r}",
                        role=role,
                        policy_id=policy_id,
                        record=record,
                        related={"record": record.to_dict(), "rule_id": rule.rule_id},
                    )

            interpreted: list[tuple[PolicyRecord, Any]] = []
            for record in matching:
                ok, base = rule.interpret(record.value)
                if not ok:
                    add_unbound(
                        REASON_UNSUPPORTED_VALUE,
                        f"rule {rule.rule_id!r} has no interpretation for {record.value_name}={_format_value(record.value)}",
                        role=role,
                        policy_id=policy_id,
                        record=record,
                        related={
                            "record": record.to_dict(),
                            "rule_id": rule.rule_id,
                            "supported_values": _json_safe(rule.conclusion_by_value),
                        },
                    )
                    continue
                interpreted.append((record, base))
            if not interpreted:
                continue

            if rule.combination == PER_SCOPE:
                for record, base in interpreted:
                    append_per_scope_explanation(role, policy_id, rule, record, base, bound_evidence_ids)
                continue

            if rule.combination == MACHINE_PRECEDENCE:
                by_scope: dict[str, list[tuple[PolicyRecord, Any]]] = {MACHINE_SCOPE: [], USER_SCOPE: []}
                for record, base in interpreted:
                    by_scope.setdefault(record.scope, []).append((record, base))

                def consistent(items: list[tuple[PolicyRecord, Any]]) -> bool:
                    return len({value_key(base) for _, base in items}) <= 1

                machine_items = by_scope.get(MACHINE_SCOPE, [])
                user_items = by_scope.get(USER_SCOPE, [])
                if machine_items and not consistent(machine_items):
                    add_unbound(
                        REASON_CONFLICTING_RECORDS,
                        f"conflicting machine-scope values for policy {policy_id!r} in role {role.role_id!r}",
                        role=role,
                        policy_id=policy_id,
                        evidence_id=machine_items[0][0].evidence_id,
                        related={"records": [record.to_dict() for record, _ in machine_items]},
                    )
                    continue
                if not machine_items and user_items and not consistent(user_items):
                    add_unbound(
                        REASON_CONFLICTING_RECORDS,
                        f"conflicting user-scope values for policy {policy_id!r} in role {role.role_id!r}",
                        role=role,
                        policy_id=policy_id,
                        evidence_id=user_items[0][0].evidence_id,
                        related={"records": [record.to_dict() for record, _ in user_items]},
                    )
                    continue

                selected_record, selected_base = (machine_items or user_items)[0]
                if machine_items:
                    qualifier = "machine scope takes precedence over user scope for this role"
                    overridden_by = selected_record.record_id if user_items else None
                else:
                    qualifier = "user scope only; no machine-scope record is bound to this role"
                    overridden_by = None

                evidence = []
                for index, (record, _base) in enumerate(interpreted):
                    if record is selected_record:
                        selection = "selected"
                    elif record.scope == MACHINE_SCOPE and machine_items:
                        selection = "corroborating"
                    elif record.scope == USER_SCOPE and machine_items:
                        selection = "overridden"
                    else:
                        selection = "corroborating"
                    evidence.append(_evidence_ref(record, evidence_by_id, selection))
                    if index == len(interpreted) - 1:
                        break

                conditions = _role_conditions(role, bound_evidence_ids)
                conditions.extend(
                    [
                        _condition(
                            "combination",
                            "a machine-scope record is present in the role's bound evidence",
                            bool(machine_items),
                        ),
                        _condition(
                            "combination",
                            "a user-scope record is present in the role's bound evidence",
                            bool(user_items),
                        ),
                        _condition(
                            "combination",
                            "machine scope takes precedence over user scope",
                            True,
                        ),
                    ]
                )
                for record, _base in interpreted:
                    conditions.append(_value_condition(record))
                    conditions.append(
                        _condition(
                            "rule",
                            f"{record.scope} value interpreted by rule {rule.rule_id!r}",
                            True,
                            rule_id=rule.rule_id,
                            evidence_id=record.evidence_id,
                            record_id=record.record_id,
                        )
                    )

                explanations.append(
                    PolicyExplanation(
                        policy_id=policy_id,
                        role_id=role.role_id,
                        role_kind=role.kind,
                        login_context=role.login_context,
                        status="applied",
                        conclusion=_compose_conclusion(selected_base, qualifier, role),
                        conclusion_code=_conclusion_code(selected_base),
                        interpretation="rule",
                        rule_id=rule.rule_id,
                        combination=rule.combination,
                        combination_expression="machine_scope_present ? machine : user_scope",
                        evidence=evidence,
                        conditions=conditions,
                        condition_logic="all_of",
                        overridden_by=overridden_by,
                        explanation=(
                            f"Policy {policy_id!r} was observed in multiple scopes for role "
                            f"{role.role_id!r}. The selected conclusion comes from "
                            f"{selected_record.evidence_id!r}; any user-scope observation is "
                            "retained in the evidence list as overridden."
                        ),
                    )
                )
                continue

            if rule.combination == ALL_SCOPES_REQUIRED:
                required_scopes = rule.required_scopes or [MACHINE_SCOPE, USER_SCOPE]
                by_scope: dict[str, list[tuple[PolicyRecord, Any]]] = {}
                for record, base in interpreted:
                    by_scope.setdefault(record.scope, []).append((record, base))

                missing_scopes = [scope for scope in required_scopes if scope not in by_scope]
                if missing_scopes:
                    add_unbound(
                        REASON_INCOMPLETE_COMBINATION,
                        f"policy {policy_id!r} requires scopes {required_scopes!r} for role "
                        f"{role.role_id!r}, but {missing_scopes!r} is not bound",
                        role=role,
                        policy_id=policy_id,
                        evidence_id=compatible[0].evidence_id,
                        related={
                            "rule_id": rule.rule_id,
                            "required_scopes": required_scopes,
                            "present_scopes": sorted(by_scope),
                            "missing_scopes": missing_scopes,
                            "records": [record.to_dict() for record, _ in interpreted],
                        },
                    )
                    continue

                selected = []
                conflict = False
                for scope in required_scopes:
                    items = by_scope.get(scope, [])
                    if len({value_key(base) for _, base in items}) > 1:
                        conflict = True
                        break
                    selected.append(items[0])
                if conflict:
                    add_unbound(
                        REASON_CONFLICTING_RECORDS,
                        f"conflicting values in a required scope for policy {policy_id!r} in role {role.role_id!r}",
                        role=role,
                        policy_id=policy_id,
                        related={
                            "rule_id": rule.rule_id,
                            "records": [record.to_dict() for record, _ in interpreted],
                        },
                    )
                    continue

                in_effect_flags = [(record, rule.value_is_in_effect(record.value)) for record, _ in selected]
                all_in_effect = all(flag for _, flag in in_effect_flags)
                base = rule.conclusion_when_combined if all_in_effect else rule.conclusion_when_not_combined
                if base is None:
                    base = (
                        "The combined policy condition is satisfied"
                        if all_in_effect
                        else "The combined policy condition is not satisfied"
                    )
                qualifier = f"combined condition across required scopes {required_scopes!r}"
                conditions = _role_conditions(role, bound_evidence_ids)
                for scope in required_scopes:
                    conditions.append(
                        _condition(
                            "combination",
                            f"required scope {scope!r} is present in the role's bound evidence",
                            True,
                            scope=scope,
                        )
                    )
                for record, flag in in_effect_flags:
                    conditions.append(
                        _condition(
                            "combination",
                            f"{record.scope} value {_format_value(record.value)} is in the in-effect set "
                            f"{_format_value(rule.in_effect_values)}",
                            flag,
                            scope=record.scope,
                            evidence_id=record.evidence_id,
                            record_id=record.record_id,
                            value=record.value,
                        )
                    )
                conditions.append(
                    _condition(
                        "combination",
                        "all required scopes are present and all values are in the in-effect set",
                        all_in_effect,
                    )
                )
                explanations.append(
                    PolicyExplanation(
                        policy_id=policy_id,
                        role_id=role.role_id,
                        role_kind=role.kind,
                        login_context=role.login_context,
                        status="applied",
                        conclusion=_compose_conclusion(base, qualifier, role),
                        conclusion_code="in_effect" if all_in_effect else "not_in_effect",
                        interpretation="rule",
                        rule_id=rule.rule_id,
                        combination=rule.combination,
                        combination_expression=(
                            " AND ".join(f"scope {scope!r} present" for scope in required_scopes)
                            + " AND all in-effect values match"
                        ),
                        evidence=[
                            _evidence_ref(
                                record,
                                evidence_by_id,
                                "selected"
                                if record.record_id in {selected_record.record_id for selected_record, _ in selected}
                                else "corroborating",
                            )
                            for record, _ in interpreted
                        ],
                        conditions=conditions,
                        condition_logic="all_of",
                        explanation=(
                            f"Policy {policy_id!r} was evaluated as a combined condition for role "
                            f"{role.role_id!r}. All of {required_scopes!r} must be present; the "
                            "per-scope value conditions are listed above."
                        ),
                    )
                )
                continue

    bound_anywhere = set()
    for evidence_ids in role_bound_evidence.values():
        bound_anywhere.update(evidence_ids)
    for record in records:
        if record.evidence_id not in bound_anywhere:
            add_unbound(
                REASON_ORPHAN_RECORD,
                f"record {record.record_id} belongs to evidence {record.evidence_id!r}, which is not bound to any role",
                policy_id=record.policy_id,
                evidence_id=record.evidence_id,
                record=record,
                related={"record": record.to_dict()},
            )

    explanations.sort(
        key=lambda item: (
            item.policy_id,
            item.role_id,
            item.status,
            item.rule_id or "",
            item.evidence[0]["record_id"] if item.evidence else "",
        )
    )
    unbound_contexts.sort(
        key=lambda item: (
            item.reason,
            item.role_id or "",
            item.policy_id or "",
            item.evidence_id or "",
            item.record_id or "",
            item.detail,
        )
    )

    return PolicyReport(
        explanations=explanations,
        unbound_contexts=unbound_contexts,
        roles=list(context.roles),
        evidence=list(context.evidence),
        records=sorted(records, key=lambda item: (item.policy_id, item.evidence_id, item.record_id)),
        shared_evidence_ids=shared_evidence_ids,
        rules=active_rules,
        metadata=dict(context.metadata),
    )


explain_policy_context = build_policy_report
explain_policies = build_policy_report
