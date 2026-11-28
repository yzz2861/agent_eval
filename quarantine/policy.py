# -*- coding: utf-8 -*-

"""Receiving policies and re-review (re-sign-off) decision logic.

Two policies are compared:

* ``legacy-rule``: the policy in force before the weekend rule update. An
  approval is bound to one concrete recognition rule. A format name staying
  the same is not enough when the attachment now matches a different rule.
* ``format-level``: the updated policy. Approvals are bound to the format
  name (extension/MIME), so any current rule producing the same format keeps
  the attachment cleared as long as the evidence is sufficient.
"""

from __future__ import absolute_import

from .engine import evaluate
from .rules import find_rule


# Reason codes attached to re-review decisions.
RULE_RETIRED = 'rule-retired'
RULE_CHANGED = 'matched-rule-changed'
FORMAT_CHANGED = 'format-changed'
EVIDENCE_INSUFFICIENT = 'evidence-insufficient'
UNRECOGNIZED = 'unrecognized-format'
NOT_ALLOWED = 'format-not-allowed'
NO_PRIOR_APPROVAL = 'no-prior-approval'


class Policy(object):
    def __init__(self, name, approval_scope, allowed_formats, description,
                 evidence_floor=0):
        self.name = name
        self.approval_scope = approval_scope
        self.allowed_formats = frozenset(allowed_formats)
        self.description = description
        # Minimum header size the gateway accepts as conclusive evidence even
        # when a matcher has a shorter magic-number guard.
        self.evidence_floor = evidence_floor

    def allows(self, extension):
        return extension in self.allowed_formats


POLICIES = {
    'legacy-rule': Policy(
        name='legacy-rule',
        approval_scope='rule',
        # The legacy gateway accepted office containers, common images and
        # both ZIP families. RTF was deliberately blocked at the gateway.
        allowed_formats=(
            'jpg', 'png', 'gif', 'tif',
            'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'odt', 'ods', 'odp',
            'zip', 'zst', 'pdf', 'tar',
        ),
        description=('Approvals are bound to a single recognition rule; '
                     'a new rule for the same format requires a new sign-off.'),
        evidence_floor=4,
    ),
    'format-level': Policy(
        name='format-level',
        approval_scope='format',
        # The updated policy additionally clears RTF, which the gateway team
        # decided to admit after the rule refresh.
        allowed_formats=(
            'jpg', 'png', 'gif', 'tif',
            'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'odt', 'ods', 'odp',
            'zip', 'zst', 'pdf', 'tar', 'rtf',
        ),
        description=('Approvals are bound to the format name; any current '
                     'rule producing that format keeps the attachment cleared.'),
        evidence_floor=4,
    ),
}


def get_policy(name):
    return POLICIES[name]


class Decision(object):
    """Re-review decision for one attachment under one policy."""

    def __init__(self, attachment_id, needs_rereview, reasons, details):
        self.attachment_id = attachment_id
        self.needs_rereview = needs_rereview
        self.reasons = reasons
        self.details = details

    def to_dict(self):
        data = {
            'attachment_id': self.attachment_id,
            'needs_rereview': self.needs_rereview,
            'reasons': self.reasons,
        }
        data.update(self.details)
        return data


def _decide(policy, history_record, scan):
    reasons = []
    details = {
        'previous_format': history_record.get('approved_format'),
        'previous_rule_id': history_record.get('approved_rule_id'),
        'current_format': scan.format,
        'current_rule_id': scan.rule_id,
        'evidence_sufficient': scan.sufficient,
    }

    policy_sufficient = (
        scan.sufficient and scan.header_length >= policy.evidence_floor
    )
    details['policy_evidence_floor'] = policy.evidence_floor
    details['header_length'] = scan.header_length

    current_format = scan.format
    if current_format is None:
        reasons.append(UNRECOGNIZED)
    elif not policy.allows(current_format):
        reasons.append(NOT_ALLOWED)
    elif not policy_sufficient:
        reasons.append(EVIDENCE_INSUFFICIENT)

    previous_format = history_record.get('approved_format')
    previous_rule_id = history_record.get('approved_rule_id')
    if not previous_format:
        reasons.append(NO_PRIOR_APPROVAL)
    elif current_format is not None and previous_format != current_format:
        reasons.append(FORMAT_CHANGED)

    # Approval coverage is only reachable when the current evidence is
    # conclusive, the format is allowed and its name did not change.
    coverage_applies = (
        previous_rule_id
        and current_format is not None
        and policy_sufficient
        and policy.allows(current_format)
        and FORMAT_CHANGED not in reasons
    )
    if coverage_applies and policy.approval_scope == 'rule':
        approved_rule = find_rule(previous_rule_id)
        if approved_rule is None:
            # The rule named on the old approval no longer exists. Under rule
            # scope its sign-off cannot be transferred to a replacement rule.
            reasons.append(RULE_RETIRED)
        elif approved_rule.rule_id != scan.rule_id:
            reasons.append(RULE_CHANGED)
    # Under format scope any current rule of the same format family covers
    # the attachment, so a retired or replaced rule adds no extra reason.

    unique_reasons = list(dict.fromkeys(reasons))
    return Decision(
        attachment_id=scan.attachment_id,
        needs_rereview=bool(unique_reasons),
        reasons=unique_reasons,
        details=details,
    )


def build_rereview_list(attachments, history, policy_name):
    """Rescan attachments and return decisions under the named policy.

    Args:
        attachments: records with ``attachment_id`` plus a local ``path`` or
            inline header ``bytes`` / ``bytes_base64``.
        history: mapping of ``attachment_id`` to the previous approval record
            containing ``approved_format`` and optionally ``approved_rule_id``.
        policy_name: one of the keys of :data:`POLICIES`.

    Returns:
        Dict with ``policy``, ``rereview`` (decision dicts) and ``cleared``.
    """
    policy = get_policy(policy_name)
    scans = evaluate(attachments)
    decisions = []
    for attachment in attachments:
        attachment_id = attachment['attachment_id']
        history_record = history.get(attachment_id, {})
        decisions.append(_decide(policy, history_record, scans[attachment_id]))

    rereview = [decision.to_dict() for decision in decisions
                if decision.needs_rereview]
    cleared = [decision.attachment_id for decision in decisions
               if not decision.needs_rereview]
    return {
        'policy': policy.name,
        'approval_scope': policy.approval_scope,
        'rereview_count': len(rereview),
        'rereview': rereview,
        'cleared': cleared,
    }
