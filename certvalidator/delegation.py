# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime

from asn1crypto.util import timezone

from ._errors import pretty_message
from ._types import str_cls, type_name
from .path import ValidationPath


class PolicyDelegation():
    """
    A single link of an externally-supplied delegation chain, recording that
    a policy authority delegated approval of a certificate policy OID to a
    specific domain, optionally limited to certain usages and to a validity
    window.
    """

    # A unicode string of the dotted OID of the certificate policy the
    # delegation applies to
    policy_oid = None

    # A unicode string identifying the delegating authority or domain
    source = None

    # A unicode string identifying the delegate domain. When different from
    # .source, the delegation is a cross-domain delegation
    target = None

    # A datetime.datetime object - the start of the approval validity window
    not_before = None

    # A datetime.datetime object - the end of the approval validity window
    not_after = None

    # None if the delegation is not usage-restricted, otherwise a set of
    # unicode strings of the usages the approval is limited to
    allowed_usages = None

    # A bool - if the delegation has been revoked by the policy authority.
    # Revoking an intermediate link breaks every approval that depends on it
    revoked = None

    def __init__(self, policy_oid, source, target, not_before, not_after,
                 allowed_usages=None, revoked=False):
        """
        :param policy_oid:
            A unicode string of the dotted OID of the certificate policy the
            delegation applies to

        :param source:
            A unicode string identifying the delegating authority or domain

        :param target:
            A unicode string identifying the delegate domain

        :param not_before:
            A datetime.datetime object - the start of the approval validity
            window

        :param not_after:
            A datetime.datetime object - the end of the approval validity
            window

        :param allowed_usages:
            None if the delegation is not usage-restricted, otherwise a set
            of unicode strings of the usages the approval is limited to

        :param revoked:
            A bool - if the delegation has been revoked by the policy
            authority
        """

        if not isinstance(policy_oid, str_cls):
            raise TypeError(pretty_message(
                '''
                policy_oid must be a unicode string, not %s
                ''',
                type_name(policy_oid)
            ))

        if not isinstance(source, str_cls):
            raise TypeError(pretty_message(
                '''
                source must be a unicode string, not %s
                ''',
                type_name(source)
            ))

        if not isinstance(target, str_cls):
            raise TypeError(pretty_message(
                '''
                target must be a unicode string, not %s
                ''',
                type_name(target)
            ))

        if not isinstance(not_before, datetime):
            raise TypeError(pretty_message(
                '''
                not_before must be a datetime object, not %s
                ''',
                type_name(not_before)
            ))

        if not isinstance(not_after, datetime):
            raise TypeError(pretty_message(
                '''
                not_after must be a datetime object, not %s
                ''',
                type_name(not_after)
            ))

        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)

        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)

        if allowed_usages is not None:
            if not isinstance(allowed_usages, set):
                raise TypeError(pretty_message(
                    '''
                    allowed_usages must be a set of unicode strings, not %s
                    ''',
                    type_name(allowed_usages)
                ))
            for allowed_usage in allowed_usages:
                if not isinstance(allowed_usage, str_cls):
                    raise TypeError(pretty_message(
                        '''
                        allowed_usages must be a set of unicode strings, not
                        %s
                        ''',
                        type_name(allowed_usage)
                    ))

        self.policy_oid = policy_oid
        self.source = source
        self.target = target
        self.not_before = not_before
        self.not_after = not_after
        self.allowed_usages = allowed_usages
        self.revoked = bool(revoked)

    @property
    def cross_domain(self):
        """
        :return:
            A bool - if the delegation crosses from one domain into another
        """

        return self.source != self.target


class DelegationEvidence():
    """
    A single piece of evidence recorded while reviewing a delegation chain.
    The approval validity window, the usage restriction and the intermediate
    revocation status of each delegation are each recorded separately.
    """

    # A unicode string of the check performed - one of "approval_source",
    # "validity_window", "usage_restriction" or "intermediate_revocation"
    check = None

    # The certvalidator.delegation.PolicyDelegation object the evidence is
    # about, or None when no delegation was found for a policy
    delegation = None

    # A bool - if the check passed
    passed = None

    # A unicode string of a human-readable description of the outcome
    detail = None

    def __init__(self, check, delegation, passed, detail):
        self.check = check
        self.delegation = delegation
        self.passed = bool(passed)
        self.detail = detail

    def __repr__(self):
        return '<DelegationEvidence %s: %s - %s>' % (
            self.check,
            'passed' if self.passed else 'failed',
            self.detail
        )


class DelegationReview():
    """
    The result of an offline review of an already-validated certification
    path against an externally-supplied delegation chain.
    """

    # A certvalidator.path.ValidationPath object of the validated path
    path = None

    # A set of unicode strings of the policy OIDs asserted by certificates
    # in the path
    policy_oids = None

    # A list of certvalidator.delegation.DelegationEvidence objects
    evidence = None

    # A unicode string of the delivery conclusion - "approved" or
    # "pending_manual"
    conclusion = None

    def __init__(self, path, policy_oids, evidence, conclusion):
        self.path = path
        self.policy_oids = policy_oids
        self.evidence = evidence
        self.conclusion = conclusion

    @property
    def approved(self):
        """
        :return:
            A bool - if every policy used by the path is covered by a valid
            delegation and the delivery may proceed without manual review
        """

        return self.conclusion == 'approved'


def _path_policy_oids(validation_path):
    """
    Collects the certificate policy OIDs asserted by the certificates in a
    validation path

    :param validation_path:
        A certvalidator.path.ValidationPath object

    :return:
        A set of unicode strings of dotted OIDs
    """

    policy_oids = set()
    for cert in validation_path:
        if not cert.certificate_policies_value:
            continue
        for policy in cert.certificate_policies_value:
            policy_identifier = policy['policy_identifier'].native
            if policy_identifier == 'any_policy':
                continue
            policy_oids.add(policy_identifier)
    return policy_oids


def review_path_delegation(validation_path, delegation_chain, usage=None, moment=None):
    """
    Performs an offline review of an already-validated certification path,
    cross-checking the policy identifiers used by the path against an
    externally-supplied delegation chain.

    Signature validation is not repeated here - it continues to be performed
    by the existing logic. A path without an approved delegation source may
    still show as validated; only the delivery conclusion is marked as
    pending manual review.

    :param validation_path:
        A certvalidator.path.ValidationPath object that has already been
        validated

    :param delegation_chain:
        A list of certvalidator.delegation.PolicyDelegation objects supplied
        by the policy officer

    :param usage:
        None or a unicode string of the usage the delivery is being approved
        for. When a delegation restricts usages, the delivery usage must be
        one of them

    :param moment:
        A datetime.datetime object to review the approval validity windows
        against. Defaults to the current time

    :return:
        A certvalidator.delegation.DelegationReview object
    """

    if not isinstance(validation_path, ValidationPath):
        raise TypeError(pretty_message(
            '''
            validation_path must be an instance of
            certvalidator.path.ValidationPath, not %s
            ''',
            type_name(validation_path)
        ))

    if not isinstance(delegation_chain, (list, tuple)):
        raise TypeError(pretty_message(
            '''
            delegation_chain must be a list of
            certvalidator.delegation.PolicyDelegation objects, not %s
            ''',
            type_name(delegation_chain)
        ))

    for delegation in delegation_chain:
        if not isinstance(delegation, PolicyDelegation):
            raise TypeError(pretty_message(
                '''
                delegation_chain must be a list of
                certvalidator.delegation.PolicyDelegation objects, not %s
                ''',
                type_name(delegation)
            ))

    if usage is not None and not isinstance(usage, str_cls):
        raise TypeError(pretty_message(
            '''
            usage must be None or a unicode string, not %s
            ''',
            type_name(usage)
        ))

    if moment is None:
        moment = datetime.now(timezone.utc)

    if not isinstance(moment, datetime):
        raise TypeError(pretty_message(
            '''
            moment must be a datetime object, not %s
            ''',
            type_name(moment)
        ))

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    policy_oids = _path_policy_oids(validation_path)
    evidence = []

    for policy_oid in sorted(policy_oids):
        candidates = [
            delegation
            for delegation in delegation_chain
            if delegation.policy_oid == policy_oid
        ]

        if not candidates:
            evidence.append(DelegationEvidence(
                'approval_source',
                None,
                False,
                pretty_message(
                    '''
                    No delegation in the externally-supplied chain approves
                    the policy %s used by the path
                    ''',
                    policy_oid
                )
            ))
            continue

        for delegation in candidates:
            delegation_label = pretty_message(
                '''
                delegation of policy %s from "%s" to "%s"
                ''',
                policy_oid,
                delegation.source,
                delegation.target
            )

            window_passed = delegation.not_before <= moment <= delegation.not_after
            if window_passed:
                window_detail = pretty_message(
                    '''
                    The %s is within its approval validity window
                    ''',
                    delegation_label
                )
            else:
                window_detail = pretty_message(
                    '''
                    The %s is outside of its approval validity window
                    ''',
                    delegation_label
                )
            evidence.append(DelegationEvidence(
                'validity_window',
                delegation,
                window_passed,
                window_detail
            ))

            usage_passed = (
                usage is None or
                delegation.allowed_usages is None or
                usage in delegation.allowed_usages
            )
            if usage_passed:
                usage_detail = pretty_message(
                    '''
                    The %s permits the requested usage
                    ''',
                    delegation_label
                )
            else:
                usage_detail = pretty_message(
                    '''
                    The %s does not permit the requested usage "%s"
                    ''',
                    delegation_label,
                    usage
                )
            evidence.append(DelegationEvidence(
                'usage_restriction',
                delegation,
                usage_passed,
                usage_detail
            ))

            revocation_passed = not delegation.revoked
            if revocation_passed:
                revocation_detail = pretty_message(
                    '''
                    The %s has not been revoked
                    ''',
                    delegation_label
                )
            else:
                revocation_detail = pretty_message(
                    '''
                    The %s has been revoked by the policy authority
                    ''',
                    delegation_label
                )
            evidence.append(DelegationEvidence(
                'intermediate_revocation',
                delegation,
                revocation_passed,
                revocation_detail
            ))

    approved = True
    for policy_oid in policy_oids:
        policy_evidence = [
            entry
            for entry in evidence
            if entry.delegation is not None and entry.delegation.policy_oid == policy_oid
        ]
        delegations = set(id(entry.delegation) for entry in policy_evidence)
        policy_approved = False
        for delegation_id in delegations:
            checks = [
                entry for entry in policy_evidence
                if id(entry.delegation) == delegation_id
            ]
            if checks and all(entry.passed for entry in checks):
                policy_approved = True
                break
        if not policy_approved:
            approved = False
            break

    if not policy_oids:
        approved = False

    conclusion = 'approved' if approved else 'pending_manual'

    return DelegationReview(validation_path, policy_oids, evidence, conclusion)
