""" Optional purpose-review layer for notation claims attached to verified signatures.

:py:meth:`~pgpy.PGPKey.verify` answers "is the signature math valid?".
This module answers the follow-up question ingest and archival pipelines
usually need: "which purpose claims ride along with this signature, which of
them are actually guaranteed by the signature itself, and do the claims our
policy cares about satisfy the business conditions we can check locally?"

Typical usage::

    verification = pubkey.verify(message)
    policy = PurposePolicy(
        rules={'purpose@example.com': {'archive-retrieval', 'archive-seal'}},
        constrained={'retention-class@example.com'},
    )
    review = review_verification(verification, policy)
    for sigreview in review.pending:
        for reason in sigreview.pending_reasons:
            ...  # route to a manual confirmation queue
"""

import collections
import enum
import itertools

from .constants import NotationDataFlags
from .packet.subpackets.signature import NotationData

__all__ = ['Claim',
           'ClaimEvidence',
           'ClaimOutcome',
           'ClaimRule',
           'ClaimStatus',
           'PurposePolicy',
           'PurposeReview',
           'ReviewQueue',
           'SignatureReview',
           'extract_claims',
           'review_signature',
           'review_verification', ]


class ClaimEvidence(enum.Enum):
    """Where a notation claim was found, i.e. how strong its evidence is."""

    SIGNATURE_BOUND = 'signature-bound'
    """The claim lives in the hashed subpacket area, so the signature math guarantees it."""

    EXTERNAL_ANNOTATION = 'external-annotation'
    """The claim lives in the unhashed subpacket area; it is an outer annotation any
    intermediary could have added, altered, or stripped without invalidating the signature."""


class ClaimStatus(enum.Enum):
    """How a single claim fared under the review policy."""

    SATISFIED = 'satisfied'
    """Recognized claim whose business condition passed."""

    FAILED_CONDITION = 'failed-condition'
    """Recognized claim whose business condition did not pass."""

    UNPROTECTED = 'unprotected'
    """Recognized claim that arrived as an external annotation although the policy
    requires signature-bound evidence for it."""

    UNRECOGNIZED_CONSTRAINED = 'unrecognized-constrained'
    """Claim constrained by policy for which the caller supplied no recognition rule;
    it must be held for manual confirmation."""

    INFORMATIONAL = 'informational'
    """Claim the policy does not constrain; carried along for context only."""


class ReviewQueue(enum.Enum):
    """The review queue a signature is routed to."""

    ACCEPTED = 'accepted'
    """Signature verified and every policy-relevant claim was satisfied."""

    PENDING = 'pending'
    """Signature verified, but at least one claim needs manual confirmation."""

    REJECTED = 'rejected'
    """Signature did not verify; claims were not evaluated."""


Claim = collections.namedtuple('Claim', ['name', 'value', 'human_readable', 'evidence'])
Claim.__doc__ = """A single notation claim extracted from a signature.

``name`` - the notation name.

``value`` - the notation value (``str`` for human-readable notations, ``bytearray`` otherwise).

``human_readable`` - ``bool`` of whether the notation is flagged human-readable.

``evidence`` - :py:obj:`ClaimEvidence` of whether the claim is guaranteed by the signature.
"""

ClaimOutcome = collections.namedtuple('ClaimOutcome', ['claim', 'status', 'reason'])
ClaimOutcome.__doc__ = """The review outcome of a single claim.

``claim`` - the :py:obj:`Claim` that was evaluated.

``status`` - :py:obj:`ClaimStatus` of the evaluation.

``reason`` - human-readable explanation, retained for the pending queue. Empty when satisfied.
"""


def extract_claims(signature):
    """Extract notation claims from a :py:obj:`~pgpy.PGPSignature`, distinguishing
    signature-bound claims from external annotations.

    :param signature: the :py:obj:`~pgpy.PGPSignature` to inspect
    :returns: a ``list`` of :py:obj:`Claim`
    """
    claims = []
    subpackets = signature._signature.subpackets
    for area, evidence in ((subpackets._hashed_sp, ClaimEvidence.SIGNATURE_BOUND),
                           (subpackets._unhashed_sp, ClaimEvidence.EXTERNAL_ANNOTATION)):
        for subpacket in area.values():
            if isinstance(subpacket, NotationData):
                claims.append(Claim(name=subpacket.name,
                                    value=subpacket.value,
                                    human_readable=NotationDataFlags.HumanReadable in subpacket.flags,
                                    evidence=evidence))
    return claims


class ClaimRule(object):
    """A caller-supplied business condition for one recognized claim name.

    :param condition: callable receiving the claim value and returning ``True``
        when the claim may pass
    :param require_signature_bound: if ``True`` (the default), the claim only passes
        on signature-bound evidence; an external annotation is held for confirmation
    :param description: optional human-readable description of the condition,
        used in retained reasons
    """

    def __init__(self, condition, require_signature_bound=True, description=''):
        if not callable(condition):
            raise TypeError('condition must be callable')
        self.condition = condition
        self.require_signature_bound = require_signature_bound
        self.description = description

    def accepts(self, value):
        try:
            return bool(self.condition(value))

        except Exception:
            return False


def _as_rule(spec, require_signature_bound=True):
    if isinstance(spec, ClaimRule):
        return spec

    if callable(spec):
        return ClaimRule(spec, require_signature_bound=require_signature_bound)

    allowed = frozenset([spec]) if isinstance(spec, str) else frozenset(spec)
    return ClaimRule(lambda value: value in allowed,
                     require_signature_bound=require_signature_bound,
                     description='value must be one of {{{:s}}}'.format(', '.join(sorted(map(str, allowed)))))


class PurposePolicy(object):
    """The caller's view of which claims are recognized and what lets them pass.

    :param rules: ``dict`` mapping recognized claim names to their business
        conditions. Each value may be a :py:obj:`ClaimRule`, a callable taking
        the claim value, or a collection of acceptable values.
    :param constrained: names of claims that are constrained by policy even
        though no local recognition rule exists for them. When such a claim
        shows up, it is retained with its pending-confirmation reason instead
        of being silently dropped.
    :param constrain_unknown: if ``True``, treat every unrecognized claim as
        constrained by policy
    :param require_signature_bound: default evidence requirement for rules
        that do not specify one
    """

    def __init__(self, rules=None, constrained=(), constrain_unknown=False, require_signature_bound=True):
        self.require_signature_bound = require_signature_bound
        self.rules = {}
        for name, spec in (rules or {}).items():
            self.rules[name] = _as_rule(spec, require_signature_bound=require_signature_bound)
        self.constrained = set(constrained)
        self.constrain_unknown = constrain_unknown

    def evaluate(self, claim):
        """Evaluate a single :py:obj:`Claim` against this policy.

        :returns: a :py:obj:`ClaimOutcome`
        """
        rule = self.rules.get(claim.name)

        if rule is None:
            if claim.name in self.constrained or self.constrain_unknown:
                return ClaimOutcome(claim, ClaimStatus.UNRECOGNIZED_CONSTRAINED,
                                    "claim '{0.name!s}' is constrained by policy but no recognition rule was "
                                    "supplied; held for manual confirmation".format(claim))

            return ClaimOutcome(claim, ClaimStatus.INFORMATIONAL, '')

        if claim.evidence is ClaimEvidence.EXTERNAL_ANNOTATION and rule.require_signature_bound:
            return ClaimOutcome(claim, ClaimStatus.UNPROTECTED,
                                "claim '{0.name!s}' arrived as an outer annotation not covered by the "
                                "signature; signature-bound evidence is required".format(claim))

        if not rule.accepts(claim.value):
            description = ' ({0})'.format(rule.description) if rule.description else ''
            return ClaimOutcome(claim, ClaimStatus.FAILED_CONDITION,
                                "claim '{0.name!s}' did not satisfy its business condition{1}".format(claim, description))

        return ClaimOutcome(claim, ClaimStatus.SATISFIED, '')


class SignatureReview(object):
    """The review outcome of a single signature.

    ``signature`` - the :py:obj:`~pgpy.PGPSignature` that was reviewed.

    ``subject`` - the subject the signature was verified against, if it was verified.

    ``queue`` - :py:obj:`ReviewQueue` the signature was routed to.

    ``outcomes`` - ``list`` of :py:obj:`ClaimOutcome` for each extracted claim.
    """

    __slots__ = ('signature', 'subject', 'queue', 'outcomes')

    def __init__(self, signature, subject, queue, outcomes):
        self.signature = signature
        self.subject = subject
        self.queue = queue
        self.outcomes = outcomes

    @property
    def pending_reasons(self):
        """A generator yielding the retained reasons this signature is held for confirmation."""
        return (outcome.reason for outcome in self.outcomes if outcome.status in _PENDING_STATUSES and outcome.reason)

    def __repr__(self):
        return '<{classname}({queue}, {outcomes} outcomes)>'.format(
            classname=self.__class__.__name__, queue=self.queue.name, outcomes=len(self.outcomes))


_PENDING_STATUSES = frozenset([ClaimStatus.FAILED_CONDITION,
                               ClaimStatus.UNPROTECTED,
                               ClaimStatus.UNRECOGNIZED_CONSTRAINED])


class PurposeReview(object):
    """Aggregate result of reviewing a :py:obj:`~pgpy.types.SignatureVerification`.

    ``accepted`` - ``list`` of :py:obj:`SignatureReview` routed to the accepted queue.

    ``pending`` - ``list`` of :py:obj:`SignatureReview` held for manual confirmation.

    ``rejected`` - ``list`` of :py:obj:`SignatureReview` whose signature math failed.
    """

    __slots__ = ('accepted', 'pending', 'rejected')

    def __init__(self):
        self.accepted = []
        self.pending = []
        self.rejected = []

    def __iter__(self):
        return itertools.chain(self.accepted, self.pending, self.rejected)

    def __len__(self):
        return len(self.accepted) + len(self.pending) + len(self.rejected)

    def __bool__(self):
        return bool(self.accepted) and not self.pending and not self.rejected

    def __nonzero__(self):
        return self.__bool__()

    def __repr__(self):
        return '<{classname}({accepted} accepted, {pending} pending, {rejected} rejected)>'.format(
            classname=self.__class__.__name__,
            accepted=len(self.accepted), pending=len(self.pending), rejected=len(self.rejected))


def review_signature(signature, subject, policy):
    """Review a single verified signature against a :py:obj:`PurposePolicy`.

    :param signature: the :py:obj:`~pgpy.PGPSignature` to review
    :param subject: the subject the signature was verified against
    :param policy: the :py:obj:`PurposePolicy` to apply
    :returns: a :py:obj:`SignatureReview`
    """
    outcomes = [policy.evaluate(claim) for claim in extract_claims(signature)]
    queue = ReviewQueue.PENDING if any(outcome.status in _PENDING_STATUSES for outcome in outcomes) \
        else ReviewQueue.ACCEPTED
    return SignatureReview(signature, subject, queue, outcomes)


def review_verification(verification, policy):
    """Split a :py:obj:`~pgpy.types.SignatureVerification` into review queues.

    Signatures that verified are evaluated against ``policy``; signatures that
    failed verification are routed straight to the rejected queue without
    evaluating their claims.

    :param verification: the :py:obj:`~pgpy.types.SignatureVerification` returned
        by :py:meth:`~pgpy.PGPKey.verify`
    :param policy: the :py:obj:`PurposePolicy` to apply
    :returns: a :py:obj:`PurposeReview`
    """
    review = PurposeReview()
    for sigsub in verification.good_signatures:
        sigreview = review_signature(sigsub.signature, sigsub.subject, policy)
        (review.accepted if sigreview.queue is ReviewQueue.ACCEPTED else review.pending).append(sigreview)

    for sigsub in verification.bad_signatures:
        review.rejected.append(SignatureReview(sigsub.signature, sigsub.subject, ReviewQueue.REJECTED, []))

    return review
