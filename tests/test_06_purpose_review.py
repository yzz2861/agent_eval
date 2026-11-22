""" test the optional purpose-review layer in pgpy.purpose

all signature material is synthesized locally: one key is generated per test
module run, and every sample is signed with it. both review queues are fed
with mathematically valid signatures whose notation claims differ in evidence
quality.
"""
import pytest

from pgpy import PGPKey
from pgpy import PGPUID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import NotationDataFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.purpose import ClaimEvidence
from pgpy.purpose import ClaimRule
from pgpy.purpose import ClaimStatus
from pgpy.purpose import PurposePolicy
from pgpy.purpose import ReviewQueue
from pgpy.purpose import extract_claims
from pgpy.purpose import review_signature
from pgpy.purpose import review_verification


PURPOSE = 'purpose@example.com'
RETENTION = 'retention-class@example.com'


@pytest.fixture(scope='module')
def sec():
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = PGPUID.new('Purpose Review', comment='synthesized locally', email='review@localhost.local')
    key.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    return key


@pytest.fixture(scope='module')
def pub(sec):
    return sec.pubkey


@pytest.fixture(scope='module')
def policy():
    return PurposePolicy(
        rules={PURPOSE: {'archive-retrieval', 'archive-seal'}},
        constrained={RETENTION},
    )


def sign_text(sec, text, notation=None):
    return text, sec.sign(text, notation=notation)


def add_outer_annotation(sig, name, value):
    # attach a notation to the unhashed subpacket area after signing, the same
    # way a transit system could annotate a signature without invalidating it
    sig._signature.subpackets.addnew('NotationData', hashed=False,
                                     flags=NotationDataFlags.HumanReadable,
                                     name=name, value=value)


class TestClaimExtraction(object):
    def test_extract_claims_distinguishes_evidence(self, sec):
        _, sig = sign_text(sec, 'evidence split', notation={PURPOSE: 'archive-retrieval'})
        add_outer_annotation(sig, PURPOSE, 'archive-seal')

        claims = extract_claims(sig)

        assert len(claims) == 2
        by_evidence = {claim.evidence: claim for claim in claims}
        assert by_evidence[ClaimEvidence.SIGNATURE_BOUND].value == 'archive-retrieval'
        assert by_evidence[ClaimEvidence.EXTERNAL_ANNOTATION].value == 'archive-seal'
        assert all(claim.human_readable for claim in claims)

    def test_extract_claims_empty(self, sec):
        _, sig = sign_text(sec, 'no claims')
        assert extract_claims(sig) == []


class TestReviewQueues(object):
    def test_valid_signature_recognized_claim_accepted(self, sec, pub, policy):
        text, sig = sign_text(sec, 'sample A', notation={PURPOSE: 'archive-retrieval'})
        verification = pub.verify(text, sig)
        assert verification

        review = review_verification(verification, policy)

        assert len(review.accepted) == 1
        assert not review.pending
        assert not review.rejected
        assert review.accepted[0].queue is ReviewQueue.ACCEPTED
        assert review.accepted[0].outcomes[0].status is ClaimStatus.SATISFIED

    def test_valid_signature_outer_annotation_pending(self, sec, pub, policy):
        # same claim, same valid signature math - but the claim rides as an
        # outer annotation, so its evidence quality routes it to pending
        message, sig = sign_text(sec, 'sample B')
        add_outer_annotation(sig, PURPOSE, 'archive-retrieval')
        verification = pub.verify('sample B', sig)
        assert verification

        review = review_verification(verification, policy)

        assert len(review.pending) == 1
        assert not review.accepted
        outcome = review.pending[0].outcomes[0]
        assert outcome.status is ClaimStatus.UNPROTECTED
        assert 'not covered by the signature' in next(iter(review.pending[0].pending_reasons))

    def test_same_policy_routes_two_valid_samples_differently(self, sec, pub, policy):
        # the archival cross-check: two mathematically valid samples diverge
        # into different review queues on claim evidence quality alone
        _, bound_sig = sign_text(sec, 'cross-check', notation={PURPOSE: 'archive-retrieval'})
        _, annotated_sig = sign_text(sec, 'cross-check')
        add_outer_annotation(annotated_sig, PURPOSE, 'archive-retrieval')

        bound_review = review_verification(pub.verify('cross-check', bound_sig), policy)
        annotated_review = review_verification(pub.verify('cross-check', annotated_sig), policy)

        assert len(bound_review.accepted) == 1
        assert len(annotated_review.pending) == 1

    def test_unrecognized_constrained_claim_pending_with_reason(self, sec, pub, policy):
        message, sig = sign_text(sec, 'sample C', notation={RETENTION: 'permanent'})
        verification = pub.verify(message, sig)
        assert verification

        review = review_verification(verification, policy)

        assert len(review.pending) == 1
        outcome = review.pending[0].outcomes[0]
        assert outcome.status is ClaimStatus.UNRECOGNIZED_CONSTRAINED
        reason = next(iter(review.pending[0].pending_reasons))
        assert RETENTION in reason
        assert 'manual confirmation' in reason

    def test_failed_condition_pending(self, sec, pub, policy):
        message, sig = sign_text(sec, 'sample D', notation={PURPOSE: 'shred-immediately'})
        verification = pub.verify(message, sig)
        assert verification

        review = review_verification(verification, policy)

        assert len(review.pending) == 1
        outcome = review.pending[0].outcomes[0]
        assert outcome.status is ClaimStatus.FAILED_CONDITION
        assert 'business condition' in next(iter(review.pending[0].pending_reasons))

    def test_unconstrained_unknown_claim_is_informational(self, sec, pub, policy):
        message, sig = sign_text(sec, 'sample E', notation={'debugging@example.com': 'on'})
        verification = pub.verify(message, sig)
        assert verification

        review = review_verification(verification, policy)

        assert len(review.accepted) == 1
        assert review.accepted[0].outcomes[0].status is ClaimStatus.INFORMATIONAL

    def test_bad_signature_rejected(self, sec, pub, policy):
        text, sig = sign_text(sec, 'sample F', notation={PURPOSE: 'archive-retrieval'})
        verification = pub.verify(text + ' tampered', sig)
        assert not verification

        review = review_verification(verification, policy)

        assert len(review.rejected) == 1
        assert not review.accepted
        assert not review.pending
        assert review.rejected[0].queue is ReviewQueue.REJECTED
        assert review.rejected[0].outcomes == []


class TestPolicyObjects(object):
    def test_callable_rule(self, sec, pub):
        policy = PurposePolicy(rules={PURPOSE: lambda value: value.startswith('archive-')})
        message, sig = sign_text(sec, 'callable', notation={PURPOSE: 'archive-retrieval'})

        review = review_verification(pub.verify(message, sig), policy)

        assert len(review.accepted) == 1

    def test_raising_condition_fails_closed(self, sec, pub):
        def explode(value):
            raise ValueError('cannot check')

        policy = PurposePolicy(rules={PURPOSE: ClaimRule(explode)})
        message, sig = sign_text(sec, 'exploding', notation={PURPOSE: 'archive-retrieval'})

        review = review_verification(pub.verify(message, sig), policy)

        assert len(review.pending) == 1
        assert review.pending[0].outcomes[0].status is ClaimStatus.FAILED_CONDITION

    def test_constrain_unknown(self, sec, pub):
        policy = PurposePolicy(constrain_unknown=True)
        message, sig = sign_text(sec, 'unknown', notation={'anything@example.com': 'x'})

        review = review_verification(pub.verify(message, sig), policy)

        assert len(review.pending) == 1
        assert review.pending[0].outcomes[0].status is ClaimStatus.UNRECOGNIZED_CONSTRAINED

    def test_annotation_allowed_when_signature_bound_not_required(self, sec, pub):
        policy = PurposePolicy(rules={PURPOSE: ClaimRule(lambda value: True, require_signature_bound=False)})
        message, sig = sign_text(sec, 'lax')
        add_outer_annotation(sig, PURPOSE, 'archive-retrieval')

        review = review_verification(pub.verify(message, sig), policy)

        assert len(review.accepted) == 1

    def test_review_signature_directly(self, sec, policy):
        message, sig = sign_text(sec, 'direct', notation={PURPOSE: 'archive-seal'})

        sigreview = review_signature(sig, message, policy)

        assert sigreview.queue is ReviewQueue.ACCEPTED
        assert sigreview.subject is message

    def test_purpose_review_truthiness(self, sec, pub, policy):
        message, sig = sign_text(sec, 'truthy', notation={PURPOSE: 'archive-seal'})

        assert review_verification(pub.verify(message, sig), policy)

        pending_message, pending_sig = sign_text(sec, 'truthy', notation={RETENTION: 'permanent'})
        assert not review_verification(pub.verify(pending_message, pending_sig), policy)
