""" acceptance tests for pgpy.archive candidate reconciliation

Scenario: an archived message carries a detached PGP signature. The audit
side holds several exported representations of the message -- an exported
text rendering and an attachment preserving the original line endings --
and must determine which candidate the signature actually covers, without
ever auto-picking an evidentiary original when several candidates verify.
"""
import pytest

from pgpy import PGPKey
from pgpy.archive import AttributionState
from pgpy.archive import EquivalencePolicy
from pgpy.archive import EvidenceCandidate
from pgpy.archive import normalize_newlines
from pgpy.archive import verify_candidates
from pgpy.errors import PGPError


# the synthetic message as originally signed (LF line endings)
ORIGINAL = (b"From: archiver@example.com\n"
            b"Subject: quarterly report\n"
            b"\n"
            b"Hello,\n"
            b"this is a synthetic message for archival review.\n")

# same message, but the attachment preserved CRLF line endings
NEWLINE_VARIANT = ORIGINAL.replace(b"\n", b"\r\n")

# same shape, but actual words were changed
TAMPERED = ORIGINAL.replace(b"synthetic", b"doctored!!")


@pytest.fixture(scope='module')
def sec_key():
    return PGPKey.from_file('tests/testdata/keys/targette.sec.rsa.asc')[0]


@pytest.fixture(scope='module')
def pub_key():
    return PGPKey.from_file('tests/testdata/keys/targette.pub.rsa.asc')[0]


@pytest.fixture(scope='module')
def signature(sec_key):
    # detached binary-document signature over the exact original bytes
    return sec_key.sign(ORIGINAL)


@pytest.fixture()
def candidates():
    return [EvidenceCandidate('exported_text', {'body': ORIGINAL}),
            EvidenceCandidate('attachment', {'body': NEWLINE_VARIANT}),
            EvidenceCandidate('edited_export', {'body': TAMPERED})]


class TestVerifyCandidates(object):
    def test_exact_only_attributes_original(self, pub_key, signature, candidates):
        # with no equivalences approved, only the byte-exact candidate verifies
        result = verify_candidates(pub_key, signature, candidates, signed_part='body',
                                   policy=EquivalencePolicy.exact_only())

        assert result.state is AttributionState.VERIFIED_UNIQUE
        assert result.original.label == 'exported_text'
        assert not result.pending
        assert result.details['exported_text'] == ('exact',)
        assert result.details['attachment'] == ()
        assert result.details['edited_export'] == ()

    def test_approved_equivalence_leaves_ambiguity_pending(self, pub_key, signature, candidates):
        # caller approves newline equivalence: both the LF export and the CRLF
        # attachment verify, so the archiver must not auto-pick an original
        policy = EquivalencePolicy([normalize_newlines])
        result = verify_candidates(pub_key, signature, candidates, signed_part='body', policy=policy)

        assert result.state is AttributionState.AMBIGUOUS
        assert result.pending
        assert result.original is None
        assert {c.label for c in result.matches} == {'exported_text', 'attachment'}
        assert result.details['attachment'] == ('normalize_newlines',)
        # the genuinely altered text still does not verify
        assert result.details['edited_export'] == ()

    def test_tampered_candidate_never_verifies(self, pub_key, signature):
        result = verify_candidates(pub_key, signature,
                                   [EvidenceCandidate('edited_export', {'body': TAMPERED})],
                                   signed_part='body',
                                   policy=EquivalencePolicy([normalize_newlines]))

        assert result.state is AttributionState.NO_MATCH
        assert result.pending
        assert result.original is None
        assert result.matches == ()

    def test_signed_part_is_caller_declared(self, sec_key, pub_key):
        # one candidate whose exported text was altered, but whose attachment
        # holds the signed material; which part counts is the caller's call
        sig = sec_key.sign(NEWLINE_VARIANT)
        candidate = EvidenceCandidate('message', {'exported_text': TAMPERED,
                                                  'attachment': NEWLINE_VARIANT})

        as_attachment = verify_candidates(pub_key, sig, [candidate], signed_part='attachment')
        assert as_attachment.state is AttributionState.VERIFIED_UNIQUE
        assert as_attachment.original is candidate

        as_text = verify_candidates(pub_key, sig, [candidate], signed_part='exported_text')
        assert as_text.state is AttributionState.NO_MATCH

    def test_duplicate_labels_rejected(self, pub_key, signature):
        dupes = [EvidenceCandidate('same', {'body': ORIGINAL}),
                 EvidenceCandidate('same', {'body': NEWLINE_VARIANT})]
        with pytest.raises(PGPError):
            verify_candidates(pub_key, signature, dupes, signed_part='body')

    def test_missing_signed_part_rejected(self, pub_key, signature, candidates):
        with pytest.raises(PGPError):
            verify_candidates(pub_key, signature, candidates, signed_part='no_such_part')
