"""Regression tests for policy-aware re-export (``bleach.export``).

The scenario mirrors production: a customer-service representative pastes a
cleaned user comment into a rich-text e-mail while the back office can still
edit the original comment.  The fragments deliberately use ordinary
blockquotes and plain document links rather than exotic markup.
"""

import pytest

import bleach
from bleach import (
    CONFIRMED,
    UNCONFIRMED,
    PolicyRecord,
    admit,
    reexport,
)
from bleach.callbacks import target_blank
from bleach.linkifier import Linker
from bleach.sanitizer import Cleaner


# A user comment containing a normal blockquote, an existing document link and
# some markup that has to be removed on the way in.
COMMENT = (
    '<p>Please review '
    '<a href="https://example.com/docs" target="_blank" '
    'rel="nofollow noopener" onclick="steal()">the document</a> '
    "now.</p>\n"
    "<blockquote>see http://example.com/guide for details</blockquote>"
    "<script>alert(1)</script>"
)

# Rich-text e-mail export: links may keep href/title/rel but never target, and
# only the safe URI schemes are allowed.
EMAIL_TAGS = ["a", "blockquote", "p", "em", "strong", "code"]
EMAIL_ATTRIBUTES = {"a": ["href", "title", "rel"]}

# Back-office preview is intentionally wider: it additionally understands
# target on links and a few more presentational tags.
PREVIEW_TAGS = EMAIL_TAGS + ["b", "i", "ul", "ol", "li"]
PREVIEW_ATTRIBUTES = {"a": ["href", "title", "rel", "target"]}


@pytest.fixture
def email_cleaner():
    return Cleaner(
        tags=EMAIL_TAGS,
        attributes=EMAIL_ATTRIBUTES,
        protocols=["http", "https", "mailto"],
    )


@pytest.fixture
def preview_cleaner():
    return Cleaner(
        tags=PREVIEW_TAGS,
        attributes=PREVIEW_ATTRIBUTES,
        protocols=["http", "https", "mailto"],
    )


@pytest.fixture
def target_linker():
    # A linker whose callback re-adds target="_blank" on every link.
    return Linker(callbacks=[target_blank])


@pytest.fixture
def admitted():
    return admit(
        COMMENT,
        tags=EMAIL_TAGS,
        attributes=EMAIL_ATTRIBUTES,
        protocols=["http", "https", "mailto"],
    )


def test_admit_cleans_inbound_and_records_email_capabilities(admitted):
    # First-pass material is, by definition, not yet confirmed for an export.
    assert admitted.status == UNCONFIRMED
    assert admitted.confirmed is False

    # Dangerous markup is neutralised; the ordinary document link survives.
    assert "<script>" not in admitted.text
    assert "&lt;script&gt;" in admitted.text
    assert 'onclick="steal()"' not in admitted.text
    assert 'href="https://example.com/docs"' in admitted.text

    # The e-mail policy does not permit target, so it was dropped on the way in.
    assert 'target="_blank"' not in admitted.text
    assert 'rel="nofollow noopener"' in admitted.text

    # The record only describes capabilities the e-mail pass actually granted.
    record = admitted.record
    assert record.version == PolicyRecord(
        body_digest="", tags=[], attributes={}, protocols=[]
    ).version
    assert "a" in record.tags and "blockquote" in record.tags
    assert record.attributes == {"a": ["href", "rel", "title"]}
    assert record.protocols == ["http", "https", "mailto"]


def test_email_export_keeps_only_allowed_link_attributes(admitted, email_cleaner):
    result = reexport(admitted.text, admitted.record, email_cleaner)

    assert result.status == CONFIRMED
    assert result.confirmed is True

    # Allowed link attributes are retained; target is not part of the e-mail
    # policy so it stays absent.
    assert 'href="https://example.com/docs"' in result.text
    assert 'rel="nofollow noopener"' in result.text
    assert 'target="_blank"' not in result.text
    assert "onclick" not in result.text


def test_wider_preview_does_not_restore_removed_capability(
    admitted, preview_cleaner, target_linker
):
    # The preview policy is wider (target is allowed there) and the linker
    # callback would happily re-add it.  Because the body still matches the
    # e-mail record, the previously removed capability must not come back.
    result = reexport(
        admitted.text, admitted.record, preview_cleaner, linker=target_linker
    )

    assert result.status == CONFIRMED
    assert 'target="_blank"' not in result.text

    # The blockquote and an ordinary document link are still present.
    assert "<blockquote>" in result.text
    assert 'href="http://example.com/guide"' in result.text

    # The freshly emitted record reflects the intersected (narrower) policy.
    assert result.record.attributes == {"a": ["href", "rel", "title"]}
    assert "target" not in result.record.attributes["a"]


def test_preview_keeps_target_for_genuinely_unconfirmed_material(
    admitted, preview_cleaner, target_linker
):
    # The back office edited the comment, so the digest no longer matches.  The
    # material is now unconfirmed and must follow the full inbound rules of the
    # (wider) preview policy, where target is allowed.
    edited = admitted.text.replace("the document", "the updated document")
    result = reexport(
        edited, admitted.record, preview_cleaner, linker=target_linker
    )

    assert result.status == UNCONFIRMED
    assert result.confirmed is False
    assert 'target="_blank"' in result.text
    assert "the updated document" in result.text


def test_stale_record_version_is_treated_as_unconfirmed(
    admitted, preview_cleaner, target_linker
):
    stale = admitted.record.to_dict()
    stale["version"] = 999  # an older/incompatible record format

    result = reexport(
        admitted.text, stale, preview_cleaner, linker=target_linker
    )

    assert result.status == UNCONFIRMED
    assert result.confirmed is False
    # Full inbound rules of the wider preview policy now apply.
    assert 'target="_blank"' in result.text


def test_corrupt_record_is_treated_as_unconfirmed(
    admitted, preview_cleaner
):
    result = reexport(admitted.text, {"not": "a record"}, preview_cleaner)
    assert result.status == UNCONFIRMED
    assert result.confirmed is False


def test_record_round_trips_through_dict(admitted, preview_cleaner):
    restored = PolicyRecord.from_dict(admitted.record.to_dict())
    assert restored == admitted.record

    result = reexport(admitted.text, restored.to_dict(), preview_cleaner)
    assert result.status == CONFIRMED


def test_any_edit_invalidates_confirmation(admitted, preview_cleaner):
    # Even a single-character change must break the digest match.
    tweaked = admitted.text + " "
    result = reexport(tweaked, admitted.record, preview_cleaner)
    assert result.status == UNCONFIRMED


def test_confirmed_reexport_is_idempotent(admitted, preview_cleaner):
    first = reexport(admitted.text, admitted.record, preview_cleaner)
    second = reexport(first.text, first.record, preview_cleaner)

    assert first.status == CONFIRMED
    assert second.status == CONFIRMED
    assert second.text == first.text


def test_plain_clean_and_linkify_remain_available():
    # The new layer must not change the direct entry points.
    assert bleach.clean("<script>x</script>ok") == "&lt;script&gt;x&lt;/script&gt;ok"
    assert (
        bleach.linkify("see http://example.com")
        == 'see <a href="http://example.com" rel="nofollow">http://example.com</a>'
    )


def test_callable_attribute_policy_cannot_be_recorded():
    cleaner = Cleaner(
        tags=EMAIL_TAGS,
        attributes=lambda tag, attr, value: attr == "href",
    )
    # A callable policy cannot be serialised into a record, so building one
    # (as admit/reexport do) must fail loudly rather than silently broaden it.
    with pytest.raises(ValueError):
        bleach.export.build_record("body", cleaner)
