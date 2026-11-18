from detect_secrets.derivation.identity import DOMAIN_GROUP
from detect_secrets.derivation.identity import DOMAIN_OCCURRENCE
from detect_secrets.derivation.identity import DOMAIN_RELATIONSHIP
from detect_secrets.derivation.identity import DOMAIN_VALUE
from detect_secrets.derivation.identity import SCHEMA_VERSION
from detect_secrets.derivation.identity import compute_group_identity
from detect_secrets.derivation.identity import compute_occurrence_identity
from detect_secrets.derivation.identity import compute_relationship_identity
from detect_secrets.derivation.identity import compute_value_identity
from detect_secrets.derivation.identity import mask_secret


SECRET = "AKIATEST-123_456.secret/value"


class TestDomainSeparation:
    @staticmethod
    def test_domains_are_distinct():
        assert len({DOMAIN_OCCURRENCE, DOMAIN_VALUE, DOMAIN_GROUP, DOMAIN_RELATIONSHIP}) == 4

    @staticmethod
    def test_same_value_different_domains_yield_different_identities():
        occurrence = compute_occurrence_identity("t", "typ", "f", 1, SECRET)
        value = compute_value_identity(SECRET)
        assert occurrence != value

    @staticmethod
    def test_identity_never_contains_plaintext():
        occurrence = compute_occurrence_identity("t", "typ", "f", 1, SECRET)
        value = compute_value_identity(SECRET)
        group = compute_group_identity(value, [occurrence])
        relationship = compute_relationship_identity("t", occurrence, occurrence)
        for digest in (occurrence, value, group, relationship):
            assert SECRET not in digest
            assert digest == digest.lower()
            assert len(digest) == 64


class TestOccurrenceIdentity:
    @staticmethod
    def test_is_deterministic():
        first = compute_occurrence_identity("acme", "AWS Access Key", "a.txt", 3, SECRET)
        second = compute_occurrence_identity("acme", "AWS Access Key", "a.txt", 3, SECRET)
        assert first == second

    @staticmethod
    def test_tenant_isolates_identical_candidates():
        left = compute_occurrence_identity("acme", "t", "f", 1, SECRET)
        right = compute_occurrence_identity("globex", "t", "f", 1, SECRET)
        assert left != right

    @staticmethod
    def test_location_participates_in_identity():
        left = compute_occurrence_identity("t", "t", "a.txt", 1, SECRET)
        right = compute_occurrence_identity("t", "t", "b.txt", 1, SECRET)
        assert left != right


class TestGroupAndRelationshipIdentity:
    @staticmethod
    def test_group_identity_is_order_independent():
        value = compute_value_identity(SECRET)
        first = compute_group_identity(value, ["a", "b", "c"])
        second = compute_group_identity(value, ["c", "a", "b"])
        assert first == second

    @staticmethod
    def test_relationship_identity_is_order_independent():
        first = compute_relationship_identity("t", "a", "b")
        second = compute_relationship_identity("t", "b", "a")
        assert first == second


class TestMasking:
    @staticmethod
    def test_mask_hides_middle_of_secret():
        masked = mask_secret(SECRET)
        assert masked.startswith(SECRET[:2])
        assert masked.endswith(SECRET[-4:])
        assert SECRET not in masked
        assert "*" in masked

    @staticmethod
    def test_mask_fully_hides_short_secrets():
        assert mask_secret("short") == "*****"

    @staticmethod
    def test_mask_handles_empty_value():
        assert mask_secret("") == ""


def test_schema_version_is_pinned():
    assert SCHEMA_VERSION == 1
