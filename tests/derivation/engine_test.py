import base64
import json
from urllib.parse import quote

from detect_secrets.derivation import MAX_CHAIN_DEPTH
from detect_secrets.derivation import analyze_observations
from detect_secrets.derivation import build_derivation_report
from detect_secrets.derivation import build_observations
from detect_secrets.derivation import clear_plaintext
from detect_secrets.derivation.engine import _edit_distance
from detect_secrets.derivation.engine import _looks_related


TENANT = "acme"
SECRET_TYPE = "AWS Access Key"
# A credential containing characters that exercise every supported encoding.
SECRET = "AKIA/TEST+123=456_secret"


def _observation(filename, line_number, raw_value, tenant=TENANT, secret_type=SECRET_TYPE):
    return (tenant, secret_type, filename, line_number, raw_value)


def _analyze(candidates, tenant=TENANT):
    return analyze_observations(build_observations(candidates), tenant=tenant)


class TestMultiLayerEncoding:
    @staticmethod
    def test_merges_raw_url_json_base64_and_layered_forms():
        url_form = quote(SECRET, safe="")
        json_form = json.dumps(SECRET)[1:-1]
        base64_form = base64.b64encode(SECRET.encode()).decode()
        layered_form = quote(base64_form, safe="")
        candidates = [
            _observation("plain.txt", 1, SECRET),
            _observation("url.txt", 2, url_form),
            _observation("json.txt", 3, json_form),
            _observation("base64.txt", 4, base64_form),
            _observation("layered.txt", 5, layered_form),
        ]

        analysis = _analyze(candidates)
        assert len(analysis.groups) == 1
        group = analysis.groups[0]
        assert len(group.members) == 5
        assert {member.filename for member in group.members} == {
            "plain.txt",
            "url.txt",
            "json.txt",
            "base64.txt",
            "layered.txt",
        }
        assert analysis.unverifiable_relationships == []


    @staticmethod
    def test_every_chain_step_keeps_original_location():
        base64_form = base64.b64encode(SECRET.encode()).decode()
        # A space guarantees a real percent-encoding layer on top of Base64.
        layered_secret = " " + SECRET
        base64_form = base64.b64encode(layered_secret.encode()).decode()
        layered_form = quote(base64_form, safe="")
        assert "%" in layered_form
        candidates = [
            _observation("plain.txt", 1, layered_secret),
            _observation("layered.txt", 7, layered_form),
        ]

        analysis = _analyze(candidates)
        member = next(
            member
            for member in analysis.groups[0].members
            if member.filename == "layered.txt"
        )
        assert member.line_number == 7
        assert [step.transform for step in member.chain] == [
            "url_decode",
            "base64_decode",
        ]
        for step in member.chain:
            assert step.source_location == {
                "filename": "layered.txt",
                "line_number": 7,
            }
            assert step.input_identity != step.output_identity

    @staticmethod
    def test_chain_depth_is_limited():
        # Three nested base64 layers decode within the bound; a fourth is
        # never explored.
        once = base64.b64encode(SECRET.encode()).decode()
        twice = base64.b64encode(once.encode()).decode()
        thrice = base64.b64encode(twice.encode()).decode()
        four_times = base64.b64encode(thrice.encode()).decode()
        assert MAX_CHAIN_DEPTH == 3

        analysis = _analyze([
            _observation("root.txt", 1, SECRET),
            _observation("three.txt", 2, thrice),
            _observation("four.txt", 3, four_times),
        ])

        secret_group = next(
            group
            for group in analysis.groups
            if any(member.filename == "root.txt" for member in group.members)
        )
        secret_files = {member.filename for member in secret_group.members}
        # The root and the three-layer form share the canonical secret.
        assert {"root.txt", "three.txt"} <= secret_files
        # The four-layer form cannot reach the canonical secret within the
        # bound, so it never joins the secret-backed group, even though it may
        # form a separate group around a shared intermediate encoding.
        assert "four.txt" not in secret_files


class TestCollisionAndSimilarity:
    @staticmethod
    def test_shared_suffix_does_not_merge():
        # Same 4-char tail, entirely different prefix: no decode relationship.
        left = "AKIAIOIOIOIOIOIOABCD"
        right = "ASIAZZZZZZZZZZZZABCD"
        analysis = _analyze([
            _observation("a.txt", 1, left),
            _observation("b.txt", 2, right),
        ])
        assert analysis.groups == []

    @staticmethod
    def test_shared_prefix_does_not_merge():
        left = "AKIAIOIOIOIOIOIOABCD"
        right = "AKIAZZZZZZZZZZZZZZZZ"
        analysis = _analyze([
            _observation("a.txt", 1, left),
            _observation("b.txt", 2, right),
        ])
        assert analysis.groups == []

    @staticmethod
    def test_mask_only_cannot_establish_identity():
        real = "AKIAIOIOIOIOIOIOABCD"
        masked = "AK**************ABCD"
        analysis = _analyze([
            _observation("a.txt", 1, real),
            _observation("b.txt", 2, masked),
        ])
        assert analysis.groups == []

    @staticmethod
    def test_look_alikes_are_listed_as_unverifiable():
        left = "AKIAIOIOIOIOIOIOABCD"
        right = "AKIAIOIOIOIOIOABCE"
        analysis = _analyze([
            _observation("a.txt", 1, left),
            _observation("b.txt", 2, right),
        ])
        assert analysis.groups == []
        assert len(analysis.unverifiable_relationships) == 1
        candidate = analysis.unverifiable_relationships[0]
        assert candidate.reason == "no_verifiable_decode_chain"
        assert left not in candidate.masked_left
        assert right not in candidate.masked_right
        assert "*" in candidate.masked_left


class TestTenantIsolation:
    @staticmethod
    def test_identical_secret_in_different_tenants_never_merges():
        candidates = [
            _observation("a.txt", 1, SECRET, tenant="acme"),
            _observation("b.txt", 2, SECRET, tenant="globex"),
        ]
        analysis = analyze_observations(build_observations(candidates), tenant="acme")
        # The other tenant is filtered out entirely.
        assert len(analysis.observations) == 1
        assert analysis.groups == []

    @staticmethod
    def test_cross_tenant_identities_never_match():
        left = build_observations([_observation("a.txt", 1, SECRET, tenant="acme")])[0]
        right = build_observations([_observation("a.txt", 1, SECRET, tenant="globex")])[0]
        assert left.occurrence_identity != right.occurrence_identity

    @staticmethod
    def test_same_tenant_identical_values_merge():
        analysis = _analyze([
            _observation("a.txt", 1, SECRET),
            _observation("b.txt", 2, SECRET),
        ])
        assert len(analysis.groups) == 1
        assert len(analysis.groups[0].members) == 2


class TestRescanStability:
    @staticmethod
    def test_repeated_analysis_produces_identical_report():
        url_form = quote(SECRET, safe="")
        candidates = [
            _observation("plain.txt", 1, SECRET),
            _observation("url.txt", 2, url_form),
            _observation("other.txt", 3, "AKIAIOIOIOIOIOIOABCD"),
        ]
        first = build_derivation_report(candidates).to_dict()
        second = build_derivation_report(candidates).to_dict()
        assert first == second

    @staticmethod
    def test_input_order_does_not_change_identities():
        url_form = quote(SECRET, safe="")
        forward = build_derivation_report([
            _observation("plain.txt", 1, SECRET),
            _observation("url.txt", 2, url_form),
        ]).to_dict()
        reverse = build_derivation_report([
            _observation("url.txt", 2, url_form),
            _observation("plain.txt", 1, SECRET),
        ]).to_dict()
        assert forward["groups"] == reverse["groups"]


class TestHeuristics:
    @staticmethod
    def test_looks_related_requires_shared_material():
        assert _looks_related("AKIAIOIOIOIOIOIOABCD", "AKIAIOIOIOIOIOABCE")
        assert not _looks_related("totally-different-one", "another-secret-here")

    @staticmethod
    def test_looks_related_handles_empty_strings():
        assert not _looks_related("", "secret")
        assert _looks_related("same", "same")

    @staticmethod
    def test_edit_distance():
        assert _edit_distance("abc", "abc") == 0
        assert _edit_distance("abc", "abd") == 1
        assert _edit_distance("kitten", "sitting") == 3


class TestPlaintextLifecycle:
    @staticmethod
    def test_clear_plaintext_drops_in_memory_values():
        analysis = _analyze([
            _observation("a.txt", 1, SECRET),
            _observation("b.txt", 2, quote(SECRET, safe="")),
        ])
        assert all(observation.raw_value for observation in analysis.observations)
        clear_plaintext(analysis)
        assert all(
            observation.raw_value == ""
            for observation in analysis.observations
        )
        # Identities and grouped relationships remain usable after clearing.
        report = analysis.to_report().to_dict()
        assert len(report["groups"]) == 1
        assert SECRET not in json.dumps(report)
