from unittest.mock import Mock
from unittest.mock import patch

from pathutils import dotname
from pathutils import full_path
from pytest import raises

from saml2 import saml
from saml2 import samlp
from saml2.config import config_factory
from saml2.response import authn_response
from saml2.sigver import SignatureBindingError
from saml2.sigver import SignatureError
from saml2.sigver import build_id_index
from saml2.sigver import node_signature_verified
from saml2.sigver import pre_signature_part
from saml2.sigver import resolve_signature_reference
from saml2.sigver import signed_instance_factory
from saml2.sigver import valid_ncname
from saml2.s_utils import success_status_factory

SIGNED_XSW_ASSERTION_WRAPPER = full_path("xsw/signed-xsw-assertion-wrapper.xml")
SIGNED_XSW_ASSERTION_EXTENSIONS = full_path("xsw/signed-xsw-assertion-extensions.xml")
SIGNED_XSW_ASSERTION_ASSERTION = full_path("xsw/signed-xsw-assertion-assertion.xml")

SIGNED_ASSERTION_FIRST_SIG = full_path("xsw/signed-xsw-assertion-in-assertion-first-sig.xml")
SIGNED_REPONSE_FIRST_SIG = full_path("xsw/signed-xsw-response-in-response-first-sig.xml")
SIGNED_DUPLICATE_ID = full_path("xsw/signed-xsw-duplicate-id.xml")
SIGNED_WRAPPER_COMMENTS_CDATA = full_path("xsw/signed-xsw-assertion-wrapper-comments-cdata.xml")


class TestXSW:
    def setup_class(self):
        self.conf = config_factory("sp", dotname("server_conf"))
        self.ar = authn_response(self.conf, return_addrs="https://example.org/acs/post")

    @patch("saml2.response.validate_on_or_after", return_value=True)
    def test_signed_xsw_assertion_wrapper_should_fail(self, mock_validate_on_or_after):
        self.ar.issue_instant_ok = Mock(return_value=True)

        with open(SIGNED_XSW_ASSERTION_WRAPPER) as fp:
            xml_response = fp.read()

        self.ar.outstanding_queries = {"id-abc": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        self.ar.loads(xml_response, decode=False)

        assert self.ar.came_from == "http://localhost:8088/sso"
        assert self.ar.session_id() == "id-abc"
        assert self.ar.issuer() == "urn:mace:example.com:saml:roland:idp"

        with raises(SignatureError):
            self.ar.verify()

        assert self.ar.ava is None
        assert self.ar.name_id is None

    @patch("saml2.response.validate_on_or_after", return_value=True)
    def test_signed_xsw_assertion_extensions_should_fail(self, mock_validate_on_or_after):
        self.ar.issue_instant_ok = Mock(return_value=True)

        with open(SIGNED_XSW_ASSERTION_EXTENSIONS) as fp:
            xml_response = fp.read()

        self.ar.outstanding_queries = {"id-abc": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        self.ar.loads(xml_response, decode=False)

        assert self.ar.came_from == "http://localhost:8088/sso"
        assert self.ar.session_id() == "id-abc"
        assert self.ar.issuer() == "urn:mace:example.com:saml:roland:idp"

        with raises(SignatureError):
            self.ar.verify()

        assert self.ar.ava is None
        assert self.ar.name_id is None

    @patch("saml2.response.validate_on_or_after", return_value=True)
    def test_signed_xsw_assertion_assertion_should_fail(self, mock_validate_on_or_after):
        self.ar.issue_instant_ok = Mock(return_value=True)

        with open(SIGNED_XSW_ASSERTION_ASSERTION) as fp:
            xml_response = fp.read()

        self.ar.outstanding_queries = {"id-abc": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        self.ar.loads(xml_response, decode=False)

        assert self.ar.came_from == "http://localhost:8088/sso"
        assert self.ar.session_id() == "id-abc"
        assert self.ar.issuer() == "urn:mace:example.com:saml:roland:idp"

        with raises(SignatureError):
            self.ar.verify()

        assert self.ar.ava is None
        assert self.ar.name_id is None


class TestInvalidDepthFirstSig:
    def setup_class(self):
        self.conf = config_factory("sp", dotname("server_conf"))
        self.ar = authn_response(self.conf, return_addrs="https://example.org/acs/post")

    @patch("saml2.response.validate_on_or_after", return_value=True)
    def test_signed_assertion_first_sig_should_fail(self, mock_validate_on_or_after):
        self.ar.issue_instant_ok = Mock(return_value=True)

        with open(SIGNED_ASSERTION_FIRST_SIG) as fp:
            xml_response = fp.read()

        self.ar.outstanding_queries = {"id-abc": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        self.ar.loads(xml_response, decode=False)

        assert self.ar.came_from == "http://localhost:8088/sso"
        assert self.ar.session_id() == "id-abc"
        assert self.ar.issuer() == "urn:mace:example.com:saml:roland:idp"

        with raises(SignatureError):
            self.ar.verify()

        assert self.ar.ava is None
        assert self.ar.name_id is None

    @patch("saml2.response.validate_on_or_after", return_value=True)
    def test_signed_response_first_sig_should_fail(self, mock_validate_on_or_after):
        self.ar.issue_instant_ok = Mock(return_value=True)

        with open(SIGNED_REPONSE_FIRST_SIG) as fp:
            xml_response = fp.read()

        self.ar.outstanding_queries = {"id-abc": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        with raises(SignatureError):
            self.ar.loads(xml_response, decode=False)


class TestIdIndexBinding:
    """Document-wide ID index and signature-to-node binding rules."""

    def setup_class(self):
        self.conf = config_factory("sp", dotname("server_conf"))
        self.ar = authn_response(self.conf, return_addrs="https://example.org/acs/post")

    def _load(self, path):
        with open(path) as fp:
            xml_response = fp.read()
        return samlp.response_from_string(xml_response)

    def test_ncname_validation(self):
        assert valid_ncname("assertion-1")
        assert valid_ncname("_abc")
        assert not valid_ncname("")
        assert not valid_ncname("1leading-digit")
        assert not valid_ncname("has space")
        assert not valid_ncname("has:colon")

    def test_duplicate_id_is_rejected_before_verification(self):
        response = self._load(SIGNED_DUPLICATE_ID)
        with raises(SignatureBindingError, match="Duplicate ID"):
            build_id_index(response)

    def test_duplicate_id_end_to_end(self):
        self.ar.issue_instant_ok = Mock(return_value=True)
        with open(SIGNED_DUPLICATE_ID) as fp:
            xml_response = fp.read()
        self.ar.outstanding_queries = {"id-abc": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        with patch("saml2.response.validate_on_or_after", return_value=True):
            with raises(SignatureBindingError):
                self.ar.loads(xml_response, decode=False)
        assert self.ar.ava is None
        assert self.ar.name_id is None

    def test_empty_id_is_rejected(self):
        response = self._load(SIGNED_XSW_ASSERTION_WRAPPER)
        response.assertion[0].id = ""
        with raises(SignatureBindingError, match="Empty ID"):
            build_id_index(response)

    def test_illegal_ncname_is_rejected(self):
        response = self._load(SIGNED_XSW_ASSERTION_WRAPPER)
        response.assertion[0].id = "1-not-a-ncname"
        with raises(SignatureBindingError, match="NCName"):
            build_id_index(response)

    def test_id_attribute_is_case_sensitive(self):
        # A lower-case "id" attribute must never be treated as the SAML ID.
        response = self._load(SIGNED_XSW_ASSERTION_WRAPPER)
        assertion = response.assertion[0]
        assertion.extension_attributes["id"] = "lowercase-shadow"
        index = build_id_index(response)
        assert "lowercase-shadow" not in index
        assert index["the-attack-assertion"] is assertion

    def test_lowercase_id_attribute_in_raw_xml_is_not_indexed(self):
        with open(SIGNED_XSW_ASSERTION_WRAPPER) as fp:
            xml_response = fp.read()
        lowercase = xml_response.replace('ID="the-attack-assertion"', 'id="the-attack-assertion"')
        response = samlp.response_from_string(lowercase)
        index = build_id_index(response)
        assert "the-attack-assertion" not in index
        assert set(index) == {"the-response", "the-assertion"}

    def test_comments_and_cdata_do_not_hide_nodes(self):
        response = self._load(SIGNED_WRAPPER_COMMENTS_CDATA)
        index = build_id_index(response)
        # The assertion hidden next to comments/CDATA still has to be indexed,
        # otherwise a signature reference could resolve to the wrong object.
        assert set(index) == {"the-response", "the-attack-assertion", "the-assertion"}

    def test_signature_reference_must_point_at_its_carrier(self):
        response = self._load(SIGNED_XSW_ASSERTION_WRAPPER)
        index = build_id_index(response)
        attack_assertion = response.assertion[0]
        reference_uri = attack_assertion.signature.signed_info.reference[0].uri
        with raises(SignatureBindingError, match="carried by node"):
            resolve_signature_reference(attack_assertion, reference_uri, index)

    def test_unknown_reference_is_a_binding_error(self):
        response = self._load(SIGNED_XSW_ASSERTION_WRAPPER)
        index = build_id_index(response)
        attack_assertion = response.assertion[0]
        with raises(SignatureBindingError, match="does not match any node"):
            resolve_signature_reference(attack_assertion, "#does-not-exist", index)

    def test_binding_error_is_a_signature_error(self):
        assert issubclass(SignatureBindingError, SignatureError)

    def test_verified_identity_follows_the_object_not_its_name(self):
        response = self._load(SIGNED_XSW_ASSERTION_WRAPPER)
        index = build_id_index(response)
        honest = index["the-assertion"]
        # The honest node carries no signature in this wrapper document, so
        # nothing can mark it verified through the attack assertion.
        assert node_signature_verified(honest) is False
        assert node_signature_verified(response.assertion[0]) is False

    def test_wrapping_attack_inside_comment_cdata_still_fails(self):
        self.ar.issue_instant_ok = Mock(return_value=True)
        with open(SIGNED_WRAPPER_COMMENTS_CDATA) as fp:
            xml_response = fp.read()
        self.ar.outstanding_queries = {"id-abc": "http://localhost:8088/sso"}
        self.ar.timeslack = 10000
        with patch("saml2.response.validate_on_or_after", return_value=True):
            self.ar.loads(xml_response, decode=False)
            with raises(SignatureError):
                self.ar.verify()
        assert self.ar.ava is None
        assert self.ar.name_id is None


class TestMultipleReferenceAndDoubleSignature:
    """Multiple references and response+assertion double signatures."""

    def setup_class(self):
        from test_40_sigver import TestSecurity

        tester = TestSecurity()
        tester.setup_class()
        self.sec = tester.sec
        self.assertion = tester._assertion
        self.assertion.issuer.text = "urn:mace:example.com:saml:roland:idp"

    def _response(self, response_id, signed_response=False):
        signature = pre_signature_part(response_id, self.sec.my_cert) if signed_response else None
        return samlp.Response(
            id=response_id,
            version="2.0",
            issue_instant="2099-10-30T13:20:28Z",
            issuer=saml.Issuer(text="the-issuer"),
            status=success_status_factory(),
            assertion=self.assertion,
            signature=signature,
        )

    def _sign(self, response, response_id, sign_response):
        to_sign = [
            (saml.Assertion.c_namespace + ":Assertion", self.assertion.id),
        ]
        if sign_response:
            to_sign.append((samlp.Response.c_namespace + ":Response", response_id))
        return signed_instance_factory(response, self.sec, to_sign)

    def test_multiple_reference_elements_are_rejected(self):
        response = self._response("id-multi-ref")
        signed_xml = self._sign(response, response.id, sign_response=False)
        parsed = samlp.response_from_string(signed_xml)
        assertion = parsed.assertion[0]
        signed_info = assertion.signature.signed_info
        signed_info.reference = list(signed_info.reference) * 2

        with raises(SignatureError):
            self.sec.check_signature(assertion, saml.Assertion.c_namespace + ":Assertion", signed_xml)

    def test_signed_assertion_inside_unsigned_response_still_binds(self):
        response = self._response("id-unsigned-response")
        signed_xml = self._sign(response, response.id, sign_response=False)
        parsed = samlp.response_from_string(signed_xml)
        assert parsed.signature is None

        # The envelope is unsigned, so the assertion signature is verified
        # while parsing the assertion (same path the response object uses).
        assertion = parsed.assertion[0]
        verified = self.sec.check_signature(assertion, saml.Assertion.c_namespace + ":Assertion", signed_xml)
        assert verified is assertion
        assert node_signature_verified(assertion) is True

    def test_response_and_assertion_double_signature_verifies_and_binds(self):
        response = self._response("id-signed-response", signed_response=True)
        signed_xml = self._sign(response, response.id, sign_response=True)
        parsed = samlp.response_from_string(signed_xml)
        assert parsed.signature is not None

        verified_response = self.sec.correctly_signed_response(signed_xml)
        assert node_signature_verified(verified_response) is True

        assertion = verified_response.assertion[0]
        verified_assertion = self.sec.check_signature(assertion, saml.Assertion.c_namespace + ":Assertion", signed_xml)
        assert verified_assertion is assertion
        assert node_signature_verified(assertion) is True

    def test_double_signed_response_rejects_relocated_reference(self):
        response = self._response("id-relocated", signed_response=True)
        signed_xml = self._sign(response, response.id, sign_response=True)
        parsed = samlp.response_from_string(signed_xml)

        # Tamper with the assertion signature so its reference points at the
        # response node instead of its carrier: binding must fail even though
        # the cryptographic material itself is untouched.
        assertion = parsed.assertion[0]
        assertion.signature.signed_info.reference[0].uri = f"#{parsed.id}"
        with raises(SignatureBindingError):
            self.sec.check_signature(assertion, saml.Assertion.c_namespace + ":Assertion", signed_xml)


class TestEndToEndBinding:
    """Full response parsing must only consume signature-bound assertions."""

    def setup_class(self):
        from contextlib import closing

        from saml2.authn_context import INTERNETPROTOCOLPASSWORD
        from saml2.server import Server

        authn = {
            "class_ref": INTERNETPROTOCOLPASSWORD,
            "authn_auth": "http://www.example.com/login",
        }
        with closing(Server("idp_conf")) as server:
            name_id = server.ident.transient_nameid("urn:mace:example.com:saml:roland:sp", "id12")
            self.unsigned_response = str(
                server.create_authn_response(
                    {"surName": ["Jeter"], "givenName": ["Derek"]},
                    in_response_to="id12",
                    destination="https://example.org/acs/post",
                    sp_entity_id="urn:mace:example.com:saml:roland:sp",
                    name_id=name_id,
                )
            )
            self.signed_assertion_response = str(
                server.create_authn_response(
                    {"surName": ["Jeter"], "givenName": ["Derek"]},
                    in_response_to="id12",
                    destination="https://example.org/acs/post",
                    sp_entity_id="urn:mace:example.com:saml:roland:sp",
                    name_id=name_id,
                    sign_assertion=True,
                    authn=authn,
                )
            )
        self.conf = config_factory("sp", dotname("server_conf"))
        self.ar = authn_response(self.conf, return_addrs="https://example.org/acs/post")

    def test_signed_assertion_in_unsigned_response_parses_bound_node(self):
        signed_xml = self.signed_assertion_response
        self.ar.timeslack = 10000
        self.ar.allow_unsolicited = True
        self.ar.asynchop = False
        self.ar.loads(signed_xml, decode=False)
        self.ar.parse_assertion()

        # The business assertion must be the exact object whose signature was
        # verified, not a second lookup by name/path.
        assert self.ar.response.signature is None
        assert self.ar.assertion.signature is not None
        assert node_signature_verified(self.ar.assertion) is True
