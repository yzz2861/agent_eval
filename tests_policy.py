"""Cross-backend tests for the shared XMLSecurityPolicy.

The same fixture documents are run through every installed backend so that
the acceptance/rejection matrix can be compared directly.  A backend that
cannot enforce a denied policy item must fail with NotSupportedError rather
than silently accept the document.
"""
from __future__ import absolute_import

import io
import os
import unittest
import warnings

import defusedxml
from defusedxml import policy as policy_mod
from defusedxml.common import (
    BackendUnavailable,
    DefusedXmlException,
    DTDForbidden,
    EntitiesForbidden,
    ExternalDTDForbidden,
    ExternalReferenceForbidden,
    NotSupportedError,
    ParameterEntityForbidden,
    UnparsedEntityForbidden,
    XMLPosition,
)
from defusedxml.policy import (
    ALL_BACKENDS,
    BACKEND_ETREE,
    BACKEND_LXML,
    BACKEND_PULLDOM,
    BACKEND_XMLRPC,
    CAPABILITIES,
    DEFAULT_POLICY,
    PERMISSIVE_POLICY,
    POLICY_DTD,
    POLICY_EXTERNAL_DTD,
    POLICY_EXTERNAL_REFERENCES,
    POLICY_INTERNAL_ENTITIES,
    POLICY_PARAMETER_ENTITIES,
    POLICY_UNPARSED_ENTITIES,
    STRICT_POLICY,
    XMLSecurityPolicy,
    available_backends,
)

warnings.simplefilter("ignore", category=DeprecationWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "xmltestdata")

# make sure probes cannot reach the network
os.environ.setdefault("http_proxy", "http://127.0.9.1:9")
os.environ.setdefault("https_proxy", "http://127.0.9.1:9")
os.environ.setdefault("ftp_proxy", "http://127.0.9.1:9")


def fixture(name):
    with open(os.path.join(DATA, name), "rb") as fp:
        return fp.read()


# (label, fixture file, policy_item that the default/strict policy rejects)
FIXTURES = [
    ("simple", "simple.xml", None),
    ("internal_dtd", "xmlbomb.xml", POLICY_INTERNAL_ENTITIES),
    ("dtd_element", "dtd_element.xml", None),
    ("parameter_entity", "parameter_entity.xml", POLICY_PARAMETER_ENTITIES),
    (
        "parameter_entity_internal",
        "parameter_entity_internal.xml",
        POLICY_PARAMETER_ENTITIES,
    ),
    ("external_system", "external.xml", POLICY_EXTERNAL_REFERENCES),
    ("external_file", "external_file.xml", POLICY_EXTERNAL_REFERENCES),
    ("unparsed_entity", "unparsed_entity.xml", POLICY_UNPARSED_ENTITIES),
    ("external_dtd", "external_dtd.xml", POLICY_EXTERNAL_DTD),
    ("external_dtd_public", "external_dtd_public.xml", POLICY_EXTERNAL_DTD),
    ("bad_namespace", "bad_namespace.xml", None),
]

EXPAT_BACKENDS = tuple(b for b in ALL_BACKENDS if b != BACKEND_LXML)


def parse_unified(data, backend, pol):
    return defusedxml.fromstring(data, backend=backend, policy=pol)


class PolicyObjectTests(unittest.TestCase):
    def test_defaults_match_legacy_semantics(self):
        legacy = XMLSecurityPolicy.from_legacy()
        self.assertFalse(legacy.allow_internal_entities)
        self.assertFalse(legacy.allow_parameter_entities)
        self.assertFalse(legacy.allow_external_references)
        self.assertFalse(legacy.allow_unparsed_entities)
        self.assertTrue(legacy.allow_dtd)
        # the legacy API had no external-DTD switch
        self.assertTrue(legacy.allow_external_dtd)

    def test_from_legacy_flags(self):
        pol = XMLSecurityPolicy.from_legacy(
            forbid_dtd=True, forbid_entities=False, forbid_external=False
        )
        self.assertFalse(pol.allow_dtd)
        self.assertTrue(pol.allow_internal_entities)
        self.assertTrue(pol.allow_external_references)

    def test_policy_is_immutable_and_typed(self):
        with self.assertRaises(Exception):
            DEFAULT_POLICY.allow_dtd = False
        with self.assertRaises(TypeError):
            XMLSecurityPolicy(allow_dtd="yes")
        derived = DEFAULT_POLICY.replace(allow_dtd=False)
        self.assertTrue(DEFAULT_POLICY.allow_dtd)
        self.assertFalse(derived.allow_dtd)

    def test_strict_and_presets(self):
        self.assertTrue(STRICT_POLICY.is_strict())
        self.assertFalse(DEFAULT_POLICY.is_strict())
        self.assertEqual(len(STRICT_POLICY.denied_items()), 6)
        self.assertEqual(len(PERMISSIVE_POLICY.denied_items()), 0)

    def test_capability_matrix_covers_all_items(self):
        for backend in ALL_BACKENDS:
            cap = CAPABILITIES[backend]
            for item in policy_mod.POLICY_ITEMS:
                self.assertIsInstance(getattr(cap, item), bool)

    def test_lxml_cannot_enforce_parameter_entities(self):
        cap = CAPABILITIES[BACKEND_LXML]
        self.assertFalse(cap.allow_parameter_entities)
        # every pyexpat backend can enforce the full matrix
        for backend in EXPAT_BACKENDS:
            self.assertEqual(
                CAPABILITIES[backend].unsupported_denials(STRICT_POLICY), ()
            )


class CapabilityEnforcementTests(unittest.TestCase):
    def test_strict_lxml_fails_closed_when_installed(self):
        if BACKEND_LXML not in available_backends():
            self.skipTest("lxml not installed")
        with self.assertRaises(NotSupportedError):
            policy_mod.check_capability(BACKEND_LXML, STRICT_POLICY)

    def test_missing_backend_raises_backend_unavailable(self):
        if BACKEND_LXML in available_backends():
            self.skipTest("lxml is installed")
        with self.assertRaises(BackendUnavailable) as ctx:
            defusedxml.fromstring(b"<r/>", backend=BACKEND_LXML)
        self.assertEqual(ctx.exception.backend, BACKEND_LXML)

    def test_lxml_module_imports_without_dependency(self):
        # importing the module must never fail even when lxml is missing
        from defusedxml import lxml as defused_lxml

        self.assertIsInstance(defused_lxml.is_available(), bool)
        if BACKEND_LXML not in available_backends():
            self.assertFalse(defused_lxml.is_available())
            with self.assertRaises(BackendUnavailable):
                defused_lxml.fromstring(b"<r/>", policy=PERMISSIVE_POLICY)

    def test_simulated_missing_lxml_dependency(self):
        # Force the optional-dependency path regardless of what is installed.
        from defusedxml import _lxml_policy

        original_etree = _lxml_policy._etree
        original_error = _lxml_policy._import_error
        _lxml_policy._etree = None
        _lxml_policy._import_error = ImportError("simulated missing lxml")
        try:
            self.assertFalse(_lxml_policy.is_available())
            with self.assertRaises(BackendUnavailable) as ctx:
                _lxml_policy._load_lxml()
            self.assertEqual(ctx.exception.backend, BACKEND_LXML)
            self.assertIsInstance(ctx.exception.cause, ImportError)
            with self.assertRaises(BackendUnavailable):
                defusedxml.fromstring(
                    b"<r/>", backend=BACKEND_LXML, policy=PERMISSIVE_POLICY
                )
        finally:
            _lxml_policy._etree = original_etree
            _lxml_policy._import_error = original_error


class ExpatMatrixTests(unittest.TestCase):
    """The five pyexpat backends must agree on every fixture."""

    available = tuple(b for b in EXPAT_BACKENDS if b in available_backends())

    def test_simple_documents_accepted_by_all(self):
        for backend in self.available:
            for name in ("simple.xml", "simple-ns.xml"):
                parse_unified(fixture(name), backend, DEFAULT_POLICY)
                parse_unified(fixture(name), backend, STRICT_POLICY)

    def test_file_and_fileobject_entry_points(self):
        path = os.path.join(DATA, "simple.xml")
        for backend in self.available:
            defusedxml.parse(path, backend=backend, policy=DEFAULT_POLICY)
            with open(path, "rb") as fp:
                defusedxml.parse(fp, backend=backend, policy=DEFAULT_POLICY)

    def test_file_entry_rejects_under_strict_policy(self):
        path = os.path.join(DATA, "xmlbomb.xml")
        for backend in self.available:
            with self.assertRaises(DefusedXmlException):
                defusedxml.parse(path, backend=backend, policy=STRICT_POLICY)

    def test_default_policy_denies_entity_features(self):
        expected = {
            "internal_dtd": EntitiesForbidden,
            "parameter_entity": ParameterEntityForbidden,
            "parameter_entity_internal": ParameterEntityForbidden,
            "external_system": EntitiesForbidden,
            "external_file": EntitiesForbidden,
            "unparsed_entity": UnparsedEntityForbidden,
            "external_dtd": ExternalDTDForbidden,
            "external_dtd_public": ExternalDTDForbidden,
        }
        for label, fname, item in FIXTURES:
            if label not in expected:
                continue
            for backend in self.available:
                with self.assertRaises(DefusedXmlException) as ctx:
                    parse_unified(fixture(fname), backend, DEFAULT_POLICY)
                self.assertIsInstance(ctx.exception, expected[label])

    def test_strict_policy_denies_any_doctype(self):
        dtd_fixtures = [
            "xmlbomb.xml",
            "dtd_element.xml",
            "parameter_entity.xml",
            "external.xml",
            "external_file.xml",
            "unparsed_entity.xml",
            "external_dtd.xml",
            "external_dtd_public.xml",
        ]
        for fname in dtd_fixtures:
            for backend in self.available:
                with self.assertRaises((DTDForbidden, ExternalDTDForbidden)):
                    parse_unified(fixture(fname), backend, STRICT_POLICY)

    def test_permissive_policy_accepts_well_formed_dtds(self):
        accepted = [
            "xmlbomb2.xml",
            "dtd_element.xml",
            "external_dtd.xml",
            "parameter_entity_internal.xml",
            "unparsed_entity.xml",
        ]
        for fname in accepted:
            for backend in self.available:
                parse_unified(fixture(fname), backend, PERMISSIVE_POLICY)


class DiagnosticsTests(unittest.TestCase):
    def test_exception_carries_backend_item_and_offset(self):
        data = fixture("xmlbomb.xml")
        for backend in EXPAT_BACKENDS:
            if backend not in available_backends():
                continue
            with self.assertRaises(DefusedXmlException) as ctx:
                parse_unified(data, backend, DEFAULT_POLICY)
            exc = ctx.exception
            self.assertEqual(exc.backend, backend)
            self.assertEqual(exc.policy_item, POLICY_INTERNAL_ENTITIES)
            self.assertIsInstance(exc.position, XMLPosition)
            self.assertIsNotNone(exc.position.byte_index)
            self.assertIsNotNone(exc.position.line)

    def test_error_text_never_contains_document_or_entity_value(self):
        secret = b'<!DOCTYPE r [\n<!ENTITY a "TOPSECRET987654">]><r>&a;</r>'
        for backend in EXPAT_BACKENDS:
            if backend not in available_backends():
                continue
            with self.assertRaises(DefusedXmlException) as ctx:
                parse_unified(secret, backend, DEFAULT_POLICY)
            rendered = str(ctx.exception) + repr(ctx.exception)
            self.assertNotIn("TOPSECRET987654", rendered)

    def test_external_dtd_reports_external_dtd_item(self):
        data = fixture("external_dtd.xml")
        for backend in EXPAT_BACKENDS:
            if backend not in available_backends():
                continue
            with self.assertRaises(DefusedXmlException) as ctx:
                parse_unified(data, backend, DEFAULT_POLICY)
            self.assertEqual(ctx.exception.policy_item, POLICY_EXTERNAL_DTD)


class BadNamespaceTests(unittest.TestCase):
    def test_bad_namespace_is_rejected_or_handled_consistently(self):
        data = fixture("bad_namespace.xml")
        outcomes = {}
        for backend in EXPAT_BACKENDS:
            if backend not in available_backends():
                continue
            try:
                parse_unified(data, backend, DEFAULT_POLICY)
                outcomes[backend] = "ok"
            except DefusedXmlException:
                outcomes[backend] = "policy"
            except Exception:
                # parser-level syntax/namespace error; the document is never
                # silently accepted as well-formed XML
                outcomes[backend] = "syntax"
        # sax/xmlrpc tolerate the prefix at the raw expat level; the tree
        # builders reject it.  No backend may return a parsed element tree
        # containing the undeclared prefix through a policy exception path.
        self.assertIn(outcomes[BACKEND_ETREE], ("syntax", "policy"))
        self.assertIn(outcomes[BACKEND_PULLDOM], ("syntax", "policy", "ok"))


class LxmlMatrixTests(unittest.TestCase):
    def setUp(self):
        if BACKEND_LXML not in available_backends():
            self.skipTest("lxml not installed")

    def _relaxed(self):
        # lxml cannot separate parameter entities; use the documented
        # lxml-scoped default for the runnable matrix.
        return policy_mod.BACKEND_DEFAULT_POLICIES[BACKEND_LXML]

    def test_strict_and_default_fail_closed(self):
        for pol in (DEFAULT_POLICY, STRICT_POLICY):
            with self.assertRaises(NotSupportedError):
                defusedxml.fromstring(
                    b"<r/>", backend=BACKEND_LXML, policy=pol
                )

    def test_runnable_policy_matches_expat_decisions(self):
        pol = self._relaxed()
        accepted = ("simple.xml", "dtd_element.xml")
        denied = {
            "xmlbomb.xml": EntitiesForbidden,
            "external.xml": EntitiesForbidden,
            "external_dtd.xml": ExternalDTDForbidden,
            "external_dtd_public.xml": ExternalDTDForbidden,
            "unparsed_entity.xml": UnparsedEntityForbidden,
        }
        for fname in accepted:
            defusedxml.fromstring(
                fixture(fname), backend=BACKEND_LXML, policy=pol
            )
        for fname, exc_type in denied.items():
            with self.assertRaises(exc_type):
                defusedxml.fromstring(
                    fixture(fname), backend=BACKEND_LXML, policy=pol
                )

    def test_permissive_lxml_accepts_simple_dtd(self):
        defusedxml.fromstring(
            fixture("dtd_element.xml"),
            backend=BACKEND_LXML,
            policy=PERMISSIVE_POLICY,
        )


class LegacyCompatibilityTests(unittest.TestCase):
    """The historical forbid_* API must keep working unchanged."""

    def test_legacy_booleans_still_supported(self):
        from defusedxml import ElementTree as det
        from defusedxml.common import DTDForbidden as LegacyDTD

        det.fromstring(b"<r/>")
        with self.assertRaises(LegacyDTD):
            det.fromstring(b"<!DOCTYPE r><r/>", forbid_dtd=True)
        with self.assertRaises(EntitiesForbidden):
            det.fromstring(fixture("xmlbomb.xml"))

    def test_legacy_path_allows_when_flags_open(self):
        from defusedxml import ElementTree as det

        det.fromstring(
            fixture("xmlbomb2.xml"),
            forbid_entities=False,
            forbid_external=False,
        )

    def test_policy_and_legacy_kwargs_are_mutually_exclusive(self):
        with self.assertRaises(TypeError):
            defusedxml.fromstring(
                b"<r/>", policy=DEFAULT_POLICY, forbid_dtd=True
            )

    def test_legacy_default_still_allows_external_dtd_identifier(self):
        # historical behavior: doctype SYSTEM id alone was not blocked
        from defusedxml import ElementTree as det

        det.fromstring(fixture("external_dtd.xml"))


if __name__ == "__main__":
    unittest.main()
