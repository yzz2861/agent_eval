from __future__ import print_function

import io
import os
import sys
import unittest
import warnings
from unittest import mock

from xml.etree import ElementTree as orig_elementtree
from xml.etree.ElementTree import Element as ElementBeforeImport
from xml.sax.saxutils import XMLGenerator
from xml.sax import SAXParseException
from pyexpat import ExpatError

from defusedxml import ElementTree, minidom, pulldom, sax, xmlrpc, expatreader
from defusedxml import defuse_stdlib
from defusedxml import (
    KEEP,
    SAFE,
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    NotSupportedError,
)
from defusedxml.common import (
    AuditRecord,
    clear_audit_records,
    get_audit_record,
    security_mode,
    set_security_mode,
    source_category,
    summarize_name,
)

from xml.etree.ElementTree import Element as ElementAfterImport

if sys.version_info < (3, 7):
    warnings.filterwarnings("once", category=DeprecationWarning)


with warnings.catch_warnings(record=True) as cetree_warnings:
    from defusedxml import cElementTree


try:
    import gzip
except ImportError:
    gzip = None


try:
    with warnings.catch_warnings(record=True) as lxml_warnings:
        from defusedxml import lxml
    from lxml import etree as lxml_etree

    LXML3 = lxml.LXML3
except ImportError:
    lxml = None
    lxml_etree = None
    LXML3 = False
    lxml_warnings = None


warnings.filterwarnings("always", category=DeprecationWarning, module=r"defusedxml\..*")


HERE = os.path.dirname(os.path.abspath(__file__))

# prevent web access
# based on Debian's rules, Port 9 is discard
os.environ["http_proxy"] = "http://127.0.9.1:9"
os.environ["https_proxy"] = os.environ["http_proxy"]
os.environ["ftp_proxy"] = os.environ["http_proxy"]


class DefusedTestCase(unittest.TestCase):
    content_binary = False

    xml_dtd = os.path.join(HERE, "xmltestdata", "dtd.xml")
    xml_external = os.path.join(HERE, "xmltestdata", "external.xml")
    xml_external_file = os.path.join(HERE, "xmltestdata", "external_file.xml")
    xml_quadratic = os.path.join(HERE, "xmltestdata", "quadratic.xml")
    xml_simple = os.path.join(HERE, "xmltestdata", "simple.xml")
    xml_simple_ns = os.path.join(HERE, "xmltestdata", "simple-ns.xml")
    xml_bomb = os.path.join(HERE, "xmltestdata", "xmlbomb.xml")
    xml_bomb2 = os.path.join(HERE, "xmltestdata", "xmlbomb2.xml")
    xml_cyclic = os.path.join(HERE, "xmltestdata", "cyclic.xml")
    xml_dtd_element = os.path.join(HERE, "xmltestdata", "dtd_element.xml")
    xml_schema_include = os.path.join(HERE, "xmltestdata", "schema-include.xsd")

    def get_content(self, xmlfile):
        mode = "rb" if self.content_binary else "r"
        with io.open(xmlfile, mode) as f:
            data = f.read()
        return data


class BaseTests(DefusedTestCase):
    module = None
    dtd_external_ref = False

    external_ref_exception = ExternalReferenceForbidden
    cyclic_error = None
    iterparse = None

    def setUp(self):
        if type(self) is BaseTests:
            self.skipTest("abstract base test class")

    def test_simple_parse(self):
        self.parse(self.xml_simple)
        self.parseString(self.get_content(self.xml_simple))
        if self.iterparse:
            self.iterparse(self.xml_simple)

    def test_simple_parse_ns(self):
        self.parse(self.xml_simple_ns)
        self.parseString(self.get_content(self.xml_simple_ns))
        if self.iterparse:
            self.iterparse(self.xml_simple_ns)

    def test_entities_forbidden(self):
        self.assertRaises(EntitiesForbidden, self.parse, self.xml_bomb)
        self.assertRaises(EntitiesForbidden, self.parse, self.xml_quadratic)
        self.assertRaises(EntitiesForbidden, self.parse, self.xml_external)

        self.assertRaises(EntitiesForbidden, self.parseString, self.get_content(self.xml_bomb))
        self.assertRaises(
            EntitiesForbidden, self.parseString, self.get_content(self.xml_quadratic)
        )
        self.assertRaises(
            EntitiesForbidden, self.parseString, self.get_content(self.xml_external)
        )

        if self.iterparse:
            self.assertRaises(EntitiesForbidden, self.iterparse, self.xml_bomb)
            self.assertRaises(EntitiesForbidden, self.iterparse, self.xml_quadratic)
            self.assertRaises(EntitiesForbidden, self.iterparse, self.xml_external)

    def test_entity_cycle(self):
        self.assertRaises(self.cyclic_error, self.parse, self.xml_cyclic, forbid_entities=False)

    def test_dtd_forbidden(self):
        self.assertRaises(DTDForbidden, self.parse, self.xml_bomb, forbid_dtd=True)
        self.assertRaises(DTDForbidden, self.parse, self.xml_quadratic, forbid_dtd=True)
        self.assertRaises(DTDForbidden, self.parse, self.xml_external, forbid_dtd=True)
        self.assertRaises(DTDForbidden, self.parse, self.xml_dtd, forbid_dtd=True)

        self.assertRaises(
            DTDForbidden, self.parseString, self.get_content(self.xml_bomb), forbid_dtd=True
        )
        self.assertRaises(
            DTDForbidden, self.parseString, self.get_content(self.xml_quadratic), forbid_dtd=True
        )
        self.assertRaises(
            DTDForbidden, self.parseString, self.get_content(self.xml_external), forbid_dtd=True
        )
        self.assertRaises(
            DTDForbidden, self.parseString, self.get_content(self.xml_dtd), forbid_dtd=True
        )

        if self.iterparse:
            self.assertRaises(DTDForbidden, self.iterparse, self.xml_bomb, forbid_dtd=True)
            self.assertRaises(DTDForbidden, self.iterparse, self.xml_quadratic, forbid_dtd=True)
            self.assertRaises(DTDForbidden, self.iterparse, self.xml_external, forbid_dtd=True)
            self.assertRaises(DTDForbidden, self.iterparse, self.xml_dtd, forbid_dtd=True)

    def test_dtd_with_external_ref(self):
        if self.dtd_external_ref:
            self.assertRaises(self.external_ref_exception, self.parse, self.xml_dtd)
        else:
            self.parse(self.xml_dtd)

    def test_external_ref(self):
        self.assertRaises(
            self.external_ref_exception, self.parse, self.xml_external, forbid_entities=False
        )

    def test_external_file_ref(self):
        content = self.get_content(self.xml_external_file)
        if isinstance(content, bytes):
            here = HERE.encode(sys.getfilesystemencoding())
            content = content.replace(b"/PATH/TO", here)
        else:
            content = content.replace("/PATH/TO", HERE)
        self.assertRaises(
            self.external_ref_exception, self.parseString, content, forbid_entities=False
        )

    def test_allow_expansion(self):
        self.parse(self.xml_bomb2, forbid_entities=False)
        self.parseString(self.get_content(self.xml_bomb2), forbid_entities=False)

    def test_dtd_element(self):
        self.parse(self.xml_dtd_element)


class TestDefusedElementTree(BaseTests):
    module = ElementTree

    # etree doesn't do external ref lookup
    # external_ref_exception = ElementTree.ParseError

    cyclic_error = ElementTree.ParseError

    def parse(self, xmlfile, **kwargs):
        tree = self.module.parse(xmlfile, **kwargs)
        return self.module.tostring(tree.getroot())

    def parseString(self, xmlstring, **kwargs):
        tree = self.module.fromstring(xmlstring, **kwargs)
        return self.module.tostring(tree)

    def parseStringList(self, sequence, **kwargs):
        tree = self.module.fromstringlist(sequence, **kwargs)
        return self.module.tostring(tree)

    def iterparse(self, source, **kwargs):
        return list(self.module.iterparse(source, **kwargs))

    def test_html_arg(self):
        with warnings.catch_warnings(record=True) as w:
            self.module.XMLParse(html=0)
        self.assertEqual(len(w), 1)
        self.assertIs(w[0].category, DeprecationWarning)
        with self.assertRaises(TypeError):
            self.module.XMLParse(html=1)

    def test_aliases(self):
        parser = self.module.DefusedXMLParser
        assert self.module.XMLTreeBuilder is parser
        assert self.module.XMLParser is parser
        assert self.module.XMLParse is parser

    def test_fromstringlist(self):
        seq = ["<root>", '<tag id="one" />', '<tag id="two" />', "</root>"]
        tree = self.module.fromstringlist(seq)
        result = self.module.tostring(tree)
        self.assertEqual(result, "".join(seq).encode("utf-8"))

    def test_import_order(self):
        from xml.etree import ElementTree as second_elementtree

        self.assertIs(orig_elementtree, second_elementtree)

    def test_orig_parseerror(self):
        # https://github.com/tiran/defusedxml/issues/63
        self.assertIs(self.module.ParseError, orig_elementtree.ParseError)
        try:
            self.parseString("invalid")
        except Exception as e:
            self.assertIsInstance(e, orig_elementtree.ParseError)
            self.assertIsInstance(e, self.module.ParseError)

    def test_etree_element(self):
        tree = tree = self.module.parse(self.xml_simple)
        root = tree.getroot()
        root.append(orig_elementtree.Element("module-import"))
        root.append(ElementBeforeImport("before-import"))
        root.append(ElementAfterImport("after-import"))
        s = orig_elementtree.tostring(root)
        self.assertEqual(s.count(b"import"), 3, s)


class TestDefusedcElementTree(TestDefusedElementTree):
    module = cElementTree

    def test_celementtree_warnings(self):
        # The deprecation warning is emitted once per process at import
        # time; re-import to make the test independent of collection order.
        import importlib

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            importlib.reload(cElementTree)
        self.addCleanup(importlib.reload, cElementTree)
        self.assertTrue(caught)
        self.assertEqual(caught[0].category, DeprecationWarning)
        self.assertIn("cElementTree", str(caught[0].message))


class TestDefusedMinidom(BaseTests):
    module = minidom

    cyclic_error = ExpatError

    iterparse = None

    def parse(self, xmlfile, **kwargs):
        doc = self.module.parse(xmlfile, **kwargs)
        return doc.toxml()

    def parseString(self, xmlstring, **kwargs):
        doc = self.module.parseString(xmlstring, **kwargs)
        return doc.toxml()


class TestDefusedMinidomWithParser(TestDefusedMinidom):
    cyclic_error = SAXParseException
    dtd_external_ref = True

    def parse(self, xmlfile, **kwargs):
        doc = self.module.parse(xmlfile, parser=expatreader.create_parser(**kwargs), **kwargs)
        return doc.toxml()

    def parseString(self, xmlstring, **kwargs):
        doc = self.module.parseString(
            xmlstring, parser=expatreader.create_parser(**kwargs), **kwargs
        )
        return doc.toxml()


class TestDefusedPulldom(BaseTests):
    module = pulldom

    cyclic_error = SAXParseException

    dtd_external_ref = True

    def parse(self, xmlfile, **kwargs):
        events = self.module.parse(xmlfile, **kwargs)
        return list(events)

    def parseString(self, xmlstring, **kwargs):
        events = self.module.parseString(xmlstring, **kwargs)
        return list(events)


class TestDefusedSax(BaseTests):
    module = sax

    cyclic_error = SAXParseException

    content_binary = True
    dtd_external_ref = True

    def parse(self, xmlfile, **kwargs):
        with io.StringIO() as result:
            handler = XMLGenerator(result)
            self.module.parse(xmlfile, handler, **kwargs)
            return result.getvalue()

    def parseString(self, xmlstring, **kwargs):
        with io.StringIO() as result:
            handler = XMLGenerator(result)
            self.module.parseString(xmlstring, handler, **kwargs)
            return result.getvalue()

    def test_exceptions(self):
        with self.assertRaises(EntitiesForbidden) as ctx:
            self.parse(self.xml_bomb)
        msg = "EntitiesForbidden(name='a', system_id=None, public_id=None)"
        self.assertEqual(str(ctx.exception), msg)
        self.assertEqual(repr(ctx.exception), msg)

        with self.assertRaises(ExternalReferenceForbidden) as ctx:
            self.parse(self.xml_external, forbid_entities=False)
        msg = (
            "ExternalReferenceForbidden"
            "(system_id='http://www.w3schools.com/xml/note.xml', public_id=None)"
        )
        self.assertEqual(str(ctx.exception), msg)
        self.assertEqual(repr(ctx.exception), msg)

        with self.assertRaises(DTDForbidden) as ctx:
            self.parse(self.xml_bomb, forbid_dtd=True)
        msg = "DTDForbidden(name='xmlbomb', system_id=None, public_id=None)"
        self.assertEqual(str(ctx.exception), msg)
        self.assertEqual(repr(ctx.exception), msg)


@unittest.skipUnless(lxml is not None, "test requires lxml")
class TestDefusedLxml(BaseTests):
    module = lxml

    cyclic_error = getattr(lxml_etree, "XMLSyntaxError", None)

    content_binary = True

    def parse(self, xmlfile, **kwargs):
        try:
            tree = self.module.parse(xmlfile, **kwargs)
        except lxml_etree.XMLSyntaxError:
            self.skipTest("lxml detects entity reference loop")
        return self.module.tostring(tree)

    def parseString(self, xmlstring, **kwargs):
        try:
            tree = self.module.fromstring(xmlstring, **kwargs)
        except lxml_etree.XMLSyntaxError:
            self.skipTest("lxml detects entity reference loop")
        return self.module.tostring(tree)

    if not LXML3:

        def test_entities_forbidden(self):
            self.assertRaises(NotSupportedError, self.parse, self.xml_bomb)

        def test_dtd_with_external_ref(self):
            self.assertRaises(NotSupportedError, self.parse, self.xml_dtd)

    def test_external_ref(self):
        pass

    def test_external_file_ref(self):
        pass

    def test_restricted_element1(self):
        try:
            tree = self.module.parse(self.xml_bomb, forbid_dtd=False, forbid_entities=False)
        except lxml_etree.XMLSyntaxError:
            self.skipTest("lxml detects entityt reference loop")
        root = tree.getroot()
        self.assertEqual(root.text, None)

        self.assertEqual(list(root), [])
        self.assertEqual(root.getchildren(), [])
        self.assertEqual(list(root.iter()), [root])
        self.assertEqual(list(root.iterchildren()), [])
        self.assertEqual(list(root.iterdescendants()), [])
        self.assertEqual(list(root.itersiblings()), [])
        self.assertEqual(list(root.getiterator()), [root])
        self.assertEqual(root.getnext(), None)

    def test_restricted_element2(self):
        try:
            tree = self.module.parse(self.xml_bomb2, forbid_dtd=False, forbid_entities=False)
        except lxml_etree.XMLSyntaxError:
            self.skipTest("lxml detects entityt reference loop")
        root = tree.getroot()
        bomb, tag = root
        self.assertEqual(root.text, "text")

        self.assertEqual(list(root), [bomb, tag])
        self.assertEqual(root.getchildren(), [bomb, tag])
        self.assertEqual(list(root.iter()), [root, bomb, tag])
        self.assertEqual(list(root.iterchildren()), [bomb, tag])
        self.assertEqual(list(root.iterdescendants()), [bomb, tag])
        self.assertEqual(list(root.itersiblings()), [])
        self.assertEqual(list(root.getiterator()), [root, bomb, tag])
        self.assertEqual(root.getnext(), None)
        self.assertEqual(root.getprevious(), None)

        self.assertEqual(list(bomb.itersiblings()), [tag])
        self.assertEqual(bomb.getnext(), tag)
        self.assertEqual(bomb.getprevious(), None)
        self.assertEqual(tag.getnext(), None)
        self.assertEqual(tag.getprevious(), bomb)

    def test_xpath_injection(self):
        # show XPath injection vulnerability
        xml = """<root><tag id="one" /><tag id="two"/></root>"""
        expr = "one' or @id='two"
        root = lxml.fromstring(xml)

        # insecure way
        xp = "tag[@id='%s']" % expr
        elements = root.xpath(xp)
        self.assertEqual(len(elements), 2)
        self.assertEqual(elements, list(root))

        # proper and safe way
        xp = "tag[@id=$idname]"
        elements = root.xpath(xp, idname=expr)
        self.assertEqual(len(elements), 0)
        self.assertEqual(elements, [])

        elements = root.xpath(xp, idname="one")
        self.assertEqual(len(elements), 1)
        self.assertEqual(elements, list(root)[:1])

    def test_lxml_warnings(self):
        self.assertTrue(lxml_warnings)
        self.assertEqual(lxml_warnings[0].category, DeprecationWarning)
        self.assertIn("tests.py", lxml_warnings[0].filename)

    def test_lxml_schema_include(self):
        # attempt to trigger network ops and error
        with mock.patch.dict(os.environ):
            os.environ.pop("no_proxy", None)
            os.environ["http_proxy"] = "http://proxy.invalid:3128"
            os.environ["https_proxy"] = "http://proxy.invalid:3128"

            doc = self.module.fromstring("<root>true</root>")

            schema = lxml_etree.XMLSchema(file=self.xml_schema_include)
            schema.validate(doc)

            schema_etree = self.module.parse(self.xml_schema_include)
            lxml_etree.XMLSchema(etree=schema_etree)
            schema.validate(doc)


class XmlRpcTarget(object):
    def __init__(self):
        self._data = []

    def __str__(self):
        return "".join(self._data)

    def xml(self, encoding, standalone):
        pass

    def start(self, tag, attrs):
        self._data.append("<%s>" % tag)

    def data(self, text):
        self._data.append(text)

    def end(self, tag):
        self._data.append("</%s>" % tag)


class TestXmlRpc(DefusedTestCase):
    module = xmlrpc

    def parse(self, xmlfile, **kwargs):
        target = XmlRpcTarget()
        parser = self.module.DefusedExpatParser(target, **kwargs)
        data = self.get_content(xmlfile)
        parser.feed(data)
        parser.close()
        return target

    def parse_unpatched(self, xmlfile):
        target = XmlRpcTarget()
        parser = self.module.ExpatParser(target)
        data = self.get_content(xmlfile)
        parser.feed(data)
        parser.close()
        return target

    def test_xmlrpc(self):
        self.assertRaises(EntitiesForbidden, self.parse, self.xml_bomb)
        self.assertRaises(EntitiesForbidden, self.parse, self.xml_quadratic)
        self.parse(self.xml_dtd)
        self.assertRaises(DTDForbidden, self.parse, self.xml_dtd, forbid_dtd=True)

    # def test_xmlrpc_unpatched(self):
    #    for fname in (self.xml_external,  self.xml_dtd):
    #        print(self.parse_unpatched(fname))

    def test_monkeypatch(self):
        try:
            xmlrpc.monkey_patch()
        finally:
            xmlrpc.unmonkey_patch()

    def test_monkeypatch_safe_mode_no_leak(self):
        import xmlrpc.client as client

        secret_http = "http://intranet.corp.local/secret.dtd"
        fragments = ("intranet.corp.local", secret_http, "/srv/")

        request = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE methodCall [<!ENTITY x SYSTEM "%s">]>'
            "<methodCall><methodName>ping</methodName>"
            "<params><param><value><string>&x;</string></value></param>"
            "</params></methodCall>" % secret_http
        ).encode("utf-8")
        try:
            xmlrpc.monkey_patch()
            with security_mode(SAFE):
                with self.assertRaises(EntitiesForbidden) as ctx:
                    client.loads(request)
            rendered = str(ctx.exception) + repr(ctx.exception)
            for fragment in fragments:
                self.assertNotIn(fragment, rendered)
            self.assertTrue(ctx.exception.audit_id)
            record = get_audit_record(ctx.exception.audit_id)
            serialized = str(record.to_dict())
            for fragment in fragments:
                self.assertNotIn(fragment, serialized)
        finally:
            xmlrpc.unmonkey_patch()


@unittest.skipUnless(gzip is not None, "test requires gzip")
class TestDefusedGzip(DefusedTestCase):
    def get_gzipped(self, length):
        f = io.BytesIO()
        self.addCleanup(f.close)
        gzf = gzip.GzipFile(mode="wb", fileobj=f)
        gzf.write(b"d" * length)
        gzf.close()
        f.seek(0)
        return f

    def decode_response(self, response, limit=None, readlength=1024):
        dec = xmlrpc.DefusedGzipDecodedResponse(response, limit)
        acc = []
        while True:
            data = dec.read(readlength)
            if not data:
                break
            acc.append(data)
        return b"".join(acc)

    def test_defused_gzip_decode(self):
        data = self.get_gzipped(4096).getvalue()
        result = xmlrpc.defused_gzip_decode(data)
        self.assertEqual(result, b"d" * 4096)
        result = xmlrpc.defused_gzip_decode(data, -1)
        self.assertEqual(result, b"d" * 4096)
        result = xmlrpc.defused_gzip_decode(data, 4096)
        self.assertEqual(result, b"d" * 4096)
        with self.assertRaises(ValueError):
            result = xmlrpc.defused_gzip_decode(data, 4095)
        with self.assertRaises(ValueError):
            result = xmlrpc.defused_gzip_decode(data, 0)

    def test_defused_gzip_response(self):
        clen = len(self.get_gzipped(4096).getvalue())

        response = self.get_gzipped(4096)
        data = self.decode_response(response)
        self.assertEqual(data, b"d" * 4096)

        with self.assertRaises(ValueError):
            response = self.get_gzipped(4096)
            xmlrpc.DefusedGzipDecodedResponse(response, clen - 1)

        with self.assertRaises(ValueError):
            response = self.get_gzipped(4096)
            self.decode_response(response, 4095)

        with self.assertRaises(ValueError):
            response = self.get_gzipped(4096)
            self.decode_response(response, 4095, 8192)


class SafeModeTestCase(unittest.TestCase):
    """Coverage for the explicit safe security mode.

    Every assertion scans both the client facing representation and the
    server side audit view for environment information.
    """

    secret_file = "file:///srv/app/secrets/db.env"
    secret_http = "http://intranet.corp.local/secret.dtd"
    secret_value = "TOPSECRET_ENTITY_VALUE_789"
    secret_fragments = (
        "file:///srv",
        "/srv/app",
        "intranet.corp.local",
        secret_file,
        secret_http,
        secret_value,
        "TOPSECRET",
    )

    entity_xml = (
        '<!DOCTYPE bomb [<!ENTITY a "%s">]><bomb>&a;</bomb>' % secret_value
    ).encode("utf-8")
    file_xml = (
        '<!DOCTYPE external [<!ENTITY ee SYSTEM "%s">]><root>&ee;</root>'
        % secret_file
    ).encode("utf-8")
    http_xml = (
        '<!DOCTYPE external [<!ENTITY ee SYSTEM "%s">]><root>&ee;</root>'
        % secret_http
    ).encode("utf-8")
    dtd_xml = (
        '<!DOCTYPE dtd PUBLIC "-//W3C//DTD DTD//EN" "%s"><root/>' % secret_http
    ).encode("utf-8")

    def setUp(self):
        clear_audit_records()
        self.addCleanup(set_security_mode, KEEP)

    def assertNoSecret(self, text):
        rendered = str(text)
        for fragment in self.secret_fragments:
            self.assertNotIn(fragment, rendered)

    def assertSafeException(self, exc, expected_cls, expected_category):
        self.assertIsInstance(exc, expected_cls)
        self.assertIsInstance(exc, ValueError)
        self.assertEqual(exc.security_mode, SAFE)
        self.assertEqual(exc.exception_category, expected_category)
        self.assertIsInstance(exc.line, int)
        self.assertGreaterEqual(exc.line, 1)
        self.assertIsInstance(exc.column, int)
        self.assertGreaterEqual(exc.column, 0)
        self.assertTrue(exc.audit_id)
        # str / repr are identical and free of environment data
        self.assertEqual(str(exc), repr(exc))
        self.assertNoSecret(str(exc))
        # no attribute on the exception object carries a secret
        for value in vars(exc).values():
            if isinstance(value, str):
                self.assertNoSecret(value)
        self.assertIsNone(exc.sysid)
        if isinstance(exc, EntitiesForbidden):
            self.assertIsNone(exc.value)
        # client mapping is redacted as well
        client = exc.client_dict()
        self.assertEqual(client["category"], expected_category)
        self.assertNoSecret(str(client))
        # audit record exposes only a redacted view
        record = get_audit_record(exc.audit_id)
        self.assertIsInstance(record, AuditRecord)
        self.assertEqual(record.exception_category, expected_category)
        self.assertNoSecret(str(record.to_dict()))
        self.assertNoSecret(repr(record))
        return record

    def test_mode_switch_and_validation(self):
        from defusedxml import common

        self.assertEqual(common.get_security_mode(), KEEP)
        with security_mode(SAFE):
            self.assertEqual(common.get_security_mode(), SAFE)
        self.assertEqual(common.get_security_mode(), KEEP)
        with self.assertRaises(ValueError):
            set_security_mode("bogus")
        with self.assertRaises(ValueError):
            with security_mode("bogus"):
                pass

    def test_keep_mode_string_compatibility(self):
        # historical representations must remain byte for byte identical
        dtd = DTDForbidden("xmlbomb", None, None)
        self.assertEqual(
            str(dtd), "DTDForbidden(name='xmlbomb', system_id=None, public_id=None)"
        )
        entity = EntitiesForbidden("a", "value", None, None, None, None)
        self.assertEqual(
            str(entity),
            "EntitiesForbidden(name='a', system_id=None, public_id=None)",
        )
        external = ExternalReferenceForbidden(
            "context", None, "http://example.invalid/note.xml", None
        )
        self.assertEqual(
            str(external),
            "ExternalReferenceForbidden(system_id='http://example.invalid/note.xml', "
            "public_id=None)",
        )
        self.assertEqual(repr(dtd), str(dtd))
        self.assertIsNone(dtd.audit_id)
        self.assertIsNone(dtd.line)

    def test_safe_repr_etree(self):
        with security_mode(SAFE):
            with self.assertRaises(EntitiesForbidden) as ctx:
                ElementTree.fromstring(self.entity_xml)
            record = self.assertSafeException(
                ctx.exception, EntitiesForbidden, "entity_forbidden"
            )
            self.assertEqual(record.source_category, "none")
            self.assertIn("sha256=", ctx.exception.name_summary)

            with self.assertRaises(ExternalReferenceForbidden) as ctx:
                ElementTree.fromstring(
                    self.file_xml, forbid_entities=False
                )
            record = self.assertSafeException(
                ctx.exception,
                ExternalReferenceForbidden,
                "external_reference_forbidden",
            )
            self.assertEqual(record.source_category, "file")

            with self.assertRaises(ExternalReferenceForbidden) as ctx:
                ElementTree.fromstring(
                    self.http_xml, forbid_entities=False
                )
            record = self.assertSafeException(
                ctx.exception,
                ExternalReferenceForbidden,
                "external_reference_forbidden",
            )
            self.assertEqual(record.source_category, "http")

            with self.assertRaises(DTDForbidden) as ctx:
                ElementTree.fromstring(self.dtd_xml, forbid_dtd=True)
            record = self.assertSafeException(
                ctx.exception, DTDForbidden, "dtd_forbidden"
            )
            self.assertEqual(record.source_category, "http")

    def test_parser_level_mode_override(self):
        # global mode stays keep, a single parser opts into safe mode
        with self.assertRaises(EntitiesForbidden) as ctx:
            ElementTree.fromstring(
                self.entity_xml, security_mode=SAFE
            )
        exc = ctx.exception
        self.assertEqual(exc.security_mode, SAFE)
        self.assertNoSecret(str(exc))
        self.assertTrue(exc.audit_id)

    def test_cross_chunk_position(self):
        document = (
            '<?xml version="1.0"?>\n'
            "<!-- comment line -->\n"
            '<!DOCTYPE dtd SYSTEM "%s">\n'
            "<root/>\n" % self.secret_http
        ).encode("utf-8")
        with security_mode(SAFE):
            with self.assertRaises(DTDForbidden) as whole_ctx:
                ElementTree.fromstring(document, forbid_dtd=True)
            expected = (whole_ctx.exception.line, whole_ctx.exception.column)

            # split the doctype declaration across several feed() calls
            cuts = (3, 10, 25, 45, 63)
            chunks = []
            start = 0
            for cut in cuts:
                chunks.append(document[start:cut])
                start = cut
            chunks.append(document[start:])
            with self.assertRaises(DTDForbidden) as split_ctx:
                ElementTree.fromstringlist(chunks, forbid_dtd=True)
            self.assertEqual(
                (split_ctx.exception.line, split_ctx.exception.column), expected
            )
            self.assertNoSecret(str(split_ctx.exception))

    def test_safe_minidom_and_sax(self):
        with security_mode(SAFE):
            with self.assertRaises(ExternalReferenceForbidden) as ctx:
                minidom.parseString(
                    self.file_xml, forbid_entities=False
                )
            self.assertSafeException(
                ctx.exception,
                ExternalReferenceForbidden,
                "external_reference_forbidden",
            )

            with self.assertRaises(EntitiesForbidden) as ctx:
                minidom.parseString(self.entity_xml)
            self.assertSafeException(
                ctx.exception, EntitiesForbidden, "entity_forbidden"
            )

            stream = io.StringIO()
            with self.assertRaises(DTDForbidden) as ctx:
                sax.parseString(
                    self.dtd_xml,
                    XMLGenerator(stream),
                    forbid_dtd=True,
                )
            self.assertSafeException(
                ctx.exception, DTDForbidden, "dtd_forbidden"
            )

            # pulldom path
            with self.assertRaises(EntitiesForbidden) as ctx:
                list(pulldom.parseString(self.entity_xml.decode("utf-8")))
            self.assertSafeException(
                ctx.exception, EntitiesForbidden, "entity_forbidden"
            )

    def test_safe_xmlrpc(self):
        class Target(XmlRpcTarget):
            pass

        with security_mode(SAFE):
            parser = xmlrpc.DefusedExpatParser(Target())
            with self.assertRaises(EntitiesForbidden) as ctx:
                parser.feed(self.entity_xml)
                parser.close()
            self.assertSafeException(
                ctx.exception, EntitiesForbidden, "entity_forbidden"
            )

            parser = xmlrpc.DefusedExpatParser(
                Target(), forbid_entities=False
            )
            with self.assertRaises(ExternalReferenceForbidden) as ctx:
                parser.feed(self.file_xml)
                parser.close()
            record = self.assertSafeException(
                ctx.exception,
                ExternalReferenceForbidden,
                "external_reference_forbidden",
            )
            self.assertEqual(record.source_category, "file")

    def test_log_serialization(self):
        import logging

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("defusedxml.safe.test")
        logger.addHandler(handler)
        try:
            with security_mode(SAFE):
                with self.assertRaises(ExternalReferenceForbidden) as ctx:
                    ElementTree.fromstring(
                        self.file_xml, forbid_entities=False
                    )
                logger.exception("gateway error: %s", ctx.exception)
                logger.warning("audit %s", ctx.exception.client_dict())
                record = get_audit_record(ctx.exception.audit_id)
                logger.warning("audit record %s", record.to_dict())
        finally:
            logger.removeHandler(handler)
        output = stream.getvalue()
        for fragment in self.secret_fragments:
            self.assertNotIn(fragment, output)

    def test_isinstance_and_categories(self):
        with security_mode(SAFE):
            instances = (
                DTDForbidden("n", None, None),
                EntitiesForbidden("n", "v", None, None, None, None),
                ExternalReferenceForbidden("c", None, None, None),
                NotSupportedError("boom"),
            )
        categories = (
            "dtd_forbidden",
            "entity_forbidden",
            "external_reference_forbidden",
            "not_supported",
        )
        classes = (
            DTDForbidden,
            EntitiesForbidden,
            ExternalReferenceForbidden,
            NotSupportedError,
        )
        for instance, cls, category in zip(instances, classes, categories):
            self.assertIsInstance(instance, cls)
            self.assertIsInstance(instance, ValueError)
            self.assertEqual(instance.exception_category, category)
            self.assertNoSecret(str(instance))

    def test_not_supported_safe_repr(self):
        with security_mode(SAFE):
            exc = NotSupportedError("internal detail with /srv/app path")
        self.assertNoSecret(str(exc))
        self.assertIn("not_supported", str(exc))
        self.assertIn(exc.audit_id, str(exc))
        # keep mode preserves the message
        keep_exc = NotSupportedError("internal detail")
        self.assertEqual(str(keep_exc), "internal detail")

    def test_legal_xml_parse_error_unchanged(self):
        # malformed but otherwise benign documents keep raising the
        # standard parser exceptions, unaffected by the security mode
        with security_mode(SAFE):
            with self.assertRaises(ElementTree.ParseError):
                ElementTree.fromstring("<root><unclosed>")
            with self.assertRaises(SAXParseException):
                sax.parseString(
                    b"<root><unclosed>", XMLGenerator(io.StringIO())
                )

    def test_source_category_and_name_summary(self):
        self.assertEqual(source_category(None), "none")
        self.assertEqual(source_category(""), "none")
        self.assertEqual(
            source_category("file:///srv/app/secrets.db"), "file"
        )
        self.assertEqual(source_category("/srv/app/secrets.db"), "file")
        self.assertEqual(
            source_category("http://intranet.example/dtd"), "http"
        )
        self.assertEqual(
            source_category("https://intranet.example/dtd"), "http"
        )
        self.assertEqual(source_category("relative/entity.dtd"), "relative")
        self.assertEqual(source_category("ftp://host/file"), "ftp")
        self.assertEqual(source_category("data:,%3C%3Fxml"), "data")

        self.assertIsNone(summarize_name(None))
        summary = summarize_name("entity-name")
        self.assertIn("entity-name", summary)
        self.assertIn("sha256=", summary)
        long_name = "x" * 100
        long_summary = summarize_name(long_name)
        self.assertIn("len=100", long_summary)
        self.assertNotIn(long_name, long_summary)
        # control characters are neutralized to avoid log forging
        forged = summarize_name("a\nFAKE_LOG_LINE")
        self.assertNotIn("\n", forged)


@unittest.skipUnless(lxml is not None, "test requires lxml")
class SafeModeLxmlTestCase(SafeModeTestCase):
    def test_safe_lxml_constructors(self):
        dtd_xml = (
            '<!DOCTYPE dtd SYSTEM "%s"><root/>' % self.secret_http
        ).encode("utf-8")
        with security_mode(SAFE):
            with self.assertRaises(DTDForbidden) as ctx:
                lxml.fromstring(dtd_xml, forbid_dtd=True)
            self.assertNoSecret(str(ctx.exception))
            self.assertEqual(ctx.exception.security_mode, SAFE)


def test_main():
    suite = unittest.TestSuite()
    cls = [
        TestDefusedElementTree,
        TestDefusedcElementTree,
        TestDefusedMinidom,
        TestDefusedMinidomWithParser,
        TestDefusedPulldom,
        TestDefusedSax,
        TestDefusedLxml,
        TestXmlRpc,
        TestDefusedGzip,
        SafeModeTestCase,
        SafeModeLxmlTestCase,
    ]
    for c in cls:
        suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(c))
    return suite


if __name__ == "__main__":
    suite = test_main()
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    # TODO: test that it actually works
    defuse_stdlib()
    sys.exit(not result.wasSuccessful())
