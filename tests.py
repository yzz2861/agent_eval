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
    DTDForbidden,
    EntityExpansionExceeded,
    EntitiesForbidden,
    ExpansionPolicy,
    ExternalReferenceForbidden,
    NotSupportedError,
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
        self.assertTrue(cetree_warnings)
        self.assertEqual(cetree_warnings[0].category, DeprecationWarning)
        self.assertIn("tests.py", cetree_warnings[0].filename)


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


class TestExpansionPolicy(DefusedTestCase):
    benign = (
        "<!DOCTYPE root ["
        '<!ENTITY reuse "ab">'
        '<!ENTITY nested "&reuse;cd">'
        "]>"
        '<root attr="x&amp;Y&#65;&reuse;">'
        "text&nested;&#65;&amp;</root>"
    )
    many_declarations = (
        "<!DOCTYPE root ["
        + "".join('<!ENTITY e{} "v">'.format(index) for index in range(4))
        + "]><root/>"
    )
    large_value = '<!DOCTYPE root [<!ENTITY big "{}">]><root/>'.format("x" * 40)
    quadratic = (
        '<!DOCTYPE root [<!ENTITY a "{}">]>'.format("x" * 10) + "<root>" + "&a;" * 5 + "</root>"
    )
    exponential = (
        "<!DOCTYPE root ["
        '<!ENTITY a "xx">'
        '<!ENTITY b "&a;&a;">'
        '<!ENTITY c "&b;&b;">'
        "]><root>&c;</root>"
    )
    cyclic = "<!DOCTYPE root [" '<!ENTITY a "&b;">' '<!ENTITY b "&a;">' "]><root>&a;</root>"
    mutual = "<!DOCTYPE root [" '<!ENTITY a "x&b;">' '<!ENTITY b "y&a;">' "]><root>&a;</root>"
    external = (
        '<!DOCTYPE root [<!ENTITY ext SYSTEM "http://example.invalid/entity">]><root>&ext;</root>'
    )
    parameter = '<!DOCTYPE root [<!ENTITY % param "x">%param;]><root/>'
    unparsed = '<!DOCTYPE root [<!ENTITY pic SYSTEM "pic.gif" NDATA gif>]><root/>'

    def parse_etree(self, xml, policy):
        return ElementTree.fromstring(xml, expansion_policy=policy)

    def parse_minidom(self, xml, policy):
        return minidom.parseString(xml, expansion_policy=policy)

    def parse_pulldom(self, xml, policy):
        return list(pulldom.parseString(xml, expansion_policy=policy))

    def parse_sax(self, xml, policy):
        with io.StringIO() as result:
            sax.parseString(xml.encode("utf-8"), XMLGenerator(result), expansion_policy=policy)
            return result.getvalue()

    def parsers(self):
        return (
            ("ElementTree", self.parse_etree),
            ("minidom", self.parse_minidom),
            ("pulldom", self.parse_pulldom),
            ("SAX", self.parse_sax),
        )

    def test_default_remains_forbidden(self):
        for parser_name, parser in self.parsers():
            with self.subTest(parser=parser_name):
                self.assertRaises(EntitiesForbidden, parser, self.benign, None)

    def test_disabled_policy_remains_forbidden(self):
        policy = ExpansionPolicy(enabled=False)
        for parser_name, parser in self.parsers():
            with self.subTest(parser=parser_name):
                self.assertRaises(EntitiesForbidden, parser, self.benign, policy)

    def test_benign_entities_and_builtin_references(self):
        policy = ExpansionPolicy()
        root = self.parse_etree(self.benign, policy)
        self.assertEqual(root.text, "textabcdA&")
        self.assertEqual(root.attrib["attr"], "x&YAab")
        self.parse_minidom(self.benign, policy)
        self.parse_pulldom(self.benign, policy)
        self.parse_sax(self.benign, policy)

    def test_predefined_and_numeric_references_do_not_consume_budget(self):
        xml = "<root>a&amp;b&#65;c&#x42;d</root>"
        policy = ExpansionPolicy(max_document_expansion=0)
        root = self.parse_etree(xml, policy)
        self.assertEqual(root.text, "a&bAcBd")
        self.parse_minidom(xml, policy)
        self.parse_pulldom(xml, policy)
        self.parse_sax(xml, policy)

    def test_limit_exceptions_identify_limit(self):
        cases = (
            ("max_entity_declarations", dict(max_entity_declarations=3), self.many_declarations),
            ("max_entity_value_size", dict(max_entity_value_size=39), self.large_value),
            ("max_expansion_size", dict(max_expansion_size=7), self.exponential),
            ("max_entity_depth", dict(max_entity_depth=2), self.exponential),
            ("max_document_expansion", dict(max_document_expansion=39), self.quadratic),
        )
        for parser_name, parser in self.parsers():
            for limit_name, kwargs, xml in cases:
                with self.subTest(parser=parser_name, limit=limit_name):
                    with self.assertRaises(EntityExpansionExceeded) as context:
                        parser(xml, ExpansionPolicy(**kwargs))
                    self.assertEqual(context.exception.limit_name, limit_name)
                    self.assertEqual(context.exception.limit, kwargs[limit_name])
                    self.assertGreater(context.exception.current, kwargs[limit_name])

    def test_recursive_and_mutual_entities_are_stable(self):
        policy = ExpansionPolicy(max_entity_depth=5)
        for parser_name, parser in self.parsers():
            for xml in (self.cyclic, self.mutual):
                with self.subTest(parser=parser_name):
                    self.assertRaises(EntityExpansionExceeded, parser, xml, policy)

    def test_external_parameter_and_unparsed_entities_remain_forbidden(self):
        policy = ExpansionPolicy()
        for parser_name, parser in self.parsers():
            for xml in (self.external, self.parameter, self.unparsed):
                with self.subTest(parser=parser_name):
                    self.assertRaises(EntitiesForbidden, parser, xml, policy)

    def test_many_declarations_without_uses_are_limited(self):
        policy = ExpansionPolicy(max_entity_declarations=3)
        for parser_name, parser in self.parsers():
            with self.subTest(parser=parser_name):
                self.assertRaises(EntityExpansionExceeded, parser, self.many_declarations, policy)

    def test_document_budget_accumulates_across_elements_and_attributes(self):
        xml = (
            '<!DOCTYPE root [<!ENTITY reuse "xy">]>'
            "<root><child>&reuse;</child>"
            '<child attr="&reuse;"/></root>'
        )
        policy = ExpansionPolicy(max_document_expansion=3)
        for parser_name, parser in self.parsers():
            with self.subTest(parser=parser_name):
                with self.assertRaises(EntityExpansionExceeded) as context:
                    parser(xml, policy)
                self.assertEqual(context.exception.limit_name, "max_document_expansion")
                self.assertEqual(context.exception.current, 4)

    def test_etree_parse_and_iterparse_entries(self):
        policy = ExpansionPolicy()
        stream = io.BytesIO(self.benign.encode("utf-8"))
        root = ElementTree.parse(stream, expansion_policy=policy).getroot()
        self.assertEqual(root.text, "textabcdA&")

        stream = io.BytesIO(self.quadratic.encode("utf-8"))
        events = ElementTree.iterparse(
            stream,
            expansion_policy=ExpansionPolicy(max_document_expansion=9),
        )
        with self.assertRaises(EntityExpansionExceeded):
            try:
                list(events)
            finally:
                events = None
        self.assertIsNone(events)

    def test_etree_iterparse_closes_opened_file_on_error(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "bomb.xml")
            with open(path, "wb") as stream:
                stream.write(self.quadratic.encode("utf-8"))
            before = set(os.listdir(directory))
            events = ElementTree.iterparse(
                path,
                expansion_policy=ExpansionPolicy(max_document_expansion=9),
            )
            with self.assertRaises(EntityExpansionExceeded):
                list(events)
            self.assertEqual(set(os.listdir(directory)), before)

            success_path = os.path.join(directory, "simple.xml")
            with open(success_path, "wb") as stream:
                stream.write(b"<root/>")
            success_events = ElementTree.iterparse(
                success_path, expansion_policy=ExpansionPolicy()
            )
            list(success_events)
            success_events.close()
            os.remove(success_path)

    def test_sax_reset_does_not_leak_budget(self):
        parser = expatreader.create_parser(expansion_policy=ExpansionPolicy())
        with io.StringIO() as result:
            sax.parseString(
                self.benign.encode("utf-8"),
                XMLGenerator(result),
                expansion_policy=parser.expansion_policy,
            )
        state = parser.expansion_state
        parser.reset()
        self.assertIsNot(parser.expansion_state, state)
        self.assertEqual(parser.expansion_state.document_expansion, 0)

    def test_etree_budget_is_per_parser_instance(self):
        policy = ExpansionPolicy(max_document_expansion=9)
        first = ElementTree.DefusedXMLParser(
            target=ElementTree._TreeBuilder(), expansion_policy=policy
        )
        with self.assertRaises(EntityExpansionExceeded):
            first.feed(self.quadratic)
            first.close()
        second = ElementTree.DefusedXMLParser(
            target=ElementTree._TreeBuilder(), expansion_policy=policy
        )
        self.assertIsNot(first.expansion_state, second.expansion_state)
        root = second.feed(self.benign) or second.close()
        self.assertEqual(root.text, "textabcdA&")

    def test_sax_failed_parse_does_not_leak_budget(self):
        from xml.sax import InputSource

        parser = expatreader.create_parser(
            expansion_policy=ExpansionPolicy(max_document_expansion=9)
        )
        with io.StringIO() as result:
            handler = XMLGenerator(result)
            parser.setContentHandler(handler)
            with self.assertRaises(EntityExpansionExceeded):
                source = InputSource()
                source.setByteStream(io.BytesIO(self.quadratic.encode("utf-8")))
                parser.parse(source)
        self.assertGreater(parser.expansion_state.document_expansion, 9)
        parser.reset()
        with io.StringIO() as result:
            parser.setContentHandler(XMLGenerator(result))
            source = InputSource()
            source.setByteStream(io.BytesIO(self.benign.encode("utf-8")))
            parser.parse(source)
        self.assertLessEqual(
            parser.expansion_state.document_expansion,
            parser.expansion_policy.max_document_expansion,
        )

    def test_policy_requires_non_negative_limits(self):
        self.assertRaises(ValueError, ExpansionPolicy, max_entity_declarations=-1)


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
        TestExpansionPolicy,
        TestXmlRpc,
        TestDefusedGzip,
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
