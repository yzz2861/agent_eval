from __future__ import print_function

import asyncio
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
    DEFAULT_FORBID_DTD,
    DEFAULT_FORBID_ENTITIES,
    DEFAULT_FORBID_EXTERNAL,
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    NotSupportedError,
    RequestConfig,
    get_request_config,
    request_config,
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


class _PolicyRecorder(orig_elementtree.TreeBuilder):
    """TreeBuilder that records the parser's defusing switches on use.

    On the first element it also starts a second, nested parse through the
    public defusedxml entry point, mimicking a SAX/TreeBuilder callback that
    begins reading another document while the outer parse is in flight.
    """

    def __init__(
        self,
        log,
        request_id,
        nested_doc=None,
        nested_config=None,
        nested_request_id=None,
    ):
        super().__init__()
        self._log = log
        self._request_id = request_id
        self._nested_doc = nested_doc
        self._nested_config = nested_config
        self._nested_request_id = nested_request_id or request_id
        self._nested_done = False

    def _record(self, tag):
        parser = getattr(self, "_parser_ref", None)
        if parser is not None:
            self._log.append(
                (
                    self._request_id,
                    tag,
                    parser.forbid_dtd,
                    parser.forbid_entities,
                    parser.forbid_external,
                )
            )

    def start(self, tag, attrs):
        self._record(tag)
        if not self._nested_done and self._nested_doc is not None:
            self._nested_done = True
            if self._nested_config is not None:
                with request_config(self._nested_config):
                    nested_builder = _PolicyRecorder(
                        self._log, self._nested_request_id
                    )
                    _feed_with_builder(self._nested_doc, nested_builder)
            else:
                ElementTree.fromstring(self._nested_doc)
        return super().start(tag, attrs)


def _feed_with_builder(doc, builder, chunk_size=12):
    from defusedxml.common import resolve_request_config

    forbid_dtd, forbid_entities, forbid_external = resolve_request_config()
    parser = ElementTree.DefusedXMLParser(
        target=builder,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    builder._parser_ref = parser
    for index in range(0, len(doc), chunk_size):
        parser.feed(doc[index:index + chunk_size])
    return parser.close()


SHORT_DOC = "<doc><item>one</item><item>two</item></doc>"
SHORT_DOC_WITH_DTD = (
    '<!DOCTYPE doc [<!ENTITY greeting "hello">]>'
    "<doc><item>&greeting;</item></doc>"
)


class TestRequestConfig(unittest.TestCase):
    """Per-request policies must follow their own execution context."""

    def setUp(self):
        self.assertIsNone(get_request_config())

    def tearDown(self):
        self.assertIsNone(get_request_config())

    def test_defaults_match_historical_guarantees(self):
        self.assertEqual(DEFAULT_FORBID_DTD, False)
        self.assertEqual(DEFAULT_FORBID_ENTITIES, True)
        self.assertEqual(DEFAULT_FORBID_EXTERNAL, True)
        self.assertEqual(
            RequestConfig(),
            RequestConfig(forbid_dtd=False, forbid_entities=True, forbid_external=True),
        )
        # old callers without any keyword arguments keep working unchanged
        root = ElementTree.fromstring(SHORT_DOC)
        self.assertEqual(root.tag, "doc")

    def test_context_restores_outer_state(self):
        strict = RequestConfig(forbid_dtd=True)
        relaxed = RequestConfig(
            forbid_dtd=False, forbid_entities=False, forbid_external=False
        )
        with request_config(strict):
            self.assertIs(get_request_config(), strict)
            with request_config(relaxed):
                self.assertIs(get_request_config(), relaxed)
                ElementTree.fromstring(SHORT_DOC_WITH_DTD)
            self.assertIs(get_request_config(), strict)
            with self.assertRaises(DTDForbidden):
                ElementTree.fromstring(SHORT_DOC_WITH_DTD)
        self.assertIsNone(get_request_config())

    def test_context_restore_on_exception(self):
        strict = RequestConfig(forbid_dtd=True)
        with self.assertRaises(DTDForbidden):
            with request_config(strict):
                ElementTree.fromstring(SHORT_DOC_WITH_DTD)
        self.assertIsNone(get_request_config())

    def test_explicit_kwargs_override_request_config(self):
        strict = RequestConfig(forbid_dtd=True)
        with request_config(strict):
            # an explicit per-call switch wins over the bound request config
            ElementTree.fromstring(
                SHORT_DOC_WITH_DTD,
                forbid_dtd=False,
                forbid_entities=False,
                forbid_external=False,
            )
        self.assertIsNone(get_request_config())

    def test_request_config_keyword_on_entry_points(self):
        strict = RequestConfig(forbid_dtd=True)
        with self.assertRaises(DTDForbidden):
            ElementTree.fromstring(SHORT_DOC_WITH_DTD, request_config=strict)
        with self.assertRaises(DTDForbidden):
            ElementTree.fromstringlist(
                [SHORT_DOC_WITH_DTD[:20], SHORT_DOC_WITH_DTD[20:]],
                request_config=strict,
            )
        stream = io.BytesIO(SHORT_DOC_WITH_DTD.encode("utf-8"))
        with self.assertRaises(DTDForbidden):
            list(ElementTree.iterparse(stream, request_config=strict))
        self.assertIsNone(get_request_config())

    def test_nested_parse_inside_callback_uses_request_policy(self):
        log = []
        strict = RequestConfig(forbid_dtd=True)
        relaxed = RequestConfig(
            forbid_dtd=False, forbid_entities=False, forbid_external=False
        )
        # The outer, relaxed request parses a plain doc. Its first builder
        # callback starts a second, strict request reading another plain doc.
        with request_config(relaxed):
            builder = _PolicyRecorder(
                log,
                "relaxed",
                nested_doc=SHORT_DOC,
                nested_config=strict,
                nested_request_id="strict",
            )
            _feed_with_builder(SHORT_DOC, builder)

        by_request = {}
        for request_id, tag, forbid_dtd, forbid_entities, forbid_external in log:
            by_request.setdefault(request_id, set()).add(
                (forbid_dtd, forbid_entities, forbid_external)
            )
        self.assertEqual(by_request["relaxed"], {(False, False, False)})
        self.assertEqual(by_request["strict"], {(True, True, True)})
        # the stricter request rejects a DTD while the relaxed one accepts it
        with request_config(strict):
            with self.assertRaises(DTDForbidden):
                ElementTree.fromstring(SHORT_DOC_WITH_DTD)
        with request_config(relaxed):
            ElementTree.fromstring(SHORT_DOC_WITH_DTD)
        self.assertIsNone(get_request_config())

    def test_interleaved_requests_keep_isolated_policies(self):
        log = []
        strict = RequestConfig(forbid_dtd=True)
        relaxed = RequestConfig(
            forbid_dtd=False, forbid_entities=False, forbid_external=False
        )

        async def parse_interleaved(request_id, config, doc, chunk_size=12):
            with request_config(config):
                await asyncio.sleep(0)
                builder = _PolicyRecorder(log, request_id)
                seen_config = get_request_config()
                self.assertIs(seen_config, config)
                _feed_with_builder(doc, builder, chunk_size=chunk_size)
                await asyncio.sleep(0)
                return get_request_config()

        async def main():
            strict_task = asyncio.ensure_future(
                parse_interleaved("strict", strict, SHORT_DOC)
            )
            relaxed_task = asyncio.ensure_future(
                parse_interleaved("relaxed", relaxed, SHORT_DOC)
            )
            strict_seen, relaxed_seen = await asyncio.gather(
                strict_task, relaxed_task
            )
            return strict_seen, relaxed_seen

        strict_seen, relaxed_seen = asyncio.run(main())
        self.assertIs(strict_seen, strict)
        self.assertIs(relaxed_seen, relaxed)

        observed = {}
        for request_id, tag, forbid_dtd, forbid_entities, forbid_external in log:
            observed.setdefault(request_id, set()).add(
                (forbid_dtd, forbid_entities, forbid_external)
            )
        # every parser event always carries the policy of its own request
        self.assertEqual(observed["strict"], {(True, True, True)})
        self.assertEqual(observed["relaxed"], {(False, False, False)})
        # and the stricter request independently enforces its own limit
        async def strict_rejects_dtd():
            with request_config(strict):
                with self.assertRaises(DTDForbidden):
                    ElementTree.fromstring(SHORT_DOC_WITH_DTD)

        asyncio.run(strict_rejects_dtd())
        self.assertIsNone(get_request_config())

    def test_cancelled_task_cleans_up_its_own_state(self):
        log = []
        strict = RequestConfig(forbid_dtd=True)
        relaxed = RequestConfig(
            forbid_dtd=False, forbid_entities=False, forbid_external=False
        )

        async def cancelled_request():
            with request_config(strict):
                builder = _PolicyRecorder(log, "strict")
                parser = ElementTree.DefusedXMLParser(
                    target=builder,
                    forbid_dtd=True,
                    forbid_entities=True,
                    forbid_external=True,
                )
                builder._parser_ref = parser
                # builder events fire and record the strict policy before
                # the task gives up control and gets cancelled
                parser.feed("<doc><item>one</item>")
                await asyncio.sleep(10)
                parser.feed(SHORT_DOC)  # pragma: no cover - cancelled
                parser.close()  # pragma: no cover - cancelled

        async def surviving_request():
            with request_config(relaxed):
                await asyncio.sleep(0)
                _feed_with_builder(SHORT_DOC, _PolicyRecorder(log, "relaxed"))
                self.assertIs(get_request_config(), relaxed)
                return get_request_config()

        async def main():
            cancel_target = asyncio.ensure_future(cancelled_request())
            survivor = asyncio.ensure_future(surviving_request())
            await asyncio.sleep(0.01)
            cancel_target.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await cancel_target
            survivor_config = await survivor
            return survivor_config

        survivor_config = asyncio.run(main())
        self.assertIs(survivor_config, relaxed)
        self.assertIsNone(get_request_config())
        observed = {}
        for request_id, tag, forbid_dtd, forbid_entities, forbid_external in log:
            observed.setdefault(request_id, set()).add(
                (forbid_dtd, forbid_entities, forbid_external)
            )
        self.assertEqual(observed["relaxed"], {(False, False, False)})
        self.assertEqual(observed["strict"], {(True, True, True)})

    def test_invalid_config_arguments(self):
        with self.assertRaises(TypeError):
            ElementTree.fromstring(SHORT_DOC, request_config={"forbid_dtd": True})
        with self.assertRaises(TypeError):
            with request_config(object()):
                pass
        with self.assertRaises(TypeError):
            with request_config(RequestConfig(), forbid_dtd=True):
                pass

    def test_all_facades_follow_request_config(self):
        strict = RequestConfig(forbid_dtd=True)
        dtd_bytes = SHORT_DOC_WITH_DTD.encode("utf-8")
        with request_config(strict):
            with self.assertRaises(DTDForbidden):
                minidom.parseString(SHORT_DOC_WITH_DTD)
            with self.assertRaises(DTDForbidden):
                list(pulldom.parseString(SHORT_DOC_WITH_DTD))
            with self.assertRaises(DTDForbidden):
                sax.parseString(dtd_bytes, XMLGenerator())
        # outside the context the historical, less strict default applies
        minidom.parseString(SHORT_DOC)
        list(pulldom.parseString(SHORT_DOC))


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
        TestRequestConfig,
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
