from __future__ import absolute_import, division, unicode_literals

import os
import json

import pytest
from six import text_type

from .support import get_data_files

from html5lib import constants, parse
from html5lib.treewalkers import getTreeWalker
from html5lib.filters.lint import Filter as Lint
from html5lib.serializer import HTMLSerializer, SerializeError, serialize
from html5lib.treewalkers.base import TreeWalker

# pylint:disable=wrong-import-position
optionals_loaded = []

try:
    from lxml import etree
    optionals_loaded.append("lxml")
except ImportError:
    pass
# pylint:enable=wrong-import-position

default_namespace = constants.namespaces["html"]
namespaces = constants.namespaces


class JsonWalker(TreeWalker):
    def __iter__(self):
        for token in self.tree:
            type = token[0]
            if type == "StartTag":
                if len(token) == 4:
                    namespace, name, attrib = token[1:4]
                else:
                    namespace = default_namespace
                    name, attrib = token[1:3]
                yield self.startTag(namespace, name, self._convertAttrib(attrib))
            elif type == "EndTag":
                if len(token) == 3:
                    namespace, name = token[1:3]
                else:
                    namespace = default_namespace
                    name = token[1]
                yield self.endTag(namespace, name)
            elif type == "EmptyTag":
                if len(token) == 4:
                    namespace, name, attrib = token[1:]
                else:
                    namespace = default_namespace
                    name, attrib = token[1:]
                for token in self.emptyTag(namespace, name, self._convertAttrib(attrib)):
                    yield token
            elif type == "Comment":
                yield self.comment(token[1])
            elif type in ("Characters", "SpaceCharacters"):
                for token in self.text(token[1]):
                    yield token
            elif type == "Doctype":
                if len(token) == 4:
                    yield self.doctype(token[1], token[2], token[3])
                elif len(token) == 3:
                    yield self.doctype(token[1], token[2])
                else:
                    yield self.doctype(token[1])
            else:
                raise ValueError("Unknown token type: " + type)

    def _convertAttrib(self, attribs):
        """html5lib tree-walkers use a dict of (namespace, name): value for
        attributes, but JSON cannot represent this. Convert from the format
        in the serializer tests (a list of dicts with "namespace", "name",
        and "value" as keys) to html5lib's tree-walker format."""
        attrs = {}
        for attrib in attribs:
            name = (attrib["namespace"], attrib["name"])
            assert name not in attrs
            attrs[name] = attrib["value"]
        return attrs


def serialize_html(input, options):
    options = {str(k): v for k, v in options.items()}
    encoding = options.get("encoding", None)
    if "encoding" in options:
        del options["encoding"]
    stream = Lint(JsonWalker(input), False)
    serializer = HTMLSerializer(alphabetical_attributes=True, **options)
    return serializer.render(stream, encoding)


def throwsWithLatin1(input):
    with pytest.raises(UnicodeEncodeError):
        serialize_html(input, {"encoding": "iso-8859-1"})


def testDoctypeName():
    throwsWithLatin1([["Doctype", "\u0101"]])


def testDoctypePublicId():
    throwsWithLatin1([["Doctype", "potato", "\u0101"]])


def testDoctypeSystemId():
    throwsWithLatin1([["Doctype", "potato", "potato", "\u0101"]])


def testCdataCharacters():
    test_serializer([["StartTag", "http://www.w3.org/1999/xhtml", "style", {}], ["Characters", "\u0101"]],
                    ["<style>&amacr;"], {"encoding": "iso-8859-1"})


def testCharacters():
    test_serializer([["Characters", "\u0101"]],
                    ["&amacr;"], {"encoding": "iso-8859-1"})


def testStartTagName():
    throwsWithLatin1([["StartTag", "http://www.w3.org/1999/xhtml", "\u0101", []]])


def testAttributeName():
    throwsWithLatin1([["StartTag", "http://www.w3.org/1999/xhtml", "span", [{"namespace": None, "name": "\u0101", "value": "potato"}]]])


def testAttributeValue():
    test_serializer([["StartTag", "http://www.w3.org/1999/xhtml", "span",
                      [{"namespace": None, "name": "potato", "value": "\u0101"}]]],
                    ["<span potato=&amacr;>"], {"encoding": "iso-8859-1"})


def testEndTagName():
    throwsWithLatin1([["EndTag", "http://www.w3.org/1999/xhtml", "\u0101"]])


def testComment():
    throwsWithLatin1([["Comment", "\u0101"]])


def testThrowsUnknownOption():
    with pytest.raises(TypeError):
        HTMLSerializer(foobar=None)


@pytest.mark.parametrize("c", list("\t\n\u000C\x20\r\"'=<>`"))
def testSpecQuoteAttribute(c):
    input_ = [["StartTag", "http://www.w3.org/1999/xhtml", "span",
               [{"namespace": None, "name": "foo", "value": c}]]]
    if c == '"':
        output_ = ["<span foo='%s'>" % c]
    else:
        output_ = ['<span foo="%s">' % c]
    options_ = {"quote_attr_values": "spec"}
    test_serializer(input_, output_, options_)


@pytest.mark.parametrize("c", list("\t\n\u000C\x20\r\"'=<>`"
                                   "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n"
                                   "\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15"
                                   "\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
                                   "\x20\x2f\x60\xa0\u1680\u180e\u180f\u2000"
                                   "\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
                                   "\u2008\u2009\u200a\u2028\u2029\u202f\u205f"
                                   "\u3000"))
def testLegacyQuoteAttribute(c):
    input_ = [["StartTag", "http://www.w3.org/1999/xhtml", "span",
               [{"namespace": None, "name": "foo", "value": c}]]]
    if c == '"':
        output_ = ["<span foo='%s'>" % c]
    else:
        output_ = ['<span foo="%s">' % c]
    options_ = {"quote_attr_values": "legacy"}
    test_serializer(input_, output_, options_)


@pytest.fixture
def lxml_parser():
    return etree.XMLParser(resolve_entities=False)


@pytest.mark.skipif("lxml" not in optionals_loaded, reason="lxml not importable")
def testEntityReplacement(lxml_parser):
    doc = '<!DOCTYPE html SYSTEM "about:legacy-compat"><html>&beta;</html>'
    tree = etree.fromstring(doc, parser=lxml_parser).getroottree()
    result = serialize(tree, tree="lxml", omit_optional_tags=False)
    assert result == '<!DOCTYPE html SYSTEM "about:legacy-compat"><html>\u03B2</html>'


@pytest.mark.skipif("lxml" not in optionals_loaded, reason="lxml not importable")
def testEntityXML(lxml_parser):
    doc = '<!DOCTYPE html SYSTEM "about:legacy-compat"><html>&gt;</html>'
    tree = etree.fromstring(doc, parser=lxml_parser).getroottree()
    result = serialize(tree, tree="lxml", omit_optional_tags=False)
    assert result == '<!DOCTYPE html SYSTEM "about:legacy-compat"><html>&gt;</html>'


@pytest.mark.skipif("lxml" not in optionals_loaded, reason="lxml not importable")
def testEntityNoResolve(lxml_parser):
    doc = '<!DOCTYPE html SYSTEM "about:legacy-compat"><html>&beta;</html>'
    tree = etree.fromstring(doc, parser=lxml_parser).getroottree()
    result = serialize(tree, tree="lxml", omit_optional_tags=False,
                                  resolve_entities=False)
    assert result == '<!DOCTYPE html SYSTEM "about:legacy-compat"><html>&beta;</html>'


def param_serializer():
    for filename in get_data_files('serializer-testdata', '*.test', os.path.dirname(__file__)):
        with open(filename) as fp:
            tests = json.load(fp)
            for test in tests['tests']:
                yield test["input"], test["expected"], test.get("options", {})


@pytest.mark.parametrize("input, expected, options", param_serializer())
def test_serializer(input, expected, options):
    encoding = options.get("encoding", None)

    if encoding:
        expected = list(map(lambda x: x.encode(encoding), expected))

    result = serialize_html(input, options)
    if len(expected) == 1:
        assert expected[0] == result, "Expected:\n%s\nActual:\n%s\nOptions:\n%s" % (expected[0], result, str(options))
    elif result not in expected:
        assert False, "Expected: %s, Received: %s" % (expected, result)


def _attributes_by_element(document):
    walker = getTreeWalker("etree")
    return [((token["namespace"], token["name"]),
             sorted(token["data"].items(), key=lambda item: text_type(item[0])))
            for token in walker(document)
            if token["type"] in ("StartTag", "EmptyTag")]


def _round_trip(markup, **options):
    document = parse(markup)
    serialized = serialize(document, omit_optional_tags=False, **options)
    reparsed = parse(serialized)
    return serialized, _attributes_by_element(document), _attributes_by_element(reparsed)


def test_namespaced_attribute_keeps_prefix():
    # Regression test: xlink:href used to be serialized as a plain href and
    # therefore changed namespace on reparse, bypassing sanitizer checks.
    serialized, before, after = _round_trip(
        "<svg><a xlink:href='javascript:alert(1)'></a></svg>")
    assert "xlink:href=javascript:alert(1)" in serialized
    assert before == after
    assert ((namespaces["svg"], "a"),
            [((namespaces["xlink"], "href"), "javascript:alert(1)")]) in after


def test_namespaced_and_plain_attribute_do_not_collapse():
    serialized, before, after = _round_trip(
        "<svg><a href='plain' xlink:href='linked'></a></svg>")
    assert before == after
    assert "href=plain" in serialized
    assert "xlink:href=linked" in serialized


def test_xml_namespace_attributes_round_trip():
    serialized, before, after = _round_trip(
        "<svg><text xml:lang='en' xml:space='preserve'>x</text></svg>")
    assert before == after
    assert "xml:lang=en" in serialized
    assert "xml:space=preserve" in serialized


def test_foreign_local_names_are_preserved():
    serialized, before, after = _round_trip(
        "<svg viewBox='0 0 1 1'></svg>"
        "<math><mi definitionURL='http://example.com/'>x</mi></math>")
    assert before == after
    assert 'viewBox="0 0 1 1"' in serialized
    assert 'definitionURL="http://example.com/"' in serialized


def test_html_attribute_names_are_lowercased():
    serialized, before, after = _round_trip("<div CLASS='c' data-FOO='b'></div>")
    assert before == after
    assert "class=c" in serialized
    assert "data-foo=b" in serialized


def test_unknown_prefix_attribute_is_literal():
    serialized, before, after = _round_trip("<div a:b='1'></div>")
    assert before == after
    assert "a:b=1" in serialized


def test_namespaced_attribute_escaping_round_trips():
    serialized, before, after = _round_trip(
        "<svg><a xlink:href='a&#13;b&amp;c&#0;d'></a></svg>")
    assert before == after
    assert "&#13;" in serialized
    assert "&amp;" in serialized


def test_namespaced_attribute_control_characters_are_quoted_and_escaped():
    result = serialize_html(
        [["StartTag", namespaces["svg"], "a", [
            {"namespace": namespaces["xlink"], "name": "href",
             "value": "a\x00b"},
            {"namespace": namespaces["xlink"], "name": "title",
             "value": "c\rd"}]],
         ["EndTag", namespaces["svg"], "a"]], {})
    assert 'xlink:href="a&#0;b"' in result
    assert 'xlink:title="c&#13;d"' in result


def test_namespaced_attribute_quote_selection():
    double_quote = serialize(
        parse("<svg><a xlink:href=\"a'b\"></a></svg>"),
        omit_optional_tags=False)
    assert "xlink:href=\"a'b\"" in double_quote

    single_quote = serialize(
        parse("<svg><a xlink:href='a&quot;b'></a></svg>"),
        omit_optional_tags=False)
    assert "xlink:href='a\"b'" in single_quote


def test_prefix_conflict_is_reported_and_dropped():
    walker = JsonWalker([
        ["StartTag", namespaces["svg"], "svg", [
            {"namespace": namespaces["xmlns"], "name": "xlink",
             "value": "urn:bogus"}]],
        ["StartTag", namespaces["svg"], "a", [
            {"namespace": namespaces["xlink"], "name": "href",
             "value": "1"}]],
        ["EndTag", namespaces["svg"], "a"],
        ["EndTag", namespaces["svg"], "svg"],
    ])
    serializer = HTMLSerializer(omit_optional_tags=False)
    result = serializer.render(Lint(walker, False))
    assert "xmlns:xlink=urn:bogus" in result
    assert "xlink:href" not in result
    assert serializer.errors


def test_unknown_namespace_attribute_is_reported_and_dropped():
    unknown_namespace = "http://example.invalid/ns"
    walker = JsonWalker([
        ["StartTag", namespaces["svg"], "a", [
            {"namespace": unknown_namespace, "name": "href",
             "value": "javascript:evil()"},
            {"namespace": namespaces["xlink"], "name": "title",
             "value": "ok"}]],
        ["EndTag", namespaces["svg"], "a"],
    ])
    serializer = HTMLSerializer(omit_optional_tags=False)
    result = serializer.render(Lint(walker, False))
    assert "javascript:evil()" not in result
    assert "xlink:title=ok" in result
    assert len(serializer.errors) == 1

    strict = HTMLSerializer(omit_optional_tags=False)
    strict.strict = True
    with pytest.raises(SerializeError):
        strict.render(Lint(JsonWalker([
            ["StartTag", namespaces["svg"], "a", [
                {"namespace": unknown_namespace, "name": "href",
                 "value": "x"}]],
            ["EndTag", namespaces["svg"], "a"],
        ]), False))


def test_duplicate_attribute_after_folding_is_reported():
    walker = JsonWalker([
        ["StartTag", namespaces["svg"], "a", [
            {"namespace": None, "name": "Href", "value": "1"},
            {"namespace": None, "name": "href", "value": "2"}]],
        ["EndTag", namespaces["svg"], "a"],
    ])
    serializer = HTMLSerializer(omit_optional_tags=False)
    result = serializer.render(Lint(walker, False))
    assert result.lower().count("href") == 1
    assert serializer.errors


def test_invalid_local_names_are_reported_and_dropped():
    walker = JsonWalker([
        ["StartTag", namespaces["svg"], "a", [
            {"namespace": namespaces["xlink"], "name": "href",
             "value": "1"},
            {"namespace": namespaces["xlink"], "name": "bad name",
             "value": "2"},
            {"namespace": None, "name": "a b", "value": "4"}]],
        ["EndTag", namespaces["svg"], "a"],
    ])
    serializer = HTMLSerializer(omit_optional_tags=False)
    result = serializer.render(walker)
    assert "xlink:href=1" in result
    assert "bad name" not in result
    assert "a b" not in result
    assert len(serializer.errors) == 2


def test_empty_local_name_is_reported_and_dropped():
    walker = JsonWalker([
        ["StartTag", namespaces["svg"], "a", [
            {"namespace": namespaces["xlink"], "name": "href",
             "value": "1"},
            {"namespace": namespaces["xlink"], "name": "",
             "value": "3"}]],
        ["EndTag", namespaces["svg"], "a"],
    ])
    serializer = HTMLSerializer(omit_optional_tags=False)
    result = serializer.render(walker)
    assert "xlink:href=1" in result
    assert len(serializer.errors) == 1
