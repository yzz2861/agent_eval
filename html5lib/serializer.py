from __future__ import absolute_import, division, unicode_literals
from six import text_type

import re

from codecs import register_error, xmlcharrefreplace_errors

from .constants import (voidElements, booleanAttributes, spaceCharacters,
                        namespaces)
from .constants import rcdataElements, entities, xmlEntities
from . import treewalkers, _utils
from xml.sax.saxutils import escape

# Canonical prefixes for the namespace URIs that the HTML parser is able to
# assign to attributes in foreign content.  Anything else cannot be expressed
# safely in HTML and has to be declared explicitly on the element.
_namespacePrefixes = {
    namespaces["xlink"]: "xlink",
    namespaces["xml"]: "xml",
    namespaces["xmlns"]: "xmlns",
}

# An XML Name minus ":", which is exactly what a local name is allowed to be.
# The explicit Unicode ranges stay valid on narrow (UTF-16) Python 2 builds,
# while excluding control characters, whitespace and markup-significant ASCII.
_localNameRegExp = re.compile(
    r"^[A-Za-z_\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D"
    r"\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF"
    r"\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]"
    r"[A-Za-z0-9_\-.\u00B7\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF"
    r"\u0300-\u036F\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u203F-\u2040"
    r"\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF"
    r"\uFDF0-\uFFFD]*$")

# Unnamespaced attribute names may use ":" (unknown prefixes are preserved
# verbatim by the HTML parser), but no other markup-significant character.
_unqualifiedNameRegExp = re.compile(
    r"^[A-Za-z_:\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF"
    r"\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F"
    r"\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]"
    r"[A-Za-z0-9_\-.:\u00B7\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF"
    r"\u0300-\u036F\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u203F-\u2040"
    r"\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF"
    r"\uFDF0-\uFFFD]*$")

_quoteAttributeSpecChars = "".join(spaceCharacters) + "\"'=<>`"
_quoteAttributeSpec = re.compile("[" + _quoteAttributeSpecChars + "]")
_quoteAttributeLegacy = re.compile("[" + _quoteAttributeSpecChars +
                                   "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n"
                                   "\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15"
                                   "\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
                                   "\x20\x2f\x60\xa0\u1680\u180e\u180f\u2000"
                                   "\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
                                   "\u2008\u2009\u200a\u2028\u2029\u202f\u205f"
                                   "\u3000]")


_encode_entity_map = {}
_is_ucs4 = len("\U0010FFFF") == 1
for k, v in list(entities.items()):
    # skip multi-character entities
    if ((_is_ucs4 and len(v) > 1) or
            (not _is_ucs4 and len(v) > 2)):
        continue
    if v != "&":
        if len(v) == 2:
            v = _utils.surrogatePairToCodepoint(v)
        else:
            v = ord(v)
        if v not in _encode_entity_map or k.islower():
            # prefer &lt; over &LT; and similarly for &amp;, &gt;, etc.
            _encode_entity_map[v] = k


def htmlentityreplace_errors(exc):
    if isinstance(exc, (UnicodeEncodeError, UnicodeTranslateError)):
        res = []
        codepoints = []
        skip = False
        for i, c in enumerate(exc.object[exc.start:exc.end]):
            if skip:
                skip = False
                continue
            index = i + exc.start
            if _utils.isSurrogatePair(exc.object[index:min([exc.end, index + 2])]):
                codepoint = _utils.surrogatePairToCodepoint(exc.object[index:index + 2])
                skip = True
            else:
                codepoint = ord(c)
            codepoints.append(codepoint)
        for cp in codepoints:
            e = _encode_entity_map.get(cp)
            if e:
                res.append("&")
                res.append(e)
                if not e.endswith(";"):
                    res.append(";")
            else:
                res.append("&#x%s;" % (hex(cp)[2:]))
        return ("".join(res), exc.end)
    else:
        return xmlcharrefreplace_errors(exc)


register_error("htmlentityreplace", htmlentityreplace_errors)


def serialize(input, tree="etree", encoding=None, **serializer_opts):
    """Serializes the input token stream using the specified treewalker

    :arg input: the token stream to serialize

    :arg tree: the treewalker to use

    :arg encoding: the encoding to use

    :arg serializer_opts: any options to pass to the
        :py:class:`html5lib.serializer.HTMLSerializer` that gets created

    :returns: the tree serialized as a string

    Example:

    >>> from html5lib.html5parser import parse
    >>> from html5lib.serializer import serialize
    >>> token_stream = parse('<html><body><p>Hi!</p></body></html>')
    >>> serialize(token_stream, omit_optional_tags=False)
    '<html><head></head><body><p>Hi!</p></body></html>'

    """
    # XXX: Should we cache this?
    walker = treewalkers.getTreeWalker(tree)
    s = HTMLSerializer(**serializer_opts)
    return s.render(walker(input), encoding)


class HTMLSerializer(object):

    # attribute quoting options
    quote_attr_values = "legacy"  # be secure by default
    quote_char = '"'
    use_best_quote_char = True

    # tag syntax options
    omit_optional_tags = True
    minimize_boolean_attributes = True
    use_trailing_solidus = False
    space_before_trailing_solidus = True

    # escaping options
    escape_lt_in_attrs = False
    escape_rcdata = False
    resolve_entities = True

    # miscellaneous options
    alphabetical_attributes = False
    inject_meta_charset = True
    strip_whitespace = False
    sanitize = False

    options = ("quote_attr_values", "quote_char", "use_best_quote_char",
               "omit_optional_tags", "minimize_boolean_attributes",
               "use_trailing_solidus", "space_before_trailing_solidus",
               "escape_lt_in_attrs", "escape_rcdata", "resolve_entities",
               "alphabetical_attributes", "inject_meta_charset",
               "strip_whitespace", "sanitize")

    def __init__(self, **kwargs):
        """Initialize HTMLSerializer

        :arg inject_meta_charset: Whether or not to inject the meta charset.

            Defaults to ``True``.

        :arg quote_attr_values: Whether to quote attribute values that don't
            require quoting per legacy browser behavior (``"legacy"``), when
            required by the standard (``"spec"``), or always (``"always"``).

            Defaults to ``"legacy"``.

        :arg quote_char: Use given quote character for attribute quoting.

            Defaults to ``"`` which will use double quotes unless attribute
            value contains a double quote, in which case single quotes are
            used.

        :arg escape_lt_in_attrs: Whether or not to escape ``<`` in attribute
            values.

            Defaults to ``False``.

        :arg escape_rcdata: Whether to escape characters that need to be
            escaped within normal elements within rcdata elements such as
            style.

            Defaults to ``False``.

        :arg resolve_entities: Whether to resolve named character entities that
            appear in the source tree. The XML predefined entities &lt; &gt;
            &amp; &quot; &apos; are unaffected by this setting.

            Defaults to ``True``.

        :arg strip_whitespace: Whether to remove semantically meaningless
            whitespace. (This compresses all whitespace to a single space
            except within ``pre``.)

            Defaults to ``False``.

        :arg minimize_boolean_attributes: Shortens boolean attributes to give
            just the attribute value, for example::

              <input disabled="disabled">

            becomes::

              <input disabled>

            Defaults to ``True``.

        :arg use_trailing_solidus: Includes a close-tag slash at the end of the
            start tag of void elements (empty elements whose end tag is
            forbidden). E.g. ``<hr/>``.

            Defaults to ``False``.

        :arg space_before_trailing_solidus: Places a space immediately before
            the closing slash in a tag using a trailing solidus. E.g.
            ``<hr />``. Requires ``use_trailing_solidus=True``.

            Defaults to ``True``.

        :arg sanitize: Strip all unsafe or unknown constructs from output.
            See :py:class:`html5lib.filters.sanitizer.Filter`.

            Defaults to ``False``.

        :arg omit_optional_tags: Omit start/end tags that are optional.

            Defaults to ``True``.

        :arg alphabetical_attributes: Reorder attributes to be in alphabetical order.

            Defaults to ``False``.

        """
        unexpected_args = frozenset(kwargs) - frozenset(self.options)
        if len(unexpected_args) > 0:
            raise TypeError("__init__() got an unexpected keyword argument '%s'" % next(iter(unexpected_args)))
        if 'quote_char' in kwargs:
            self.use_best_quote_char = False
        for attr in self.options:
            setattr(self, attr, kwargs.get(attr, getattr(self, attr)))
        self.errors = []
        self.strict = False

    def encode(self, string):
        assert isinstance(string, text_type)
        if self.encoding:
            return string.encode(self.encoding, "htmlentityreplace")
        else:
            return string

    def encodeStrict(self, string):
        assert isinstance(string, text_type)
        if self.encoding:
            return string.encode(self.encoding, "strict")
        else:
            return string

    def serialize(self, treewalker, encoding=None):
        # pylint:disable=too-many-nested-blocks
        self.encoding = encoding
        in_cdata = False
        self.errors = []
        # One frame per open element, each holding the explicit xmlns
        # declarations (prefix -> namespace URI) carried by that element.
        # HTML has no general namespace mechanism, but the parser recognizes
        # fixed xlink/xml/xmlns prefixes; tracking their declarations lets us
        # detect conflicts instead of letting a redeclared prefix hijack the
        # namespace of an attribute.
        namespace_stack = []
        element_stack = []

        if encoding and self.inject_meta_charset:
            from .filters.inject_meta_charset import Filter
            treewalker = Filter(treewalker, encoding)
        # Alphabetical attributes is here under the assumption that none of
        # the later filters add or change order of attributes; it needs to be
        # before the sanitizer so escaped elements come out correctly
        if self.alphabetical_attributes:
            from .filters.alphabeticalattributes import Filter
            treewalker = Filter(treewalker)
        # WhitespaceFilter should be used before OptionalTagFilter
        # for maximum efficiently of this latter filter
        if self.strip_whitespace:
            from .filters.whitespace import Filter
            treewalker = Filter(treewalker)
        if self.sanitize:
            from .filters.sanitizer import Filter
            treewalker = Filter(treewalker)
        if self.omit_optional_tags:
            from .filters.optionaltags import Filter
            treewalker = Filter(treewalker)

        for token in treewalker:
            type = token["type"]
            if type == "Doctype":
                doctype = "<!DOCTYPE %s" % token["name"]

                if token["publicId"]:
                    doctype += ' PUBLIC "%s"' % token["publicId"]
                elif token["systemId"]:
                    doctype += " SYSTEM"
                if token["systemId"]:
                    if token["systemId"].find('"') >= 0:
                        if token["systemId"].find("'") >= 0:
                            self.serializeError("System identifier contains both single and double quote characters")
                        quote_char = "'"
                    else:
                        quote_char = '"'
                    doctype += " %s%s%s" % (quote_char, token["systemId"], quote_char)

                doctype += ">"
                yield self.encodeStrict(doctype)

            elif type in ("Characters", "SpaceCharacters"):
                if type == "SpaceCharacters" or in_cdata:
                    if in_cdata and token["data"].find("</") >= 0:
                        self.serializeError("Unexpected </ in CDATA")
                    yield self.encode(token["data"])
                else:
                    yield self.encode(escape(token["data"]))

            elif type in ("StartTag", "EmptyTag"):
                name = token["name"]
                element_namespace = token.get("namespace", namespaces["html"])
                yield self.encodeStrict("<%s" % name)
                if name in rcdataElements and not self.escape_rcdata:
                    in_cdata = True
                elif in_cdata:
                    self.serializeError("Unexpected child element of a CDATA element")
                for chunk in self.serializeAttributes(name, element_namespace,
                                                      token["data"],
                                                      namespace_stack):
                    yield chunk
                if type == "StartTag":
                    element_stack.append((element_namespace, name))
                else:
                    # EmptyTag tokens never have a matching EndTag.
                    namespace_stack.pop()
                if name in voidElements and self.use_trailing_solidus:
                    if self.space_before_trailing_solidus:
                        yield self.encodeStrict(" /")
                    else:
                        yield self.encodeStrict("/")
                yield self.encode(">")

            elif type == "EndTag":
                name = token["name"]
                end_namespace = token.get("namespace", namespaces["html"])
                # Optional end tags may have been omitted by a filter, so pop
                # back to the matching open element rather than assuming the
                # streams are perfectly balanced.
                while element_stack and element_stack[-1] != (end_namespace, name):
                    element_stack.pop()
                    namespace_stack.pop()
                if element_stack:
                    element_stack.pop()
                    namespace_stack.pop()
                if name in rcdataElements:
                    in_cdata = False
                elif in_cdata:
                    self.serializeError("Unexpected child element of a CDATA element")
                yield self.encodeStrict("</%s>" % name)

            elif type == "Comment":
                data = token["data"]
                if data.find("--") >= 0:
                    self.serializeError("Comment contains --")
                yield self.encodeStrict("<!--%s-->" % token["data"])

            elif type == "Entity":
                name = token["name"]
                key = name + ";"
                if key not in entities:
                    self.serializeError("Entity %s not recognized" % name)
                if self.resolve_entities and key not in xmlEntities:
                    data = entities[key]
                else:
                    data = "&%s;" % name
                yield self.encodeStrict(data)

            else:
                self.serializeError(token["data"])

    def render(self, treewalker, encoding=None):
        """Serializes the stream from the treewalker into a string

        :arg treewalker: the treewalker to serialize

        :arg encoding: the string encoding to use

        :returns: the serialized tree

        Example:

        >>> from html5lib import parse, getTreeWalker
        >>> from html5lib.serializer import HTMLSerializer
        >>> token_stream = parse('<html><body>Hi!</body></html>')
        >>> walker = getTreeWalker('etree')
        >>> serializer = HTMLSerializer(omit_optional_tags=False)
        >>> serializer.render(walker(token_stream))
        '<html><head></head><body>Hi!</body></html>'

        """
        if encoding:
            return b"".join(list(self.serialize(treewalker, encoding)))
        else:
            return "".join(list(self.serialize(treewalker)))

    def serializeAttributes(self, element_name, element_namespace, attributes,
                            namespace_stack):
        """Yield the serialized form of an element's attributes.

        HTML attributes keep their (already normalized) lower-case local
        name.  Attributes living in the SVG/MathML/xlink/xml namespaces are
        written with the prefix an HTML parser will map back onto the same
        namespace, so a serialize/reparse round trip cannot fold them onto a
        different attribute.  Namespaces the HTML parser cannot represent
        are reported and dropped instead of being folded onto another name.
        """
        # First pass: validate every local name and record namespace
        # declarations already carried by the tree.  The HTML parser only
        # knows how to map the xlink/xml/xmlns prefixes (plus the implicit
        # SVG/MathML element namespaces) back onto namespaces, so anything
        # else cannot be round-tripped and is rejected below instead of being
        # silently folded onto a different attribute.
        planned = []
        emitted_names = set()
        frame = {}
        namespace_stack.append(frame)
        # The in-scope mapping is the union of ancestor declarations and the
        # declarations carried by this element; frame shadows ancestors so a
        # local redeclaration is visible to this element's own attributes.
        declared_prefixes = {}
        for ancestor in namespace_stack[:-1]:
            declared_prefixes.update(ancestor)

        for (attr_namespace, attr_name), attr_value in attributes.items():
            if not self._isValidLocalName(attr_namespace, attr_name):
                self.serializeError(
                    "Dropping attribute with invalid local name: %r" %
                    ((attr_namespace, attr_name),))
                continue

            if attr_namespace == namespaces["xmlns"]:
                prefix = "" if attr_name == "xmlns" else attr_name
                frame[prefix] = attr_value
                declared_prefixes[prefix] = attr_value

        for (attr_namespace, attr_name), attr_value in attributes.items():
            if not self._isValidLocalName(attr_namespace, attr_name):
                continue

            output_name = self._attributeName(
                attr_namespace, attr_name, element_namespace,
                declared_prefixes)
            if output_name is None:
                continue

            folded = output_name.lower()
            if folded in emitted_names:
                # Two distinct DOM attributes would serialize to the same
                # token; the parser can only keep one, so refuse to choose.
                self.serializeError(
                    "Dropping duplicate attribute after serialization: %r" %
                    output_name)
                continue
            emitted_names.add(folded)
            planned.append((output_name, attr_namespace, attr_value))

        for output_name, attr_namespace, attr_value in planned:
            for chunk in self._writeAttribute(
                    output_name, attr_value, element_name,
                    strict_whitespace=attr_namespace is not None and
                    attr_namespace != namespaces["xmlns"]):
                yield chunk

    def _isValidLocalName(self, attr_namespace, attr_name):
        if not isinstance(attr_name, text_type) or not attr_name:
            return False
        if attr_namespace == namespaces["xmlns"]:
            return attr_name == "xmlns" or _localNameRegExp.match(attr_name) is not None
        if attr_namespace is None:
            # Unnamespaced names may legitimately contain a colon (the parser
            # exposes unknown "prefix:local" tokens verbatim); every other
            # markup-significant character is still rejected.
            return _unqualifiedNameRegExp.match(attr_name) is not None
        return _localNameRegExp.match(attr_name) is not None

    def _attributeName(self, attr_namespace, attr_name, element_namespace,
                       declared_prefixes):
        if attr_namespace is None:
            if element_namespace == namespaces["html"]:
                # HTML attribute names are ASCII case-insensitive; the parser
                # always exposes them in lower case.
                return attr_name.lower()
            return attr_name

        if attr_namespace == namespaces["xmlns"]:
            if attr_name == "xmlns":
                return "xmlns"
            return "xmlns:" + attr_name

        preferred = _namespacePrefixes.get(attr_namespace)
        if preferred is None or preferred == "xmlns":
            # HTML serialization has no way to declare an arbitrary
            # namespace: an HTML parser would treat the synthetic prefix as
            # an unknown attribute and fold it onto a different name, which
            # would enable namespace hijacking.  Refuse it instead.
            self.serializeError(
                "Dropping attribute in namespace that cannot be "
                "serialized as HTML: %r %r" % (attr_namespace, attr_name))
            return None

        existing = declared_prefixes.get(preferred)
        if existing is not None and existing != attr_namespace:
            # The canonical prefix is already bound to another URI in the
            # tree.  Emitting the prefixed name anyway would be interpreted
            # using the conflicting declaration, so report and drop it.
            self.serializeError(
                "Dropping attribute %r: prefix %r is already declared as %r" %
                (attr_name, preferred, existing))
            return None

        return preferred + ":" + attr_name

    def _writeAttribute(self, name, value, element_name,
                        strict_whitespace=False):
        yield self.encodeStrict(" ")
        yield self.encodeStrict(name)

        if not self.minimize_boolean_attributes or \
            (name not in booleanAttributes.get(element_name, tuple()) and
             name not in booleanAttributes.get("", tuple())):
            yield self.encodeStrict("=")

            if self.quote_attr_values == "always" or len(value) == 0:
                quote_attr = True
            elif self.quote_attr_values == "spec":
                quote_attr = _quoteAttributeSpec.search(value) is not None
            elif self.quote_attr_values == "legacy":
                quote_attr = _quoteAttributeLegacy.search(value) is not None
            else:
                raise ValueError("quote_attr_values must be one of: "
                                 "'always', 'spec', or 'legacy'")
            if strict_whitespace and ("\r" in value or "\x00" in value):
                # These code points only round trip when written as
                # character references, which requires a quoted value.
                quote_attr = True

            value = self._escapeAttributeValue(
                value, quote_attr and strict_whitespace)
            if quote_attr:
                quote_char = self.quote_char
                if self.use_best_quote_char:
                    if "'" in value and '"' not in value:
                        quote_char = '"'
                    elif '"' in value and "'" not in value:
                        quote_char = "'"
                if quote_char == "'":
                    value = value.replace("'", "&#39;")
                else:
                    value = value.replace('"', "&quot;")
                yield self.encodeStrict(quote_char)
                yield self.encode(value)
                yield self.encodeStrict(quote_char)
            else:
                yield self.encode(value)

    def _escapeAttributeValue(self, value, escape_whitespace):
        # "&" must always be escaped first so later escapes are not doubled.
        value = value.replace("&", "&amp;")
        if self.escape_lt_in_attrs:
            value = value.replace("<", "&lt;")
        if escape_whitespace:
            # CR is normalized to LF while tokenizing quoted attribute
            # values; only the character reference survives a round trip.
            # U+0000 is replaced by U+FFFD on reparse unless it is escaped.
            value = value.replace("\r", "&#13;")
            value = value.replace("\x00", "&#0;")
        return value

    def serializeError(self, data="XXX ERROR MESSAGE NEEDED"):
        # XXX The idea is to make data mandatory.
        self.errors.append(data)
        if self.strict:
            raise SerializeError


class SerializeError(Exception):
    """Error in serialized tree"""
    pass
