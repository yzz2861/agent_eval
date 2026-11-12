from itertools import chain
import re
import warnings

from xml.sax.saxutils import unescape

from bleach import html5lib_shim
from bleach import parse_shim


#: Set of allowed tags
ALLOWED_TAGS = frozenset(
    (
        "a",
        "abbr",
        "acronym",
        "b",
        "blockquote",
        "code",
        "em",
        "i",
        "li",
        "ol",
        "strong",
        "ul",
    )
)


#: Map of allowed attributes by tag
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "abbr": ["title"],
    "acronym": ["title"],
}

#: Set of allowed protocols
ALLOWED_PROTOCOLS = frozenset(("http", "https", "mailto"))

#: Namespaces that bleach recognizes when comparing SVG tags and attributes
SVG_NAMESPACE = html5lib_shim.namespaces["svg"]
XLINK_NAMESPACE = html5lib_shim.namespaces["xlink"]
XML_NAMESPACE = html5lib_shim.namespaces["xml"]
XMLNS_NAMESPACE = html5lib_shim.namespaces["xmlns"]

#: Safe SVG subset--geometry, paths, text, gradients and basic presentation.
#:
#: ``script``, ``foreignObject``, animation elements (``animate``,
#: ``animateMotion``, ``animateTransform``, ``set`` ...), remote-loading
#: elements (``image``, ``audio``, ``video``, ``iframe`` ...) and filter
#: primitives are intentionally excluded.
ALLOWED_SVG_TAGS = frozenset(
    (
        "svg",
        "g",
        "defs",
        "desc",
        "title",
        "symbol",
        "use",
        "circle",
        "ellipse",
        "line",
        "path",
        "polygon",
        "polyline",
        "rect",
        "text",
        "tspan",
        "textPath",
        "linearGradient",
        "radialGradient",
        "stop",
        "clipPath",
        "mask",
        "pattern",
        "marker",
        "view",
    )
)

#: Attributes allowed on safe SVG elements, keyed by namespace.
#:
#: Namespaced names are compared exactly so prefix tricks can't smuggle
#: attributes in. Event handler attributes (``on*``), ``style`` element
#: embedding and remote-loading attributes such as ``filter`` are excluded.
ALLOWED_SVG_ATTRIBUTES = frozenset(
    (
        # core / structural
        (None, "id"),
        (None, "class"),
        (None, "lang"),
        (None, "tabindex"),
        (None, "role"),
        (None, "focusable"),
        (None, "contentStyleType"),
        (None, "contentScriptType"),
        (None, "viewBox"),
        (None, "preserveAspectRatio"),
        (None, "version"),
        (None, "width"),
        (None, "height"),
        (None, "x"),
        (None, "y"),
        (None, "x1"),
        (None, "y1"),
        (None, "x2"),
        (None, "y2"),
        (None, "cx"),
        (None, "cy"),
        (None, "r"),
        (None, "rx"),
        (None, "ry"),
        (None, "d"),
        (None, "points"),
        (None, "pathLength"),
        (None, "offset"),
        (None, "gradientUnits"),
        (None, "gradientTransform"),
        (None, "patternUnits"),
        (None, "patternContentUnits"),
        (None, "patternTransform"),
        (None, "clipPathUnits"),
        (None, "markerUnits"),
        (None, "markerWidth"),
        (None, "markerHeight"),
        (None, "refX"),
        (None, "refY"),
        (None, "orient"),
        (None, "spreadMethod"),
        (None, "href"),
        (None, "transform"),
        (None, "systemLanguage"),
        (None, "text-anchor"),
        (None, "text-decoration"),
        (None, "text-rendering"),
        (None, "textLength"),
        (None, "lengthAdjust"),
        (None, "startOffset"),
        (None, "font-family"),
        (None, "font-size"),
        (None, "font-size-adjust"),
        (None, "font-stretch"),
        (None, "font-style"),
        (None, "font-variant"),
        (None, "font-weight"),
        (None, "direction"),
        (None, "unicode-bidi"),
        (None, "dominant-baseline"),
        (None, "alignment-baseline"),
        (None, "baseline-shift"),
        (None, "letter-spacing"),
        (None, "word-spacing"),
        (None, "writing-mode"),
        (None, "overflow"),
        (None, "clip-rule"),
        (None, "clip-path"),
        (None, "fill-rule"),
        (None, "opacity"),
        (None, "fill"),
        (None, "fill-opacity"),
        (None, "stroke"),
        (None, "stroke-dasharray"),
        (None, "stroke-dashoffset"),
        (None, "stroke-linecap"),
        (None, "stroke-linejoin"),
        (None, "stroke-miterlimit"),
        (None, "stroke-opacity"),
        (None, "stroke-width"),
        (None, "color"),
        (None, "cursor"),
        (None, "display"),
        (None, "visibility"),
        (None, "stop-color"),
        (None, "stop-opacity"),
        (None, "style"),
        # xlink--only local fragment references survive value sanitizing
        (XLINK_NAMESPACE, "href"),
        (XLINK_NAMESPACE, "title"),
        (XLINK_NAMESPACE, "role"),
        # xml
        (XML_NAMESPACE, "lang"),
        (XML_NAMESPACE, "space"),
    )
)

#: SVG elements allowed to carry ``href``/``xlink:href``; in safe mode these
#: only accept same-document fragment references (``#fragment``).
SVG_LOCAL_HREF_TAGS = frozenset(("use", "lineargradient", "radialgradient"))

#: Matches a same-document fragment reference after surrounding whitespace
SVG_LOCAL_HREF_RE = re.compile(r"^\s*#")

#: Disallowed SVG elements whose entire subtree--including the raw text the
#: HTML tokenizer exposes as Characters tokens--is dropped. This covers script
#: bodies, embedded style sheets and HTML embedded through foreignObject, none
#: of which may survive even as inert text.
SVG_DROP_SUBTREE_TAGS = frozenset(
    (
        "script",
        "style",
        "foreignobject",
    )
)

#: Matches the opening of an SVG CSS/IRI ``url(`` reference
SVG_URL_OPEN_RE = re.compile(r"url\s*\(", re.IGNORECASE)

#: Collapses runs of whitespace left behind after IRI cleaning
SVG_WHITESPACE_RE = re.compile(r"\s+")

#: Invisible characters--0 to and including 31 except 9 (tab), 10 (lf), and 13 (cr)
INVISIBLE_CHARACTERS = "".join(
    [chr(c) for c in chain(range(0, 9), range(11, 13), range(14, 32))]
)

#: Regexp for characters that are invisible
INVISIBLE_CHARACTERS_RE = re.compile("[" + INVISIBLE_CHARACTERS + "]", re.UNICODE)

#: String to replace invisible characters with. This can be a character, a
#: string, or even a function that takes a Python re matchobj
INVISIBLE_REPLACEMENT_CHAR = "?"


class NoCssSanitizerWarning(UserWarning):
    pass


class Cleaner:
    """Cleaner for cleaning HTML fragments of malicious content

    This cleaner is a security-focused function whose sole purpose is to remove
    malicious content from a string such that it can be displayed as content in
    a web page.

    To use::

        from bleach.sanitizer import Cleaner

        cleaner = Cleaner()

        for text in all_the_yucky_things:
            sanitized = cleaner.clean(text)

    .. Note::

       This cleaner is not designed to use to transform content to be used in
       non-web-page contexts.

    .. Warning::

       This cleaner is not thread-safe--the html parser has internal state.
       Create a separate cleaner per thread!


    """

    def __init__(
        self,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=False,
        strip_comments=True,
        filters=None,
        css_sanitizer=None,
        svg=False,
    ):
        """Initializes a Cleaner

        :arg set tags: set of allowed tags; defaults to
            ``bleach.sanitizer.ALLOWED_TAGS``

        :arg dict attributes: allowed attributes; can be a callable, list or dict;
            defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

        :arg set protocols: set of allowed protocols for links; defaults
            to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

        :arg bool strip: whether or not to strip disallowed elements

        :arg bool strip_comments: whether or not to strip HTML comments

        :arg list filters: list of html5lib Filter classes to pass streamed content through

            .. seealso:: http://html5lib.readthedocs.io/en/latest/movingparts.html#filters

            .. Warning::

               Using filters changes the output of ``bleach.Cleaner.clean``.
               Make sure the way the filters change the output are secure.

        :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
            sanitizing style attribute values and style text; defaults to None

        :arg bool svg: whether or not to enable the explicit SVG safe subset
            mode. When enabled, SVG namespace tags and attributes are compared
            by namespace against ``ALLOWED_SVG_TAGS`` and
            ``ALLOWED_SVG_ATTRIBUTES``; ``script``, ``foreignObject``,
            animation elements, event handler attributes, external
            ``href``/``xlink:href`` references and dangerous filters are
            removed. This is opt-in--the default ``False`` preserves the
            pure-HTML cleaning behavior.

        """
        self.tags = tags
        self.attributes = attributes
        self.protocols = protocols
        self.strip = strip
        self.strip_comments = strip_comments
        self.filters = filters or []
        self.css_sanitizer = css_sanitizer
        self.svg = svg

        # The tokenizer converts any tag not in this set into characters
        # before the sanitizer filter runs, so in SVG mode the SVG subset
        # has to be visible to the parser. Namespace-based policy is still
        # enforced by BleachSanitizerFilter--this only keeps the tokens alive.
        parser_tags = self.tags
        if svg:
            parser_tags = frozenset(self.tags) | frozenset(ALLOWED_SVG_TAGS)

        self.parser = html5lib_shim.BleachHTMLParser(
            tags=parser_tags,
            strip=self.strip,
            consume_entities=False,
            namespaceHTMLElements=False,
            svg=svg,
        )
        self.walker = html5lib_shim.getTreeWalker("etree")
        serializer_class = (
            html5lib_shim.BleachSVGSerializer
            if svg
            else html5lib_shim.BleachHTMLSerializer
        )
        self.serializer = serializer_class(
            quote_attr_values="always",
            omit_optional_tags=False,
            escape_lt_in_attrs=True,
            # We want to leave entities as they are without escaping or
            # resolving or expanding
            resolve_entities=False,
            # Bleach has its own sanitizer, so don't use the html5lib one
            sanitize=False,
            # clean preserves attr order
            alphabetical_attributes=False,
        )

        if css_sanitizer is None:
            # FIXME(willkg): this doesn't handle when attributes or an
            # attributes value is a callable
            attributes_values = []
            if isinstance(attributes, list):
                attributes_values = attributes

            elif isinstance(attributes, dict):
                attributes_values = []
                for values in attributes.values():
                    if isinstance(values, (list, tuple)):
                        attributes_values.extend(values)

            if "style" in attributes_values:
                warnings.warn(
                    "'style' attribute specified, but css_sanitizer not set.",
                    category=NoCssSanitizerWarning,
                )

    def clean(self, text):
        """Cleans text and returns sanitized result as unicode

        :arg str text: text to be cleaned

        :returns: sanitized text as unicode

        :raises TypeError: if ``text`` is not a text type

        """
        if not isinstance(text, str):
            message = (
                f"argument cannot be of {text.__class__.__name__!r} type, "
                + "must be of text type"
            )
            raise TypeError(message)

        if not text:
            return ""

        dom = self.parser.parseFragment(text)
        filtered = BleachSanitizerFilter(
            source=self.walker(dom),
            allowed_tags=self.tags,
            attributes=self.attributes,
            strip_disallowed_tags=self.strip,
            strip_html_comments=self.strip_comments,
            css_sanitizer=self.css_sanitizer,
            allowed_protocols=self.protocols,
            svg=self.svg,
        )

        # Apply any filters after the BleachSanitizerFilter
        for filter_class in self.filters:
            filtered = filter_class(source=filtered)

        return self.serializer.render(filtered)


def attribute_filter_factory(attributes):
    """Generates attribute filter function for the given attributes value

    The attributes value can take one of several shapes. This returns a filter
    function appropriate to the attributes value. One nice thing about this is
    that there's less if/then shenanigans in the ``allow_token`` method.

    """
    if callable(attributes):
        return attributes

    if isinstance(attributes, dict):

        def _attr_filter(tag, attr, value):
            if tag in attributes:
                attr_val = attributes[tag]
                if callable(attr_val):
                    return attr_val(tag, attr, value)

                if attr in attr_val:
                    return True

            if "*" in attributes:
                attr_val = attributes["*"]
                if callable(attr_val):
                    return attr_val(tag, attr, value)

                return attr in attr_val

            return False

        return _attr_filter

    if isinstance(attributes, list):

        def _attr_filter(tag, attr, value):
            return attr in attributes

        return _attr_filter

    raise ValueError("attributes needs to be a callable, a list or a dict")


class BleachSanitizerFilter(html5lib_shim.SanitizerFilter):
    """html5lib Filter that sanitizes text

    This filter can be used anywhere html5lib filters can be used.

    """

    def __init__(
        self,
        source,
        allowed_tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        allowed_protocols=ALLOWED_PROTOCOLS,
        attr_val_is_uri=html5lib_shim.attr_val_is_uri,
        svg_attr_val_allows_ref=html5lib_shim.svg_attr_val_allows_ref,
        svg_allow_local_href=html5lib_shim.svg_allow_local_href,
        strip_disallowed_tags=False,
        strip_html_comments=True,
        css_sanitizer=None,
        svg=False,
    ):
        """Creates a BleachSanitizerFilter instance

        :arg source: html5lib TreeWalker stream as an html5lib TreeWalker

        :arg set allowed_tags: set of allowed tags; defaults to
            ``bleach.sanitizer.ALLOWED_TAGS``

        :arg dict attributes: allowed attributes; can be a callable, list or dict;
            defaults to ``bleach.sanitizer.ALLOWED_ATTRIBUTES``

        :arg set allowed_protocols: set of allowed protocols for links; defaults
            to ``bleach.sanitizer.ALLOWED_PROTOCOLS``

        :arg attr_val_is_uri: set of attributes that have URI values

        :arg svg_attr_val_allows_ref: set of SVG attributes that can have
            references

        :arg svg_allow_local_href: set of SVG elements that can have local
            hrefs

        :arg bool strip_disallowed_tags: whether or not to strip disallowed
            tags

        :arg bool strip_html_comments: whether or not to strip HTML comments

        :arg CSSSanitizer css_sanitizer: instance with a "sanitize_css" method for
            sanitizing style attribute values and style text; defaults to None

        :arg bool svg: whether or not the explicit SVG safe subset is enabled.
            When True, SVG namespace tags and attributes are matched by
            namespace against the SVG allowlists instead of the HTML tag
            name based policy.

        """
        # NOTE(willkg): This is the superclass of
        # html5lib.filters.sanitizer.Filter. We call this directly skipping the
        # __init__ for html5lib.filters.sanitizer.Filter because that does
        # things we don't need to do and kicks up the deprecation warning for
        # using Sanitizer.
        html5lib_shim.Filter.__init__(self, source)

        self.allowed_tags = frozenset(allowed_tags)
        self.allowed_protocols = frozenset(allowed_protocols)

        self.attr_filter = attribute_filter_factory(attributes)
        self.strip_disallowed_tags = strip_disallowed_tags
        self.strip_html_comments = strip_html_comments

        self.attr_val_is_uri = attr_val_is_uri
        self.svg_attr_val_allows_ref = svg_attr_val_allows_ref
        self.css_sanitizer = css_sanitizer
        self.svg_allow_local_href = svg_allow_local_href
        self.svg = svg

        if svg:
            self.allowed_svg_tags = frozenset(
                tag.lower() for tag in ALLOWED_SVG_TAGS
            )
            # Attribute local names stored lowercased so case variants can't
            # bypass the policy; the namespace part of the tuple is compared
            # exactly.
            self.allowed_svg_attributes = frozenset(
                (namespace, name.lower())
                for namespace, name in ALLOWED_SVG_ATTRIBUTES
            )

    def sanitize_stream(self, token_iterator):
        # Depth of open subtrees rooted at a disallowed SVG element
        # (script, style, foreignObject ...). The tokenizer turns rawtext
        # contents into Characters tokens, so the element and everything below
        # it have to be swallowed together.
        drop_depth = 0

        for token in token_iterator:
            token_type = token.get("type")

            if self.svg and drop_depth:
                if token_type == "StartTag":
                    drop_depth += 1
                elif token_type == "EndTag":
                    drop_depth -= 1
                continue

            if (
                self.svg
                and token_type in ("StartTag", "EmptyTag")
                and token.get("namespace") == SVG_NAMESPACE
                and token.get("name", "").lower() in SVG_DROP_SUBTREE_TAGS
            ):
                if token_type == "StartTag":
                    drop_depth = 1
                continue

            ret = self.sanitize_token(token)

            if not ret:
                continue

            if isinstance(ret, list):
                yield from ret
            else:
                yield ret

    def merge_characters(self, token_iterator):
        """Merge consecutive Characters tokens in a stream"""
        characters_buffer = []

        for token in token_iterator:
            if characters_buffer:
                if token["type"] == "Characters":
                    characters_buffer.append(token)
                    continue
                else:
                    # Merge all the characters tokens together into one and then
                    # operate on it.
                    new_token = {
                        "data": "".join(
                            [char_token["data"] for char_token in characters_buffer]
                        ),
                        "type": "Characters",
                    }
                    characters_buffer = []
                    yield new_token

            elif token["type"] == "Characters":
                characters_buffer.append(token)
                continue

            yield token

        new_token = {
            "data": "".join([char_token["data"] for char_token in characters_buffer]),
            "type": "Characters",
        }
        yield new_token

    def __iter__(self):
        return self.merge_characters(
            self.sanitize_stream(html5lib_shim.Filter.__iter__(self))
        )

    def sanitize_token(self, token):
        """Sanitize a token either by HTML-encoding or dropping.

        Unlike sanitizer.Filter, allowed_attributes can be a dict of {'tag':
        ['attribute', 'pairs'], 'tag': callable}.

        Here callable is a function with two arguments of attribute name and
        value. It should return true of false.

        Also gives the option to strip tags instead of encoding.

        :arg dict token: token to sanitize

        :returns: token or list of tokens

        """
        token_type = token["type"]
        if token_type in ["StartTag", "EndTag", "EmptyTag"]:
            if self.svg and token.get("namespace") == SVG_NAMESPACE:
                if token["name"].lower() in self.allowed_svg_tags:
                    return self.allow_svg_token(token)

                # Disallowed SVG elements (script, foreignObject, animation
                # and filter primitives, remote loaders ...) are always
                # unwrapped rather than HTML-escaped: escaping would leave
                # the tag text inside the graphic and re-parsing would not
                # round-trip it as XML. Descendants keep going through the
                # policy, so active content can't survive inside them.
                return None

            if token["name"] in self.allowed_tags:
                return self.allow_token(token)

            elif self.strip_disallowed_tags:
                return None

            else:
                return self.disallowed_token(token)

        elif token_type == "Comment":
            if not self.strip_html_comments:
                # call lxml.sax.saxutils to escape &, <, and > in addition to " and '
                token["data"] = html5lib_shim.escape(
                    token["data"], entities={'"': "&quot;", "'": "&#x27;"}
                )
                return token
            else:
                return None

        elif token_type == "Characters":
            return self.sanitize_characters(token)

        else:
            return token

    def sanitize_characters(self, token):
        """Handles Characters tokens

        Our overridden tokenizer doesn't do anything with entities. However,
        that means that the serializer will convert all ``&`` in Characters
        tokens to ``&amp;``.

        Since we don't want that, we extract entities here and convert them to
        Entity tokens so the serializer will let them be.

        :arg token: the Characters token to work on

        :returns: a list of tokens

        """
        data = token.get("data", "")

        if not data:
            return token

        data = INVISIBLE_CHARACTERS_RE.sub(INVISIBLE_REPLACEMENT_CHAR, data)
        token["data"] = data

        # If there isn't a & in the data, we can return now
        if "&" not in data:
            return token

        new_tokens = []

        # For each possible entity that starts with a "&", we try to extract an
        # actual entity and re-tokenize accordingly
        for part in html5lib_shim.next_possible_entity(data):
            if not part:
                continue

            if part.startswith("&"):
                entity = html5lib_shim.match_entity(part)
                if entity is not None:
                    if entity == "amp":
                        # LinkifyFilter can't match urls across token boundaries
                        # which is problematic with &amp; since that shows up in
                        # querystrings all the time. This special-cases &amp;
                        # and converts it to a & and sticks it in as a
                        # Characters token. It'll get merged with surrounding
                        # tokens in the BleachSanitizerfilter.__iter__ and
                        # escaped in the serializer.
                        new_tokens.append({"type": "Characters", "data": "&"})
                    else:
                        new_tokens.append({"type": "Entity", "name": entity})

                    # Length of the entity plus 2--one for & at the beginning
                    # and one for ; at the end
                    remainder = part[len(entity) + 2 :]
                    if remainder:
                        new_tokens.append({"type": "Characters", "data": remainder})
                    continue

            new_tokens.append({"type": "Characters", "data": part})

        return new_tokens

    def sanitize_uri_value(self, value, allowed_protocols):
        """Checks a uri value to see if it's allowed

        :arg value: the uri value to sanitize
        :arg allowed_protocols: set of allowed protocols

        :returns: allowed value or None

        """
        # NOTE(willkg): This transforms the value into a normalized one that's
        # easier to match and verify, but shouldn't get returned since it's
        # vastly different than the original value.

        # Convert all character entities in the value
        normalized_uri = html5lib_shim.convert_entities(value)

        # Strip backtick, whitespace, and control characters
        normalized_uri = re.sub(r"[`\000-\040\177-\240\s]+", "", normalized_uri)

        # Strip non-ASCII characters so that urlparse can parse the url into
        # components correctly. This drops invisible and whitespace unicode
        # characters among other things.
        normalized_uri = re.sub(r"[^\x00-\x7f]", "", normalized_uri)

        # Lowercase value to make matching easier
        normalized_uri = normalized_uri.lower()

        try:
            # Drop attributes with uri values that have protocols that aren't
            # allowed
            parsed = parse_shim.urlparse(normalized_uri)
        except ValueError:
            # URI is impossible to parse, therefore it's not allowed
            return None

        if parsed.scheme:
            # If urlparse found a scheme, check that
            if parsed.scheme in allowed_protocols:
                return value

        else:
            # Allow uris that are just an anchor
            if normalized_uri.startswith("#"):
                return value

            # Handle protocols that urlparse doesn't recognize like "myprotocol"
            if (
                ":" in normalized_uri
                and normalized_uri.split(":")[0] in allowed_protocols
            ):
                return value

            # If there's no protocol/scheme specified, then assume it's "http" or
            # "https" and see if that's allowed
            if "http" in allowed_protocols or "https" in allowed_protocols:
                return value

        return None

    def sanitize_svg_style(self, value):
        """Sanitizes an SVG ``style`` attribute value

        Runs the value through the configured CSS sanitizer (which limits the
        declaration to an allowlist of properties) and additionally strips
        any ``url(...)`` reference that isn't a same-document fragment, since
        a CSS URL can load remote active content even when the property itself
        is benign.

        """
        if self.css_sanitizer:
            value = self.css_sanitizer.sanitize_css(value)
        else:
            # No CSS sanitizer configured--the style can't be verified, so
            # drop it rather than letting arbitrary CSS through.
            return ""

        if not value:
            return ""

        # Remove every non-fragment url() reference. Fragment references such
        # as url(#clip) are left intact.
        return self.sanitize_svg_iri(value)

    def sanitize_svg_iri(self, value):
        """Sanitizes an SVG presentation attribute that may hold IRIs

        Fragment references such as ``url(#clip)`` are preserved. Any
        ``url(...)`` pointing elsewhere--including ``javascript:``,
        ``data:`` or remote ``http(s)`` URLs--is removed together with its
        wrapping ``url(...)`` so the remainder stays valid SVG. Non-IRI
        keywords and colors are untouched.

        :returns: cleaned value, or None when nothing safe remains

        """
        cleaned_parts = []
        remainder = unescape(value)

        while True:
            match = SVG_URL_OPEN_RE.search(remainder)
            if not match:
                cleaned_parts.append(remainder)
                break

            cleaned_parts.append(remainder[: match.start()])
            depth = 0
            end = None
            tail = remainder[match.start() :]
            for index, char in enumerate(tail, start=match.start()):
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break

            if end is None:
                # Unbalanced url( ... --nothing after it is trustworthy.
                break

            reference = remainder[match.end() : end - 1].strip()
            if reference.startswith("#"):
                cleaned_parts.append(remainder[match.start() : end])
            else:
                cleaned_parts.append(" ")
            remainder = remainder[end:]

        cleaned = "".join(cleaned_parts)
        cleaned = SVG_WHITESPACE_RE.sub(" ", cleaned).strip()
        return cleaned or None

    def allow_svg_token(self, token):
        """Handles an allowed SVG namespace tag

        Tags and attributes are compared by namespace, not by prefix, so
        duplicate namespace declarations and prefix or case variants can't
        bypass the policy. Allowed URI-valued attributes still go through the
        protocol and local-reference checks.

        """
        if "data" not in token:
            return token

        attrs = {}
        tag = token["name"].lower()

        for namespaced_name, val in token["data"].items():
            namespace, name = namespaced_name

            # Namespace declarations are rewritten by the serializer--never
            # trust user-supplied ones.
            if namespace == XMLNS_NAMESPACE:
                continue

            # Compare on the exact (namespace, lowercased local name) tuple.
            # Event handler attributes (on*) are not on the allowlist, but
            # reject them explicitly so casing tricks can never sneak one in.
            normalized_name = name.lower()
            if normalized_name.startswith("on"):
                continue

            if (namespace, normalized_name) not in self.allowed_svg_attributes:
                continue

            # href / xlink:href on the elements that may carry them only
            # accept same-document fragment references. Everything else--
            # http(s), data:, javascript:, relative paths--is dropped.
            if normalized_name == "href" and (
                namespace is None or namespace == XLINK_NAMESPACE
            ):
                if tag not in SVG_LOCAL_HREF_TAGS:
                    continue
                if not SVG_LOCAL_HREF_RE.match(val):
                    continue

            # Presentation attributes that take an IRI reference: drop the
            # attribute when it contains a non-fragment url() reference.
            if namespaced_name in self.svg_attr_val_allows_ref:
                new_val = self.sanitize_svg_iri(val)
                if new_val is None:
                    continue
                val = new_val

            # Any other URI-valued attribute still goes through the protocol
            # allowlist cleaning.
            if namespaced_name in self.attr_val_is_uri:
                new_value = self.sanitize_uri_value(val, self.allowed_protocols)
                if new_value is None:
                    continue
                val = new_value

            if namespaced_name == (None, "style"):
                val = self.sanitize_svg_style(val)
                if not val:
                    continue

            attrs[namespaced_name] = val

        token["data"] = attrs
        return token

    def allow_token(self, token):
        """Handles the case where we're allowing the tag"""
        if "data" in token:
            # Loop through all the attributes and drop the ones that are not
            # allowed, are unsafe or break other rules. Additionally, fix
            # attribute values that need fixing.
            #
            # At the end of this loop, we have the final set of attributes
            # we're keeping.
            attrs = {}
            for namespaced_name, val in token["data"].items():
                namespace, name = namespaced_name

                # Drop attributes that are not explicitly allowed
                #
                # NOTE(willkg): We pass in the attribute name--not a namespaced
                # name.
                if not self.attr_filter(token["name"], name, val):
                    continue

                # Drop attributes with uri values that use a disallowed protocol
                # Sanitize attributes with uri values
                if namespaced_name in self.attr_val_is_uri:
                    new_value = self.sanitize_uri_value(val, self.allowed_protocols)
                    if new_value is None:
                        continue
                    val = new_value

                # Drop values in svg attrs with non-local IRIs
                if namespaced_name in self.svg_attr_val_allows_ref:
                    new_val = re.sub(r"url\s*\(\s*[^#\s][^)]+?\)", " ", unescape(val))
                    new_val = new_val.strip()
                    if not new_val:
                        continue

                    else:
                        # Replace the val with the unescaped version because
                        # it's a iri
                        val = new_val

                # Drop href and xlink:href attr for svg elements with non-local IRIs
                if (None, token["name"]) in self.svg_allow_local_href:
                    if namespaced_name in [
                        (None, "href"),
                        (html5lib_shim.namespaces["xlink"], "href"),
                    ]:
                        if re.search(r"^\s*[^#\s]", val):
                            continue

                # If it's a style attribute, sanitize it
                if namespaced_name == (None, "style"):
                    if self.css_sanitizer:
                        val = self.css_sanitizer.sanitize_css(val)
                    else:
                        # FIXME(willkg): if style is allowed, but no
                        # css_sanitizer was set up, then this is probably a
                        # mistake and we should raise an error here
                        #
                        # For now, we're going to set the value to "" because
                        # there was no sanitizer set
                        val = ""

                # At this point, we want to keep the attribute, so add it in
                attrs[namespaced_name] = val

            token["data"] = attrs

        return token

    def disallowed_token(self, token):
        token_type = token["type"]
        if token_type == "EndTag":
            token["data"] = f"</{token['name']}>"

        elif token["data"]:
            assert token_type in ("StartTag", "EmptyTag")
            attrs = []
            for (ns, name), v in token["data"].items():
                # If we end up with a namespace, but no name, switch them so we
                # have a valid name to use.
                if ns and not name:
                    ns, name = name, ns

                # Figure out namespaced name if the namespace is appropriate
                # and exists; if the ns isn't in prefixes, then drop it.
                if ns is None or ns not in html5lib_shim.prefixes:
                    namespaced_name = name
                else:
                    namespaced_name = f"{html5lib_shim.prefixes[ns]}:{name}"

                # NOTE(willkg): HTMLSerializer escapes attribute values
                # already, so if we do it here (like HTMLSerializer does),
                # then we end up double-escaping.
                attrs.append(f' {namespaced_name}="{v}"')
            token["data"] = f"<{token['name']}{''.join(attrs)}>"

        else:
            token["data"] = f"<{token['name']}>"

        if token.get("selfClosing"):
            token["data"] = f"{token['data'][:-1]}/>"

        token["type"] = "Characters"

        del token["name"]
        return token
