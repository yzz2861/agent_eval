"""CSS sanitizer for ``style`` attribute values.

The sanitizer works on the token stream produced by tinycss2.  Before any
policy decision is made, the input is normalized so that the two parser
features that can be used to hide a dangerous token are taken into account:

* CSS identifier escapes (``u\\72l`` is the identifier ``url``) are decoded
  by tinycss2 while tokenizing.  Policy checks always use the decoded,
  lower-cased token names instead of the raw source text.
* Comments do not exist as CSS tokens with any semantics, but they can split
  an identifier into adjacent tokens (``ur/**/l(...)``).  Comments are
  removed at the source level and the remaining text is re-parsed, so a
  token hidden behind a comment boundary is evaluated exactly as a browser
  would see it.

Only declaration tokens for explicitly allowed properties can survive.  At
  rules (``@import``, ``@font-face``, ``@supports`` and friends) and parse
  errors are always dropped instead of being passed through as unknown
  tokens.
"""

import tinycss2


ALLOWED_CSS_PROPERTIES = frozenset(
    (
        "azimuth",
        "background-color",
        "border-bottom-color",
        "border-collapse",
        "border-color",
        "border-left-color",
        "border-right-color",
        "border-top-color",
        "clear",
        "color",
        "cursor",
        "direction",
        "display",
        "elevation",
        "float",
        "font",
        "font-family",
        "font-size",
        "font-style",
        "font-variant",
        "font-weight",
        "height",
        "letter-spacing",
        "line-height",
        "overflow",
        "pause",
        "pause-after",
        "pause-before",
        "pitch",
        "pitch-range",
        "richness",
        "speak",
        "speak-header",
        "speak-numeral",
        "speak-punctuation",
        "speech-rate",
        "stress",
        "text-align",
        "text-decoration",
        "text-indent",
        "unicode-bidi",
        "vertical-align",
        "voice-family",
        "volume",
        "white-space",
        "width",
    )
)


ALLOWED_SVG_PROPERTIES = frozenset(
    (
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-opacity",
    )
)


# Functions that never fetch a resource and only compute values from the
# arguments the author already provided.  Anything outside of this list is
# rejected, including unknown functions, so that newly specified resource
# functions cannot slip through as generic tokens.
ALLOWED_FUNCTIONS = frozenset(
    (
        "rgb",
        "rgba",
        "hsl",
        "hsla",
        "hwb",
        "lab",
        "lch",
        "oklab",
        "oklch",
        "color",
        "color-mix",
        "calc",
        "min",
        "max",
        "clamp",
        "cubic-bezier",
        "steps",
        "blur",
        "brightness",
        "contrast",
        "drop-shadow",
        "grayscale",
        "hue-rotate",
        "invert",
        "opacity",
        "saturate",
        "sepia",
    )
)


# Functions whose arguments name an external resource that the user agent
# would fetch.  They are rejected unless the sanitizer was configured with a
# URL policy that explicitly accepts every URL referenced by the function.
RESOURCE_FUNCTIONS = frozenset(
    (
        "url",
        "src",
        "image",
        "image-set",
        "cross-fade",
        "element",
        "paint",
        "cursor",
    )
)


# At-rules can pull in external style sheets and fonts or change the meaning
# of the surrounding rules.  ``style`` attribute values are a declaration
# list, so every at-rule is dropped by default and an empty allow list keeps
# it that way.
DEFAULT_ALLOWED_AT_RULES = frozenset()


def _strip_comments(style):
    """Removes CSS comments without touching comments inside strings.

    tinycss2 emits comment tokens based on the real CSS grammar, so string
    contents that merely look like comments are left alone.  Removing the
    comment tokens and re-serializing also removes unterminated comments,
    because tinycss2 only emits a comment for a closed ``/* ... */`` pair.
    """
    tokens = tinycss2.parse_component_value_list(style)
    return "".join(token.serialize() for token in tokens if token.type != "comment")


class URLPolicy:
    """Policy object deciding which ``url()`` references may survive.

    By default no URL is accepted.  When *allowed_protocols* is configured,
    a URL is only kept when it uses one of those schemes (or is a
    document-local fragment reference) and is no longer than
    *max_url_length*.

    A custom policy may be any callable taking the URL text and returning
    the URL to serialize, or ``None`` to reject it.
    """

    def __init__(
        self,
        allowed_protocols=frozenset(),
        max_url_length=2150,
        allow_relative=False,
    ):
        self.allowed_protocols = frozenset(
            protocol.lower().strip(":") for protocol in allowed_protocols
        )
        self.max_url_length = max_url_length
        self.allow_relative = allow_relative

    def __call__(self, url):
        url = url.strip()
        if not url or len(url) > self.max_url_length:
            return None

        if url.startswith("#"):
            return url

        head = url.split(":", 1)[0].lower()
        if "/" in head or "?" in head or "=" in head or head == url.lower():
            # There is no scheme before the first colon: the reference is
            # relative (possibly containing a colon in a path segment).
            if not self.allow_relative:
                return None
        elif head not in self.allowed_protocols:
            return None

        return url


class CSSSanitizer:
    def __init__(
        self,
        allowed_css_properties=ALLOWED_CSS_PROPERTIES,
        allowed_svg_properties=ALLOWED_SVG_PROPERTIES,
        allowed_at_rules=DEFAULT_ALLOWED_AT_RULES,
        url_policy=None,
    ):
        self.allowed_css_properties = allowed_css_properties
        self.allowed_svg_properties = allowed_svg_properties
        self.allowed_at_rules = frozenset(
            at_rule.lower() for at_rule in allowed_at_rules
        )
        self.url_policy = url_policy

    def sanitize_css(self, style):
        """Sanitizes css in style tags"""
        if not style:
            return ""

        # Remove comments first and parse the resulting text again so that a
        # comment can no longer split an identifier or at-keyword past the
        # policy checks below.
        normalized = _strip_comments(style)
        parsed = tinycss2.parse_declaration_list(normalized)

        sanitized_declarations = []
        for token in parsed:
            if token.type != "declaration":
                # At-rule, parse error, comment and whitespace tokens are
                # never emitted.  Whitespace between kept declarations is
                # re-created deterministically during serialization, so
                # dropping it here cannot merge two tokens into a new one.
                continue

            property_name = token.lower_name
            if (
                property_name not in self.allowed_css_properties
                and property_name not in self.allowed_svg_properties
            ):
                continue

            if not self._tokens_are_safe(token.value):
                continue

            sanitized_declarations.append(token.serialize())

        if not sanitized_declarations:
            return ""

        return "; ".join(sanitized_declarations) + ";"

    def _tokens_are_safe(self, tokens):
        """Recursively validates a flat list of tinycss2 tokens."""
        previous = None
        for token in tokens:
            if token.type == "error":
                return False

            if token.type == "ident" and token.lower_value in RESOURCE_FUNCTIONS:
                # A bare resource keyword (for example ``url`` without
                # parentheses) is not a valid value on its own, but keeping
                # it would leave the sensitive identifier in the output.
                return False

            if token.type == "url":
                if not self._url_is_allowed(token.value):
                    return False
                continue

            if token.type == "function":
                if not self._function_is_safe(token):
                    return False
            elif token.type == "() block":
                # White space between a function name and its opening
                # parenthesis (``url ( ... )``) makes tinycss2 emit an
                # identifier followed by a parenthesis block instead of a
                # function token.  Re-check the identifier as a function
                # name so the gap cannot be used to bypass the policy.
                if previous is not None and previous.type == "ident":
                    function_name = previous.lower_value
                    if not self._function_name_is_safe(function_name):
                        return False
                    if function_name in RESOURCE_FUNCTIONS and not (
                        self._spaced_resource_block_is_safe(function_name, token)
                    ):
                        return False
                if not self._tokens_are_safe(token.content):
                    return False
            elif token.type in ("[] block", "{} block"):
                if not self._tokens_are_safe(token.content):
                    return False
            elif token.type == "at-rule":
                if token.lower_at_keyword not in self.allowed_at_rules:
                    return False
                if not self._tokens_are_safe(token.prelude):
                    return False
                if token.content is not None and not self._tokens_are_safe(
                    token.content
                ):
                    return False

            if token.type != "whitespace":
                previous = token

        return True

    def _function_name_is_safe(self, function_name):
        if function_name in RESOURCE_FUNCTIONS:
            return self.url_policy is not None
        return function_name in ALLOWED_FUNCTIONS

    def _spaced_resource_block_is_safe(self, function_name, block_token):
        """Validates an ``ident ( ... )`` block split by white space.

        Outside of a real function context tinycss2 tokenizes unquoted
        references inside the parenthesis as ordinary identifiers, so the
        original URL cannot be reconstructed reliably.  Only an explicit
        string or URL token is accepted and checked against the URL policy.
        """
        arguments = [
            argument
            for argument in block_token.content
            if argument.type != "whitespace"
        ]
        if len(arguments) != 1:
            return False
        argument = arguments[0]
        if argument.type == "url":
            return self._url_is_allowed(argument.value)
        if argument.type == "string" and function_name in (
            "url",
            "image",
            "image-set",
            "cross-fade",
            "src",
        ):
            return self._url_is_allowed(argument.value)
        return False

    def _function_is_safe(self, function_token):
        function_name = function_token.lower_name

        if not self._function_name_is_safe(function_name):
            return False

        if function_name == "url":
            # A quoted url("...") is parsed as a function block rather than
            # a URL token.  Its single non-whitespace argument must be a
            # plain string, otherwise the reference is malformed.
            arguments = [
                argument
                for argument in function_token.arguments
                if argument.type != "whitespace"
            ]
            if len(arguments) != 1 or arguments[0].type != "string":
                return False
            return self._url_is_allowed(arguments[0].value)

        if function_name in RESOURCE_FUNCTIONS:
            # image-set(), image(), cross-fade() and friends nest url()
            # tokens, quoted strings and further resource functions.  Check
            # every argument explicitly: plain strings are treated as
            # resource references and must pass the URL policy, while other
            # tokens go through the regular recursive validation.
            return self._resource_arguments_are_safe(function_token.arguments)

        return self._tokens_are_safe(function_token.arguments)

    def _resource_arguments_are_safe(self, tokens):
        """Validates the arguments of a resource-loading function.

        Inside ``image-set()`` and friends a quoted string names a resource
        just like ``url(...)`` does, so strings are checked against the URL
        policy instead of being accepted as ordinary text.  Nested url() and
        other resource functions are validated recursively.

        Unquoted references are tokenized into identifiers and punctuation
        that cannot be reconstructed reliably, so an identifier or other
        unexpected token rejects the whole declaration.  Commas only separate
        arguments and never name a resource themselves.
        """
        for token in tokens:
            if token.type in (
                "whitespace",
                "literal",
                "number",
                "dimension",
                "percentage",
                "hash",
                "unicode-range",
            ):
                continue
            if token.type == "string":
                if not self._url_is_allowed(token.value):
                    return False
            elif token.type == "url":
                if not self._url_is_allowed(token.value):
                    return False
            elif token.type == "function":
                if not self._function_is_safe(token):
                    return False
            elif token.type in ("() block", "[] block", "{} block"):
                if not self._resource_arguments_are_safe(token.content):
                    return False
            else:
                return False
        return True

    def _url_is_allowed(self, url):
        if self.url_policy is None:
            return False
        return self.url_policy(url) is not None
