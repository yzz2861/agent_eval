from functools import partial

import pytest

tinycss2 = pytest.importorskip("tinycss2")

from bleach import clean  # noqa
from bleach.css_sanitizer import CSSSanitizer, URLPolicy  # noqa


clean = partial(clean, tags={"p"}, attributes=["style"])


def _walk_tokens(tokens):
    for token in tokens:
        yield token
        if token.type == "function":
            yield from _walk_tokens(token.arguments)
        elif token.type in ("() block", "[] block", "{} block"):
            yield from _walk_tokens(token.content)
        elif token.type == "at-rule":
            yield from _walk_tokens(token.prelude)
            if token.content is not None:
                yield from _walk_tokens(token.content)


@pytest.mark.parametrize(
    "data, styles, expected",
    [
        (
            '<p style="font-family: Arial; color: red; float: left; background-color: red;">bar</p>',
            ["color"],
            '<p style="color: red;">bar</p>',
        ),
        (
            '<p style="border: 1px solid blue; color: red; float: left;">bar</p>',
            ["color"],
            '<p style="color: red;">bar</p>',
        ),
        (
            '<p style="border: 1px solid blue; color: red; float: left;">bar</p>',
            ["color", "float"],
            '<p style="color: red; float: left;">bar</p>',
        ),
        (
            '<p style="color: red; float: left; padding: 1em;">bar</p>',
            ["color", "float"],
            '<p style="color: red; float: left;">bar</p>',
        ),
        (
            '<p style="color: red; float: left; padding: 1em;">bar</p>',
            ["color"],
            '<p style="color: red;">bar</p>',
        ),
        # Handle leading - in attributes
        pytest.param(
            '<p style="cursor: -moz-grab;">bar</p>',
            ["cursor"],
            '<p style="cursor: -moz-grab;">bar</p>',
        ),
        # Handle () in attributes
        (
            '<p style="color: hsl(30,100%,50%);">bar</p>',
            ["color"],
            '<p style="color: hsl(30,100%,50%);">bar</p>',
        ),
        (
            '<p style="color: rgba(255,0,0,0.4);">bar</p>',
            ["color"],
            '<p style="color: rgba(255,0,0,0.4);">bar</p>',
        ),
        # Handle ' in attributes
        pytest.param(
            "<p style=\"text-overflow: ',' ellipsis;\">bar</p>",
            ["text-overflow"],
            "<p style='text-overflow: \",\" ellipsis;'>bar</p>",
        ),
        # Handle " in attributes
        pytest.param(
            "<p style='text-overflow: \",\" ellipsis;'>bar</p>",
            ["text-overflow"],
            "<p style='text-overflow: \",\" ellipsis;'>bar</p>",
        ),
        (
            "<p style='font-family: \"Arial\";'>bar</p>",
            ["font-family"],
            "<p style='font-family: \"Arial\";'>bar</p>",
        ),
        # Handle non-ascii characters in attributes
        (
            '<p style="font-family: \u30e1\u30a4\u30ea\u30aa; color: blue;">bar</p>',
            ["color"],
            '<p style="color: blue;">bar</p>',
        ),
    ],
)
def test_allowed_css(data, styles, expected):
    css_sanitizer = CSSSanitizer(allowed_css_properties=styles)
    assert clean(data, css_sanitizer=css_sanitizer) == expected


def test_valid_css():
    """The sanitizer should fix missing CSS values."""
    css_sanitizer = CSSSanitizer(allowed_css_properties=["color", "float"])
    assert (
        clean('<p style="float: left; color: ">foo</p>', css_sanitizer=css_sanitizer)
        == '<p style="float: left; color: ;">foo</p>'
    )
    assert (
        clean('<p style="color: float: left;">foo</p>', css_sanitizer=css_sanitizer)
        == '<p style="color: float: left;">foo</p>'
    )


@pytest.mark.parametrize(
    "data, expected",
    [
        # No url--unchanged
        (
            '<p style="background: #00D;">foo</p>',
            '<p style="background: #00D;">foo</p>',
        ),
        # External resources are dropped by default because no URL policy
        # is configured.
        (
            '<p style="background: url(topbanner.png) #00D;">foo</p>',
            '<p style="">foo</p>',
        ),
        (
            "<p style=\"background: url('topbanner.png') #00D;\">foo</p>",
            '<p style="">foo</p>',
        ),
        (
            "<p style='background: url(\"topbanner.png\") #00D;'>foo</p>",
            '<p style="">foo</p>',
        ),
        # Whitespace inside url() does not make the reference safe.
        (
            "<p style=\"background: url(  'topbanner.png') #00D;\">foo</p>",
            '<p style="">foo</p>',
        ),
        (
            "<p style=\"background: url('topbanner.png'  ) #00D;\">foo</p>",
            '<p style="">foo</p>',
        ),
        (
            "<p style=\"background: url(  'topbanner.png'  ) #00D;\">foo</p>",
            '<p style="">foo</p>',
        ),
        # A gap between the function name and the parenthesis is still a
        # url() reference for the browser and must not slip through.
        (
            "<p style=\"background: url (  'topbanner.png'  ) #00D;\">foo</p>",
            '<p style="">foo</p>',
        ),
        # image-set() and other resource functions are rejected too.
        (
            '<p style="background: image-set(url(topbanner.png) 1x);">foo</p>',
            '<p style="">foo</p>',
        ),
        # Verify urls with character entities
        (
            "<p style=\"background: url&#x09;('topbanner.png') #00D;\">foo</p>",
            # The entity becomes a tab between "url" and "(", so this is a
            # resource reference and the whole declaration is dropped.
            '<p style="">foo</p>',
        ),
    ],
)
def test_urls(data, expected):
    css_sanitizer = CSSSanitizer(allowed_css_properties=["background"])
    assert clean(data, css_sanitizer=css_sanitizer) == expected


@pytest.mark.parametrize(
    "data, expected",
    [
        (
            '<p style="background: url(https://example.com/a.png);">foo</p>',
            '<p style="background: url(https://example.com/a.png);">foo</p>',
        ),
        (
            "<p style=\"background: url('https://example.com/a.png');\">foo</p>",
            "<p style='background: url(\"https://example.com/a.png\");'>foo</p>",
        ),
        (
            '<p style="background: url(http://example.com/a.png);">foo</p>',
            '<p style="background: url(http://example.com/a.png);">foo</p>',
        ),
        (
            '<p style="background: url(//example.com/a.png);">foo</p>',
            '<p style="">foo</p>',
        ),
        (
            '<p style="background: url(javascript:alert(1));">foo</p>',
            '<p style="">foo</p>',
        ),
        (
            '<p style="background: url(data:text/html,x);">foo</p>',
            '<p style="">foo</p>',
        ),
        (
            '<p style="background: url(relative.png);">foo</p>',
            '<p style="">foo</p>',
        ),
        (
            '<p style="background: url(#fragment);">foo</p>',
            '<p style="background: url(#fragment);">foo</p>',
        ),
        (
            '<p style="background: image-set(url(https://example.com/a.png) 1x);'
            '">foo</p>',
            '<p style="background: image-set(url(https://example.com/a.png) 1x);'
            '">foo</p>',
        ),
        (
            '<p style="background: image-set(url(relative.png) 1x);">foo</p>',
            '<p style="">foo</p>',
        ),
        (
            '<p style="background: url(https://example.com/a.png), '
            'url(javascript:alert(1));">foo</p>',
            '<p style="">foo</p>',
        ),
    ],
)
def test_url_policy(data, expected):
    css_sanitizer = CSSSanitizer(
        allowed_css_properties=["background"],
        url_policy=URLPolicy(allowed_protocols=("http", "https")),
    )
    assert clean(data, css_sanitizer=css_sanitizer) == expected


def test_url_policy_relative_and_length():
    relative = CSSSanitizer(
        allowed_css_properties=["background"],
        url_policy=URLPolicy(allow_relative=True),
    )
    assert (
        clean(
            '<p style="background: url(relative.png);">foo</p>',
            css_sanitizer=relative,
        )
        == '<p style="background: url(relative.png);">foo</p>'
    )

    too_long = CSSSanitizer(
        allowed_css_properties=["background"],
        url_policy=URLPolicy(allowed_protocols=("https",), max_url_length=20),
    )
    assert (
        clean(
            '<p style="background: url(https://example.com/a-very-long-name.png);'
            '">foo</p>',
            css_sanitizer=too_long,
        )
        == '<p style="">foo</p>'
    )


def test_url_policy_callable():
    def https_only(url):
        return url if url.startswith("https://") else None

    css_sanitizer = CSSSanitizer(
        allowed_css_properties=["background"], url_policy=https_only
    )
    assert (
        clean(
            '<p style="background: url(https://example.com/a.png);">foo</p>',
            css_sanitizer=css_sanitizer,
        )
        == '<p style="background: url(https://example.com/a.png);">foo</p>'
    )
    assert (
        clean(
            '<p style="background: url(http://example.com/a.png);">foo</p>',
            css_sanitizer=css_sanitizer,
        )
        == '<p style="">foo</p>'
    )


@pytest.mark.parametrize(
    "style",
    [
        # Escaped property name decoding to "url"
        r"u\72l: red",
        r"U\000052l: red",
        # Escaped url() function name
        r"background: u\72l(evil.png)",
        r"background: UR\4C(evil.png)",
        # Comment joining an identifier across the boundary
        r"background: ur/**/l(evil.png)",
        r"width: expression/**/(alert(1))",
        # Escaped and comment-split at-rule keywords
        r"@im\port url(evil.css)",
        r"@IM\PORT url(evil.css)",
        r"@im/**/\port url(evil.css)",
        r"@import url(evil.css)",
        r'@import "evil.css"',
        r"@font-face { font-family: x; src: url(evil.ttf) }",
        r"@supports (color: red) { color: red }",
        r"@media screen { color: red }",
        r"@keyframes spin { from { width: 1px } }",
        r"@namespace svg url(http://example.com/svg)",
        # Resource functions hidden among allowed declarations
        r"color: red; @import url(evil.css); width: 1px",
        r"background: image-set(url(evil.png) 1x)",
        r"background: image-set('evil.png' 1x)",
        # Unknown and legacy functions cannot pass as generic tokens
        r"background: expression(alert(1))",
        r"background: var(--evil)",
        r"--custom: url(evil.png)",
        # Whitespace gap between function name and parenthesis
        r"background: url (evil.png)",
        r"background: url ('evil.png')",
    ],
)
def test_dangerous_styles_are_dropped(style):
    css_sanitizer = CSSSanitizer(
        allowed_css_properties=[
            "background",
            "color",
            "width",
            "expression",
            "var",
            "--custom",
        ]
    )
    sanitized = css_sanitizer.sanitize_css(style)

    # Nothing that names an external resource or an at-rule may survive.
    reparsed = tinycss2.parse_declaration_list(sanitized)
    assert all(token.type in ("declaration", "whitespace") for token in reparsed)
    for token in reparsed:
        if token.type != "declaration":
            continue
        serialized_value = tinycss2.serialize(token.value).lower()
        assert "url" not in serialized_value
        assert "image-set" not in serialized_value
        assert "expression" not in serialized_value
        assert "@" not in tinycss2.serialize(token.value)


@pytest.mark.parametrize(
    "style, expected",
    [
        # Escapes in safe property/value names are decoded but preserved.
        (r"col\6f r: red", "color: red;"),
        (r"width: 1px; col\6f r: re\64", "width: 1px; color: red;"),
        # Comments joining a safe identifier are reconstructed.
        (r"wid/**/th: 1px", "width: 1px;"),
        (r"color: re/**/d", "color: red;"),
        (r"width: 10px /* note */ ; color: red", "width: 10px  ; color: red;"),
        # Case-insensitive property and function names.
        ("COLOR: RED", "COLOR: RED;"),
        ("color: RGB(255, 0, 0)", "color: RGB(255, 0, 0);"),
        # Comments inside strings are literal text and stay intact.
        (
            "font-family: 'A/*B'; color: red",
            'font-family: "A/*B"; color: red;',
        ),
        # Safe colors, fonts and widths keep their meaning.
        ("color: hsl(30,100%,50%)", "color: hsl(30,100%,50%);"),
        ("width: calc(100% - 1px)", "width: calc(100% - 1px);"),
        ("fill: red; stroke-width: 2px", "fill: red; stroke-width: 2px;"),
    ],
)
def test_legitimate_styles_keep_their_meaning(style, expected):
    css_sanitizer = CSSSanitizer()
    assert css_sanitizer.sanitize_css(style) == expected


@pytest.mark.parametrize(
    "style",
    [
        "color: red; width: 1px",
        r"col\6f r: re/**/d; width: 1px",
        "color: hsl(30,100%,50%); font-family: Arial, sans-serif",
        "fill: red; stroke: blue; stroke-width: 2px",
        "  color:   red  ;  width : 1px ;",
    ],
)
def test_sanitizing_is_idempotent(style):
    css_sanitizer = CSSSanitizer()
    once = css_sanitizer.sanitize_css(style)
    twice = css_sanitizer.sanitize_css(once)
    assert once == twice
    # The output must re-parse to the same declarations without creating
    # any new token types.
    reparsed = tinycss2.parse_declaration_list(once)
    assert all(token.type in ("declaration", "whitespace") for token in reparsed)


def test_empty_and_whitespace_input():
    css_sanitizer = CSSSanitizer()
    assert css_sanitizer.sanitize_css("") == ""
    assert css_sanitizer.sanitize_css("   ") == ""
    assert css_sanitizer.sanitize_css("@import url(evil.css)") == ""
    # Allowing an unknown property does not matter when the value is unsafe.
    assert css_sanitizer.sanitize_css("color: ") == "color: ;"


@pytest.mark.parametrize(
    "style",
    [
        "/* only a comment */",
        "/* unterminated comment",
        "::::",
        "(",
        "color: 'unterminated string; width: 1px",
        "width: 1px;;; color: red",
        "color:red\fcolor:blue",
        "color:red\vcolor:blue",
        "background: url(`backtick`)",
        "background: url($!@%)",
    ],
)
def test_malformed_input_never_raises_or_creates_tokens(style):
    css_sanitizer = CSSSanitizer()
    sanitized = css_sanitizer.sanitize_css(style)
    reparsed = tinycss2.parse_declaration_list(sanitized)
    assert all(token.type in ("declaration", "whitespace") for token in reparsed)
    # Re-sanitizing the output must be a no-op.
    assert css_sanitizer.sanitize_css(sanitized) == sanitized


def test_second_parse_contains_no_dangerous_token():
    """Acceptance guard: the output re-parses without folded tokens."""
    css_sanitizer = CSSSanitizer(
        allowed_css_properties=["color", "width", "background"]
    )
    payloads = [
        r"u\72l: red",
        r"background: u\72l(evil.png)",
        r"background: ur/**/l(evil.png)",
        r"@im\port url(evil.css); color: red",
        r"@im/**/\port url(evil.css); width: 1px",
        r"@font-face { src: url(evil.ttf) }",
        r"@supports (color: red) { color: red }",
        r"background: image-set(url(evil.png) 1x); color: red",
        r"background: url (evil.png); width: 1px",
    ]
    for payload in payloads:
        sanitized = css_sanitizer.sanitize_css(payload)
        reparsed = tinycss2.parse_declaration_list(sanitized)
        assert [token.type for token in reparsed if token.type != "whitespace"] == [
            token.type for token in reparsed if token.type == "declaration"
        ]
        for token in reparsed:
            if token.type != "declaration":
                continue
            for nested in _walk_tokens(token.value):
                assert nested.type not in ("url", "at-rule", "error")
                if nested.type == "function":
                    assert nested.lower_name not in (
                        "url",
                        "image-set",
                        "image",
                        "cross-fade",
                        "expression",
                    )


def test_allowed_at_rules_still_drop_top_level_at_rules():
    # style attributes are declaration lists; opting into an at-rule never
    # lets an at-rule survive at the top level.
    css_sanitizer = CSSSanitizer(allowed_at_rules=["media"])
    assert css_sanitizer.sanitize_css("@media screen { color: red }") == ""
    assert css_sanitizer.sanitize_css("@import url(evil.css)") == ""
    assert css_sanitizer.sanitize_css("color: red") == "color: red;"


def test_style_hang():
    """The sanitizer should not hang on any inline styles"""
    style = [
        "margin-top: 0px;",
        "margin-right: 0px;",
        "margin-bottom: 1.286em;",
        "margin-left: 0px;",
        "padding-top: 15px;",
        "padding-right: 15px;",
        "padding-bottom: 15px;",
        "padding-left: 15px;",
        "border-top-width: 1px;",
        "border-right-width: 1px;",
        "border-bottom-width: 1px;",
        "border-left-width: 1px;",
        "border-top-style: dotted;",
        "border-right-style: dotted;",
        "border-bottom-style: dotted;",
        "border-left-style: dotted;",
        "border-top-color: rgb(203, 200, 185);",
        "border-right-color: rgb(203, 200, 185);",
        "border-bottom-color: rgb(203, 200, 185);",
        "border-left-color: rgb(203, 200, 185);",
        "background-image: initial;",
        "background-attachment: initial;",
        "background-origin: initial;",
        "background-clip: initial;",
        "background-color: rgb(246, 246, 242);",
        "overflow-x: auto;",
        "overflow-y: auto;",
        "font: italic small-caps bolder condensed 16px/3 cursive;",
        "background-position: initial initial;",
        "background-repeat: initial initial;",
    ]
    html = '<p style="%s">Hello world</p>' % " ".join(style)
    styles = [
        "border",
        "float",
        "overflow",
        "min-height",
        "vertical-align",
        "white-space",
        "margin",
        "margin-left",
        "margin-top",
        "margin-bottom",
        "margin-right",
        "padding",
        "padding-left",
        "padding-top",
        "padding-bottom",
        "padding-right",
        "background",
        "background-color",
        "font",
        "font-size",
        "font-weight",
        "text-align",
        "text-transform",
    ]

    expected = (
        '<p style="'
        "margin-top: 0px; "
        "margin-right: 0px; "
        "margin-bottom: 1.286em; "
        "margin-left: 0px; "
        "padding-top: 15px; "
        "padding-right: 15px; "
        "padding-bottom: 15px; "
        "padding-left: 15px; "
        "background-color: rgb(246, 246, 242); "
        "font: italic small-caps bolder condensed 16px/3 cursive;"
        '">Hello world</p>'
    )

    css_sanitizer = CSSSanitizer(allowed_css_properties=styles)
    assert clean(html, css_sanitizer=css_sanitizer) == expected


@pytest.mark.parametrize(
    "data, styles, expected",
    [
        (
            '<p style="font-family: Droid Sans, serif; white-space: pre-wrap;">text</p>',
            ["font-family", "white-space"],
            '<p style="font-family: Droid Sans, serif; white-space: pre-wrap;">text</p>',
        ),
        (
            "<p style=\"content: '&nbsp;';\">text</p>",
            ["content"],
            # This seems wrong, but it's right. Character entities aren't a
            # thing in CSS, so this is treated as text.
            "<p style='content: \"&amp;nbsp;\";'>text</p>",
        ),
    ],
)
def test_css_parsing_with_entities(data, styles, expected):
    """The sanitizer should be ok with character entities"""
    css_sanitizer = CSSSanitizer(allowed_css_properties=styles)
    assert (
        clean(
            data, tags={"p"}, attributes={"p": ["style"]}, css_sanitizer=css_sanitizer
        )
        == expected
    )
