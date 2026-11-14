from __future__ import absolute_import, division, unicode_literals

import warnings

import pytest

from html5lib import constants, parseFragment, serialize

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from html5lib.filters import sanitizer


def sanitize_html(stream):
    parsed = parseFragment(stream)
    with pytest.deprecated_call():
        serialized = serialize(parsed,
                               sanitize=True,
                               omit_optional_tags=False,
                               use_trailing_solidus=True,
                               space_before_trailing_solidus=False,
                               quote_attr_values="always",
                               quote_char='"',
                               alphabetical_attributes=True)
    return serialized


def test_should_handle_astral_plane_characters():
    sanitized = sanitize_html("<p>&#x1d4b5; &#x1d538;</p>")
    expected = '<p>\U0001d4b5 \U0001d538</p>'
    assert expected == sanitized


def test_should_allow_relative_uris():
    sanitized = sanitize_html('<p><a href="/example.com"></a></p>')
    expected = '<p><a href="/example.com"></a></p>'
    assert expected == sanitized


def test_invalid_data_uri():
    sanitized = sanitize_html('<audio controls="" src="data:foobar"></audio>')
    expected = '<audio controls></audio>'
    assert expected == sanitized


def test_invalid_ipv6_url():
    sanitized = sanitize_html('<a href="h://]">')
    expected = "<a></a>"
    assert expected == sanitized


def test_data_uri_disallowed_type():
    sanitized = sanitize_html('<audio controls="" src="data:text/html,<html>"></audio>')
    expected = "<audio controls></audio>"
    assert expected == sanitized


def test_wbr_allowed():
    sanitized = sanitize_html('<wbr>')
    expected = '<wbr/>'
    assert expected == sanitized


def param_sanitizer():
    for ns, tag_name in sanitizer.allowed_elements:
        if ns != constants.namespaces["html"]:
            continue
        if tag_name in ['caption', 'col', 'colgroup', 'optgroup', 'option', 'table', 'tbody', 'td',
                        'tfoot', 'th', 'thead', 'tr', 'select']:
            continue  # TODO
        if tag_name == 'image':
            yield ("test_should_allow_%s_tag" % tag_name,
                   "<img title=\"1\"/>foo &lt;bad&gt;bar&lt;/bad&gt; baz",
                   "<%s title='1'>foo <bad>bar</bad> baz</%s>" % (tag_name, tag_name))
        elif tag_name == 'br':
            yield ("test_should_allow_%s_tag" % tag_name,
                   "<br title=\"1\"/>foo &lt;bad&gt;bar&lt;/bad&gt; baz<br/>",
                   "<%s title='1'>foo <bad>bar</bad> baz</%s>" % (tag_name, tag_name))
        elif tag_name in constants.voidElements:
            yield ("test_should_allow_%s_tag" % tag_name,
                   "<%s title=\"1\"/>foo &lt;bad&gt;bar&lt;/bad&gt; baz" % tag_name,
                   "<%s title='1'>foo <bad>bar</bad> baz</%s>" % (tag_name, tag_name))
        else:
            yield ("test_should_allow_%s_tag" % tag_name,
                   "<%s title=\"1\">foo &lt;bad&gt;bar&lt;/bad&gt; baz</%s>" % (tag_name, tag_name),
                   "<%s title='1'>foo <bad>bar</bad> baz</%s>" % (tag_name, tag_name))

    for ns, attribute_name in sanitizer.allowed_attributes:
        if ns is not None:
            continue
        if attribute_name != attribute_name.lower():
            continue  # TODO
        if attribute_name == 'style':
            continue
        attribute_value = 'foo'
        if attribute_name in sanitizer.attr_val_is_uri:
            attribute_value = '%s://sub.domain.tld/path/object.ext' % sanitizer.allowed_protocols[0]
        yield ("test_should_allow_%s_attribute" % attribute_name,
               "<p %s=\"%s\">foo &lt;bad&gt;bar&lt;/bad&gt; baz</p>" % (attribute_name, attribute_value),
               "<p %s='%s'>foo <bad>bar</bad> baz</p>" % (attribute_name, attribute_value))

    for protocol in sanitizer.allowed_protocols:
        rest_of_uri = '//sub.domain.tld/path/object.ext'
        if protocol == 'data':
            rest_of_uri = 'image/png;base64,aGVsbG8gd29ybGQ='
        yield ("test_should_allow_uppercase_%s_uris" % protocol,
               "<img src=\"%s:%s\">foo</a>" % (protocol, rest_of_uri),
               """<img src="%s:%s">foo</a>""" % (protocol, rest_of_uri))

    for protocol in sanitizer.allowed_protocols:
        rest_of_uri = '//sub.domain.tld/path/object.ext'
        if protocol == 'data':
            rest_of_uri = 'image/png;base64,aGVsbG8gd29ybGQ='
        protocol = protocol.upper()
        yield ("test_should_allow_uppercase_%s_uris" % protocol,
               "<img src=\"%s:%s\">foo</a>" % (protocol, rest_of_uri),
               """<img src="%s:%s">foo</a>""" % (protocol, rest_of_uri))


def test_details_open_allowed():
    sanitized = sanitize_html("<details open>.</details>")
    expected = '<details open>.</details>'
    assert expected == sanitized


def test_details_summary_allowed():
    sanitized = sanitize_html("<details><summary>.</summary><p>...</p></details>")
    expected = '<details><summary>.</summary><p>...</p></details>'
    assert expected == sanitized


@pytest.mark.parametrize("expected, input",
                         (pytest.param(expected, input, id=id)
                          for id, expected, input in param_sanitizer()))
def test_sanitizer(expected, input):
    parsed = parseFragment(expected)
    expected = serialize(parsed,
                         omit_optional_tags=False,
                         use_trailing_solidus=True,
                         space_before_trailing_solidus=False,
                         quote_attr_values="always",
                         quote_char='"',
                         alphabetical_attributes=True)
    assert expected == sanitize_html(input)


def test_lowercase_color_codes_in_style():
    sanitized = sanitize_html("<p style=\"border: 1px solid #a2a2a2;\"></p>")
    expected = '<p style=\"border: 1px solid #a2a2a2;\"></p>'
    assert expected == sanitized


def test_uppercase_color_codes_in_style():
    sanitized = sanitize_html("<p style=\"border: 1px solid #A2A2A2;\"></p>")
    expected = '<p style=\"border: 1px solid #A2A2A2;\"></p>'
    assert expected == sanitized


def test_ol_start_allowed():
    sanitized = sanitize_html("<ol start=2><li>.</ol>")
    expected = '<ol start="2"><li>.</li></ol>'
    assert expected == sanitized


def test_ol_type_allowed():
    sanitized = sanitize_html("<ol type=I><li>.</ol>")
    expected = '<ol type="I"><li>.</li></ol>'
    assert expected == sanitized


def test_ol_reversed_allowed():
    sanitized = sanitize_html("<ol reversed><li>.</ol>")
    expected = '<ol reversed><li>.</li></ol>'
    assert expected == sanitized


def reserialize(stream):
    """Serialize without sanitizing (used to check re-parse stability)."""
    parsed = parseFragment(stream)
    return serialize(parsed,
                     omit_optional_tags=False,
                     use_trailing_solidus=True,
                     space_before_trailing_solidus=False,
                     quote_attr_values="always",
                     quote_char='"',
                     alphabetical_attributes=True)


def check_stable_and_idempotent(input):
    """Sanitized output must be a fixed point of parsing and sanitizing."""
    sanitized = sanitize_html(input)
    # idempotent: sanitizing the output again changes nothing
    assert sanitized == sanitize_html(sanitized)
    # stable tree: re-parsing the output (without sanitizing) yields the
    # same serialization, i.e. no mutation XSS
    assert sanitized == reserialize(sanitized)
    return sanitized


def test_foreignobject_iframe_srcdoc_escaped():
    sanitized = check_stable_and_idempotent(
        '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></iframe></foreignObject></svg>')
    assert "<iframe" not in sanitized
    assert "<foreignObject" not in sanitized
    # the dangerous markup only survives as inert, escaped text
    assert "<script" not in sanitized
    assert "&lt;script&gt;" not in sanitized


def test_foreignobject_html_children_do_not_escape_svg():
    # The HTML children of a removed foreignObject must not remain as
    # elements directly inside the SVG tree: they would be relocated by
    # the parser on re-parse (mutation XSS).
    sanitized = check_stable_and_idempotent(
        '<svg><foreignObject><p onclick="alert(1)">hi</p></foreignObject></svg>')
    assert "<p" not in sanitized
    assert "hi" in sanitized


def test_annotation_xml_text_html_escaped():
    sanitized = check_stable_and_idempotent(
        '<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>')
    assert "<annotation-xml" not in sanitized
    assert "<script" not in sanitized


def test_script_and_style_elements_escaped_everywhere():
    for input in ('<script>alert(1)</script>',
                  '<svg><script>alert(1)</script></svg>',
                  '<math><script>alert(1)</script></math>',
                  '<style><img src=x onerror=alert(1)></style>',
                  '<svg><style><img src=x onerror=alert(1)></style></svg>'):
        sanitized = check_stable_and_idempotent(input)
        assert "<script" not in sanitized
        assert "<style" not in sanitized
        # no element in the final DOM carries an event handler
        for element in parseFragment(sanitized).iter():
            assert not any(attr.split("}")[-1].lower().startswith("on") and
                           attr.split("}")[-1].lower() != "open"
                           for attr in element.attrib)


def test_table_foster_parenting_is_stable():
    # Character data (e.g. escaped markup) directly inside table contexts
    # would be foster-parented on re-parse; it must be dropped instead.
    for input in ('<table><tbody><script>alert(1)</script></tbody></table>',
                  '<table><style><img src=x onerror=alert(1)></style></table>',
                  '<table><svg><script>alert(1)</script></svg></table>'):
        check_stable_and_idempotent(input)


def test_nested_form_is_stable():
    # The parser ignores a <form> start tag while another form is open
    check_stable_and_idempotent(
        '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>')


def test_mxss_corpus_is_stable():
    corpus = [
        '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">',
        '<svg></p><style><a id="</style><img src=x onerror=alert(1)>">',
        '<svg><foreignObject><math><script>alert(1)</script></math></foreignObject></svg>',
        '<math><mtext><script>alert(1)</script></mtext></math>',
        '<select><script>alert(1)</script></select>',
    ]
    for input in corpus:
        check_stable_and_idempotent(input)


def test_event_attributes_removed():
    assert "<p>hi</p>" == sanitize_html('<p onclick="alert(1)">hi</p>')
    assert "<details open>x</details>" == sanitize_html(
        '<details open ontoggle="alert(1)">x</details>')
    sanitized = sanitize_html('<svg><rect ONCLICK="alert(1)" width="10"/></svg>')
    assert "ONCLICK" not in sanitized and "onclick" not in sanitized
    assert 'width="10"' in sanitized


def test_svg_animation_cannot_set_event_handlers():
    sanitized = sanitize_html(
        '<svg><set attributeName="onmouseover" to="alert(1)"></set></svg>')
    assert "attributeName" not in sanitized


def test_svg_animation_cannot_smuggle_dangerous_urls():
    sanitized = sanitize_html(
        '<svg><animate attributeName="href" values="javascript:alert(1)"></animate></svg>')
    assert "javascript" not in sanitized
    sanitized = sanitize_html(
        '<svg><animate attributeName="xlink:href" to="javascript:alert(1)"></animate></svg>')
    assert "javascript" not in sanitized


def test_svg_use_allows_only_local_href():
    sanitized = sanitize_html('<svg><use xlink:href="https://evil.example/x.svg#y"></use></svg>')
    assert "href" not in sanitized
    sanitized = sanitize_html('<svg><use href="https://evil.example/x.svg#y"></use></svg>')
    assert "href" not in sanitized
    sanitized = check_stable_and_idempotent('<svg><use xlink:href="#local"></use></svg>')
    assert 'xlink:href="#local"' in sanitized


def test_xlink_href_round_trips_with_prefix():
    sanitized = check_stable_and_idempotent(
        '<svg><a xlink:href="https://example.com/"><text>x</text></a></svg>')
    assert 'xlink:href="https://example.com/"' in sanitized


def test_svg_and_mathml_content_preserved():
    sanitized = check_stable_and_idempotent(
        '<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="red"/></svg>')
    assert '<svg viewBox="0 0 100 100">' in sanitized
    assert "<circle" in sanitized
    sanitized = check_stable_and_idempotent(
        '<math><mi>x</mi><mo>+</mo><mn>1</mn></math>')
    assert "<math><mi>x</mi><mo>+</mo><mn>1</mn></math>" == sanitized


def test_case_and_prefix_determinism():
    # HTML attribute names are case-insensitive
    assert '<p class="c">x</p>' == sanitize_html('<P CLASS="c">x</P>')
    # SVG attribute names are canonicalized by the parser
    assert '<svg viewBox="0 0 1 1"></svg>' == sanitize_html('<svg viewbox="0 0 1 1"></svg>')
    # unknown namespace-prefixed attributes are dropped
    assert "<div>x</div>" == sanitize_html('<div foo:bar="1">x</div>')
    # duplicate attributes: the first occurrence wins
    assert '<p id="first">x</p>' == sanitize_html('<p id="first" id="second">x</p>')


def test_dropped_items_are_audited():
    from html5lib import getTreeWalker
    walker = getTreeWalker("etree")
    audit_log = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        stream = sanitizer.Filter(
            walker(parseFragment('<p onclick="x()">hi</p><script>alert(1)</script>')),
            audit_log=audit_log)
        list(stream)
    reasons = set(entry[0] for entry in audit_log)
    assert "event-attribute-dropped" in reasons
    assert "disallowed-element" in reasons


def test_table_structure_elements_need_their_ancestors():
    # a <tbody> outside a table is ignored by the parser, so it must be
    # escaped rather than emitted
    sanitized = check_stable_and_idempotent("<p><object><table><tbody>")
    assert "<tbody>" not in sanitized
    # ... while proper tables round-trip untouched
    sanitized = check_stable_and_idempotent(
        "<table><tbody><tr><td>x</td></tr></tbody></table>")
    assert sanitized == "<table><tbody><tr><td>x</td></tr></tbody></table>"
    sanitized = check_stable_and_idempotent(
        "<table><caption>c</caption><colgroup><col/></colgroup>"
        "<thead><tr><th>h</th></tr></thead>"
        "<tbody><tr><td>d</td></tr></tbody></table>")
    assert "<caption>c</caption>" in sanitized
    assert "<thead><tr><th>h</th></tr></thead>" in sanitized


def test_elements_inside_rcdata_elements_are_escaped():
    # element children of <textarea> can only arise through parser
    # quirks; they would be text when re-parsed
    sanitized = check_stable_and_idempotent(
        "<b><textarea><img src=x onerror=alert(1)></textarea></b>")
    assert "<img" not in sanitized


def test_carriage_returns_are_normalized():
    # CR can only reach the output through character references; any HTML
    # parser normalizes it to LF on (re-)parse
    sanitized = check_stable_and_idempotent("<p>&#xd;</p>")
    assert "\r" not in sanitized


def test_auto_close_rules_are_stable():
    # removing an intermediate element must not bring auto-closing
    # relatives together
    for input in ("<option><object><option>",
                  "<ul><li><object><li>",
                  "<p><object><div>",
                  "<h1><object><h2>",
                  "<button><object><button>",
                  "<dl><dd><object><dt>"):
        check_stable_and_idempotent(input)
