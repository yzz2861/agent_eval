from __future__ import absolute_import, division, unicode_literals

import warnings

import pytest

from html5lib import constants, HTMLParser, parseFragment, serialize

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from html5lib.filters import sanitizer

html_ns = constants.namespaces["html"]
svg_ns = constants.namespaces["svg"]


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


tree_serialize_options = dict(
    sanitize=True,
    omit_optional_tags=False,
    use_trailing_solidus=True,
    space_before_trailing_solidus=False,
    quote_attr_values="always",
    quote_char='"',
    alphabetical_attributes=True)


def sanitize_tree_and_serialize(stream, full_document=False, **kwargs):
    """Run the post-parse tree sanitizer, then the streaming token filter."""
    parser = HTMLParser()
    if full_document:
        tree = parser.parse(stream)
    else:
        tree = parser.parseFragment(stream)
    diagnostics = sanitizer.sanitize_tree(
        tree, relocations=parser.tree.relocations, **kwargs)
    with pytest.deprecated_call():
        serialized = serialize(tree, **tree_serialize_options)
    return serialized, diagnostics


def removals(diagnostics):
    return [d for d in diagnostics if d.action == "removed"]


def test_tree_style_in_table_cell_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<table><tr><td><style>body{color:red}</style></td></tr></table>")
    assert serialized == "<table><tbody><tr><td></td></tr></tbody></table>"
    assert sanitizer.Diagnostic(
        "removed", "executable-content-in-body", "style", html_ns,
        ("table", "tbody", "tr", "td")) in diagnostics


def test_tree_style_in_table_scope_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<table><style>img{x}</style><tr><td>x</td></tr></table>")
    assert serialized == "<table><tbody><tr><td>x</td></tr></tbody></table>"
    assert sanitizer.Diagnostic(
        "removed", "executable-content-in-table-scope", "style", html_ns,
        ("table",)) in diagnostics


def test_tree_foster_parented_script_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<table><b><script>alert(1)</script></b></table>")
    assert serialized == "<b></b><table></table>"
    assert sanitizer.Diagnostic(
        "removed", "foster-parented-into-executable-context", "script",
        html_ns, ("b",)) in diagnostics
    assert sanitizer.Diagnostic(
        "moved", "foster-parented", "b", html_ns, ()) in diagnostics


def test_tree_foster_parented_text_kept_script_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<table>hello<script>alert(1)</script></table>")
    assert serialized == "hello<table></table>"
    assert sanitizer.Diagnostic(
        "removed", "executable-content-in-table-scope", "script", html_ns,
        ("table",)) in diagnostics
    assert sanitizer.Diagnostic(
        "moved", "foster-parented-text", "#text", None, ()) in diagnostics


def test_tree_implicit_tbody_preserved():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<table><td>foo</td></table>")
    assert serialized == "<table><tbody><tr><td>foo</td></tr></tbody></table>"
    assert removals(diagnostics) == []
    assert sanitizer.Diagnostic(
        "inserted", "implicit-tbody", "tbody", html_ns, ("table",)) in diagnostics
    assert sanitizer.Diagnostic(
        "inserted", "implicit-tr", "tr", html_ns,
        ("table", "tbody")) in diagnostics


def test_tree_legitimate_table_content_preserved():
    stream = ("<table><caption>cap</caption><thead><tr><th>h</th></tr></thead>"
              "<tbody><tr><td>d</td></tr></tbody></table>")
    serialized, diagnostics = sanitize_tree_and_serialize(stream)
    assert serialized == stream
    assert removals(diagnostics) == []


def test_tree_style_relocated_to_head_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<html><head></head><style>body{color:red}</style><p>hi</p></html>",
        full_document=True)
    assert "color:red" not in serialized
    assert sanitizer.Diagnostic(
        "removed", "relocated-to-head-executable-content", "style", html_ns,
        ("html", "head")) in diagnostics


def test_tree_style_in_head_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<style>body{color:red}</style><p>hi</p>", full_document=True)
    assert "color:red" not in serialized
    assert sanitizer.Diagnostic(
        "removed", "executable-content-in-head", "style", html_ns,
        ("html", "head")) in diagnostics


def test_tree_script_in_body_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<p>hi</p><script>alert(1)</script>", full_document=True)
    assert "alert(1)" not in serialized
    assert sanitizer.Diagnostic(
        "removed", "executable-content-in-body", "script", html_ns,
        ("html", "body")) in diagnostics


def test_tree_foreign_content_script_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<svg><script>alert(1)</script><circle/></svg>")
    assert serialized == "<svg><circle></circle></svg>"
    assert sanitizer.Diagnostic(
        "removed", "executable-content-in-foreign-content", "script", svg_ns,
        ("svg",)) in diagnostics


def test_tree_foreign_content_html_integration_point_script_removed():
    serialized, diagnostics = sanitize_tree_and_serialize(
        '<math><annotation-xml encoding="text/html">'
        "<script>alert(1)</script></annotation-xml></math>")
    assert "alert(1)" not in serialized
    assert sanitizer.Diagnostic(
        "removed", "executable-content-in-body", "script", html_ns,
        ("math", "annotation-xml")) in diagnostics


def test_tree_foreign_content_allowed_elements_kept():
    serialized, diagnostics = sanitize_tree_and_serialize(
        "<svg><title>ok</title></svg>")
    assert serialized == "<svg><title>ok</title></svg>"
    assert removals(diagnostics) == []


def test_tree_style_kept_when_policy_allows_it():
    # Scoped styles explicitly allowed by the policy must not be removed.
    allowed = sanitizer.allowed_elements | {(html_ns, "style")}
    parser = HTMLParser()
    tree = parser.parseFragment(
        "<table><tr><td><style>body{color:red}</style></td></tr></table>")
    diagnostics = sanitizer.sanitize_tree(
        tree, relocations=parser.tree.relocations, allowed_elements=allowed)
    assert removals(diagnostics) == []
    serialized = serialize(tree, omit_optional_tags=False)
    assert serialized == ("<table><tbody><tr><td>"
                          "<style>body{color:red}</style>"
                          "</td></tr></tbody></table>")


def test_tree_sanitize_is_idempotent_over_multiple_rounds():
    stream = ("<table><style>a{b:c}</style><tr><td>x</td></tr></table>"
              "<script>alert(1)</script>")
    first, diagnostics = sanitize_tree_and_serialize(stream)
    assert removals(diagnostics) != []
    second, diagnostics = sanitize_tree_and_serialize(first)
    assert first == second
    assert removals(diagnostics) == []


@pytest.mark.parametrize("stream", [
    "<table><tr><td><style>body{color:red}</style></td></tr></table>",
    "<table><style>img{x}</style><tr><td>x</td></tr></table>",
    "<table><b><script>alert(1)</script></b></table>",
    "<table>hello<script>alert(1)</script></table>",
    "<table><td>foo</td></table>",
    "<svg><script>alert(1)</script><circle/></svg>",
])
def test_tree_serialized_output_reparses_to_sanitized_dom(stream):
    serialized, _ = sanitize_tree_and_serialize(stream)
    reparsed = parseFragment(serialized)
    with pytest.deprecated_call():
        reserialized = serialize(reparsed, **tree_serialize_options)
    assert reserialized == serialized


def test_tree_diagnostics_do_not_leak_payload():
    _, diagnostics = sanitize_tree_and_serialize(
        "<table><script>alert(1)</script><style>body{color:red}</style>"
        "</table>")
    assert removals(diagnostics) != []
    for diagnostic in diagnostics:
        assert "alert" not in repr(diagnostic)
        assert "color:red" not in repr(diagnostic)
        assert "alert" not in str(diagnostic.as_dict())
        assert "color:red" not in str(diagnostic.as_dict())


def test_token_stream_sanitizer_still_escapes_without_tree_pass():
    # The streaming token filter is unchanged: it escapes disallowed
    # elements without needing the whole document first.
    sanitized = sanitize_html("<script>alert(1)</script>")
    assert sanitized == "&lt;script&gt;alert(1)&lt;/script&gt;"
