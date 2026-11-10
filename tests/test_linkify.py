import re

import pytest
from urllib.parse import quote_plus

from bleach import linkify, DEFAULT_CALLBACKS as DC
from bleach.linkifier import Linker, LinkifyFilter, LinkPolicy
from bleach.sanitizer import Cleaner


def test_empty():
    assert linkify("") == ""


def test_simple_link():
    assert (
        linkify("a http://example.com link")
        == 'a <a href="http://example.com" rel="nofollow">http://example.com</a> link'
    )
    assert (
        linkify("a https://example.com link")
        == 'a <a href="https://example.com" rel="nofollow">https://example.com</a> link'
    )
    assert (
        linkify("a example.com link")
        == 'a <a href="http://example.com" rel="nofollow">example.com</a> link'
    )


def test_trailing_slash():
    assert (
        linkify("http://examp.com/")
        == '<a href="http://examp.com/" rel="nofollow">http://examp.com/</a>'
    )
    assert (
        linkify("http://example.com/foo/")
        == '<a href="http://example.com/foo/" rel="nofollow">http://example.com/foo/</a>'
    )
    assert (
        linkify("http://example.com/foo/bar/")
        == '<a href="http://example.com/foo/bar/" rel="nofollow">http://example.com/foo/bar/</a>'
    )


def test_mangle_link():
    """We can muck with the href attribute of the link."""

    def filter_url(attrs, new=False):
        if not attrs.get((None, "href"), "").startswith("http://bouncer"):
            quoted = quote_plus(attrs[(None, "href")])
            attrs[(None, "href")] = f"http://bouncer/?u={quoted}"
        return attrs

    assert (
        linkify("http://example.com", callbacks=DC + [filter_url])
        == '<a href="http://bouncer/?u=http%3A%2F%2Fexample.com" rel="nofollow">http://example.com</a>'
    )


def test_mangle_text():
    """We can muck with the inner text of a link."""

    def ft(attrs, new=False):
        attrs["_text"] = "bar"
        return attrs

    assert (
        linkify('http://ex.mp <a href="http://ex.mp/foo">foo</a>', callbacks=[ft])
        == '<a href="http://ex.mp">bar</a> <a href="http://ex.mp/foo">bar</a>'
    )


@pytest.mark.parametrize(
    "data, parse_email, expected",
    [
        ("a james@example.com mailto", False, "a james@example.com mailto"),
        ("a james@example.com.au mailto", False, "a james@example.com.au mailto"),
        (
            "a james@example.com mailto",
            True,
            'a <a href="mailto:james@example.com">james@example.com</a> mailto',
        ),
        (
            "aussie james@example.com.au mailto",
            True,
            'aussie <a href="mailto:james@example.com.au">james@example.com.au</a> mailto',
        ),
        # This is kind of a pathological case. I guess we do our best here.
        (
            'email to <a href="james@example.com">james@example.com</a>',
            True,
            'email to <a href="james@example.com" rel="nofollow">james@example.com</a>',
        ),
        (
            "<br>jinkyun@example.com",
            True,
            '<br><a href="mailto:jinkyun@example.com">jinkyun@example.com</a>',
        ),
        # Mailto links at the end of a sentence.
        (
            "mailto james@example.com.au.",
            True,
            'mailto <a href="mailto:james@example.com.au">james@example.com.au</a>.',
        ),
        # Incorrect email
        ('"\\\n"@opa.ru', True, '"\\\n"@opa.ru'),
        # RFC6068 special characters
        (
            "gorby%kremvax@example.com",
            True,
            '<a href="mailto:gorby%25kremvax@example.com">gorby%kremvax@example.com</a>',
        ),
        (
            "unlikely?address@example.com",
            True,
            '<a href="mailto:unlikely%3Faddress@example.com">unlikely?address@example.com</a>',
        ),
    ],
)
def test_email_link(data, parse_email, expected):
    assert linkify(data, parse_email=parse_email) == expected


@pytest.mark.parametrize(
    "data, expected",
    [
        (
            '"james"@example.com',
            """<a href="mailto:%22james%22@example.com">"james"@example.com</a>""",
        ),
        (
            '"j\'ames"@example.com',
            """<a href="mailto:%22j%27ames%22@example.com">"j'ames"@example.com</a>""",
        ),
        (
            '"ja>mes"@example.com',
            """<a href="mailto:%22ja%3Emes%22@example.com">"ja&gt;mes"@example.com</a>""",
        ),
    ],
)
def test_email_link_escaping(data, expected):
    assert linkify(data, parse_email=True) == expected


def no_new_links(attrs, new=False):
    if new:
        return None
    return attrs


def no_old_links(attrs, new=False):
    if not new:
        return None
    return attrs


def noop(attrs, new=False):
    return attrs


@pytest.mark.parametrize(
    "callback, expected",
    [
        (
            [noop],
            'a <a href="http://ex.mp">ex.mp</a> <a href="http://example.com">example</a>',
        ),
        ([no_new_links, noop], 'a ex.mp <a href="http://example.com">example</a>'),
        ([noop, no_new_links], 'a ex.mp <a href="http://example.com">example</a>'),
        ([no_old_links, noop], 'a <a href="http://ex.mp">ex.mp</a> example'),
        ([noop, no_old_links], 'a <a href="http://ex.mp">ex.mp</a> example'),
        ([no_old_links, no_new_links], "a ex.mp example"),
    ],
)
def test_prevent_links(callback, expected):
    """Returning None from any callback should remove links or prevent them
    from being created."""
    text = 'a ex.mp <a href="http://example.com">example</a>'
    assert linkify(text, callbacks=callback) == expected


def test_set_attrs():
    """We can set random attributes on links."""

    def set_attr(attrs, new=False):
        attrs[(None, "rev")] = "canonical"
        return attrs

    assert (
        linkify("ex.mp", callbacks=[set_attr])
        == '<a href="http://ex.mp" rev="canonical">ex.mp</a>'
    )


def test_only_proto_links():
    """Only create links if there's a protocol."""

    def only_proto(attrs, new=False):
        if new and not attrs["_text"].startswith(("http:", "https:")):
            return None
        return attrs

    in_text = 'a ex.mp http://ex.mp <a href="/foo">bar</a>'
    assert (
        linkify(in_text, callbacks=[only_proto])
        == 'a ex.mp <a href="http://ex.mp">http://ex.mp</a> <a href="/foo">bar</a>'
    )


def test_stop_email():
    """Returning None should prevent a link from being created."""

    def no_email(attrs, new=False):
        if attrs[(None, "href")].startswith("mailto:"):
            return None
        return attrs

    text = "do not link james@example.com"

    assert linkify(text, parse_email=True, callbacks=[no_email]) == text


@pytest.mark.parametrize(
    "data, expected",
    [
        # tlds
        ("example.com", '<a href="http://example.com" rel="nofollow">example.com</a>'),
        ("example.co", '<a href="http://example.co" rel="nofollow">example.co</a>'),
        (
            "example.co.uk",
            '<a href="http://example.co.uk" rel="nofollow">example.co.uk</a>',
        ),
        ("example.edu", '<a href="http://example.edu" rel="nofollow">example.edu</a>'),
        ("example.xxx", '<a href="http://example.xxx" rel="nofollow">example.xxx</a>'),
        ("bit.ly/fun", '<a href="http://bit.ly/fun" rel="nofollow">bit.ly/fun</a>'),
        # non-tlds
        ("example.yyy", "example.yyy"),
        ("brie", "brie"),
    ],
)
def test_tlds(data, expected):
    assert linkify(data) == expected


@pytest.mark.parametrize(
    "data, expected",
    [
        ("< unrelated", "&lt; unrelated"),
        ("<U \x7f=&#;>", '<u \x7f="&amp;#;"></u>'),
    ],
)
def test_escaping(data, expected):
    assert linkify(data) == expected


def test_nofollow_off():
    assert (
        linkify("example.com", callbacks=[])
        == '<a href="http://example.com">example.com</a>'
    )


def test_link_in_html():
    assert (
        linkify("<i>http://yy.com</i>")
        == '<i><a href="http://yy.com" rel="nofollow">http://yy.com</a></i>'
    )
    assert (
        linkify("<em><strong>http://xx.com</strong></em>")
        == '<em><strong><a href="http://xx.com" rel="nofollow">http://xx.com</a></strong></em>'
    )


def test_links_https():
    assert (
        linkify("https://yy.com")
        == '<a href="https://yy.com" rel="nofollow">https://yy.com</a>'
    )


def test_add_rel_nofollow():
    """Verify that rel="nofollow" is added to an existing link"""
    assert (
        linkify('<a href="http://yy.com">http://yy.com</a>')
        == '<a href="http://yy.com" rel="nofollow">http://yy.com</a>'
    )


def test_url_with_path():
    assert linkify("http://example.com/path/to/file") == (
        '<a href="http://example.com/path/to/file" rel="nofollow">'
        + "http://example.com/path/to/file</a>"
    )


def test_link_ftp():
    assert linkify("ftp://ftp.mozilla.org/some/file") == (
        '<a href="ftp://ftp.mozilla.org/some/file" rel="nofollow">'
        + "ftp://ftp.mozilla.org/some/file</a>"
    )


def test_link_with_qs_with_array():
    """Test that urls pick up [] in querystring"""
    assert linkify("http://test.com?array[]=1&params_in[]=2") == (
        '<a href="http://test.com?array[]=1&amp;params_in[]=2" '
        + 'rel="nofollow">http://test.com?array[]=1&amp;params_in[]=2</a>'
    )


def test_link_query():
    assert (
        linkify("http://xx.com/?test=win")
        == '<a href="http://xx.com/?test=win" rel="nofollow">http://xx.com/?test=win</a>'
    )
    assert (
        linkify("xx.com/?test=win")
        == '<a href="http://xx.com/?test=win" rel="nofollow">xx.com/?test=win</a>'
    )
    assert (
        linkify("xx.com?test=win")
        == '<a href="http://xx.com?test=win" rel="nofollow">xx.com?test=win</a>'
    )


def test_link_fragment():
    assert (
        linkify("http://xx.com/path#frag")
        == '<a href="http://xx.com/path#frag" rel="nofollow">http://xx.com/path#frag</a>'
    )


def test_link_entities_in_qs():
    """Entities in the querystring get escaped"""
    assert (
        linkify("http://xx.com/?a=1&b=2")
        == '<a href="http://xx.com/?a=1&amp;b=2" rel="nofollow">http://xx.com/?a=1&amp;b=2</a>'
    )


def test_link_entities_in_characters_token():
    """Entitites in a Characters token don't get escaped"""
    assert linkify("foo &nbsp; bar") == "foo &nbsp; bar"


def test_link_entities_in_a_tag():
    """Entitites between an a start tag and an a end tag don't get escaped"""
    assert (
        linkify('<a href="/">Some&nbsp;entity&rsquo;s</a>', callbacks=[])
        == '<a href="/">Some&nbsp;entity&rsquo;s</a>'
    )


def test_escaped_html():
    """If I pass in escaped HTML, it should probably come out escaped."""
    s = "&lt;em&gt;strong&lt;/em&gt;"
    assert linkify(s) == s


def test_link_http_complete():
    assert linkify("https://user:pass@ftp.mozilla.org/x/y.exe?a=b&c=d&e#f") == (
        '<a href="https://user:pass@ftp.mozilla.org/x/y.exe?a=b&amp;c=d&amp;e#f" rel="nofollow">'
        + "https://user:pass@ftp.mozilla.org/x/y.exe?a=b&amp;c=d&amp;e#f</a>"
    )


def test_non_url():
    """document.vulnerable should absolutely not be linkified."""
    s = "document.vulnerable"
    assert linkify(s) == s


def test_javascript_url():
    """javascript: urls should never be linkified."""
    s = "javascript:document.vulnerable"
    assert linkify(s) == s


def test_unsafe_url():
    """Any unsafe char ({}[]<>, etc.) in the path should end URL scanning."""
    assert linkify('All your{"xx.yy.com/grover.png"}base are') == (
        'All your{"<a href="http://xx.yy.com/grover.png" rel="nofollow">xx.yy.com/grover.png</a>"}'
        + "base are"
    )


def test_skip_tags():
    """Skip linkification in skip tags"""
    simple = "http://xx.com <pre>http://xx.com</pre>"
    linked = (
        '<a href="http://xx.com" rel="nofollow">http://xx.com</a> '
        + "<pre>http://xx.com</pre>"
    )
    all_linked = (
        '<a href="http://xx.com" rel="nofollow">http://xx.com</a> '
        + '<pre><a href="http://xx.com" rel="nofollow">http://xx.com'
        + "</a></pre>"
    )
    assert linkify(simple, skip_tags={"pre"}) == linked
    assert linkify(simple) == all_linked

    already_linked = '<pre><a href="http://xx.com">xx</a></pre>'
    nofollowed = '<pre><a href="http://xx.com" rel="nofollow">xx</a></pre>'
    assert linkify(already_linked) == nofollowed
    assert linkify(already_linked, skip_tags={"pre"}) == nofollowed

    assert linkify(
        "<pre><code>http://example.com</code></pre>http://example.com",
        skip_tags={"pre"},
    ) == (
        "<pre><code>http://example.com</code></pre>"
        + '<a href="http://example.com" rel="nofollow">http://example.com</a>'
    )


def test_libgl():
    """libgl.so.1 should not be linkified."""
    s = "libgl.so.1"
    assert linkify(s) == s


@pytest.mark.parametrize(
    "url, periods",
    [
        ("example.com", "."),
        ("example.com", "..."),
        ("ex.com/foo", "."),
        ("ex.com/foo", "...."),
    ],
)
def test_end_of_sentence(url, periods):
    """example.com. should match."""
    assert (
        linkify(f"{url}{periods}")
        == f'<a href="http://{url}" rel="nofollow">{url}</a>{periods}'
    )


def test_end_of_clause():
    """example.com/foo, shouldn't include the ,"""
    assert (
        linkify("ex.com/foo, bar")
        == '<a href="http://ex.com/foo" rel="nofollow">ex.com/foo</a>, bar'
    )


def test_sarcasm():
    """Jokes should crash.<sarcasm/>"""
    assert linkify("Yeah right <sarcasm/>") == "Yeah right &lt;sarcasm/&gt;"


@pytest.mark.parametrize(
    "data, expected_parts",
    [
        (
            "(example.com)",
            {
                "before": "(",
                "url": "http://example.com",
                "text": "example.com",
                "after": ")",
            },
        ),
        (
            "(example.com/)",
            {
                "before": "(",
                "url": "http://example.com/",
                "text": "example.com/",
                "after": ")",
            },
        ),
        (
            "(example.com/foo)",
            {
                "before": "(",
                "url": "http://example.com/foo",
                "text": "example.com/foo",
                "after": ")",
            },
        ),
        (
            "(((example.com/))))",
            {
                "before": "(((",
                "url": "http://example.com/",
                "text": "example.com/",
                "after": "))))",
            },
        ),
        (
            "example.com/))",
            {
                "before": "",
                "url": "http://example.com/",
                "text": "example.com/",
                "after": "))",
            },
        ),
        (
            "(foo http://example.com/)",
            {
                "before": "(foo ",
                "url": "http://example.com/",
                "text": "http://example.com/",
                "after": ")",
            },
        ),
        (
            "(foo http://example.com)",
            {
                "before": "(foo ",
                "url": "http://example.com",
                "text": "http://example.com",
                "after": ")",
            },
        ),
        (
            "http://en.wikipedia.org/wiki/Test_(assessment)",
            {
                "before": "",
                "url": "http://en.wikipedia.org/wiki/Test_(assessment)",
                "text": "http://en.wikipedia.org/wiki/Test_(assessment)",
                "after": "",
            },
        ),
        (
            "(http://en.wikipedia.org/wiki/Test_(assessment))",
            {
                "before": "(",
                "url": "http://en.wikipedia.org/wiki/Test_(assessment)",
                "text": "http://en.wikipedia.org/wiki/Test_(assessment)",
                "after": ")",
            },
        ),
        (
            "((http://en.wikipedia.org/wiki/Test_(assessment))",
            {
                "before": "((",
                "url": "http://en.wikipedia.org/wiki/Test_(assessment",
                "text": "http://en.wikipedia.org/wiki/Test_(assessment",
                "after": "))",
            },
        ),
        (
            "(http://en.wikipedia.org/wiki/Test_(assessment)))",
            {
                "before": "(",
                "url": "http://en.wikipedia.org/wiki/Test_(assessment))",
                "text": "http://en.wikipedia.org/wiki/Test_(assessment))",
                "after": ")",
            },
        ),
        (
            "(http://en.wikipedia.org/wiki/)Test_(assessment",
            {
                "before": "(",
                "url": "http://en.wikipedia.org/wiki/)Test_(assessment",
                "text": "http://en.wikipedia.org/wiki/)Test_(assessment",
                "after": "",
            },
        ),
        (
            "hello (http://www.mu.de/blah.html) world",
            {
                "before": "hello (",
                "url": "http://www.mu.de/blah.html",
                "text": "http://www.mu.de/blah.html",
                "after": ") world",
            },
        ),
        (
            "hello (http://www.mu.de/blah.html). world",
            {
                "before": "hello (",
                "url": "http://www.mu.de/blah.html",
                "text": "http://www.mu.de/blah.html",
                "after": "). world",
            },
        ),
    ],
)
def test_wrapping_parentheses(data, expected_parts):
    """URLs wrapped in parantheses should not include them."""
    before = expected_parts["before"]
    url = expected_parts["url"]
    text = expected_parts["text"]
    after = expected_parts["after"]
    assert linkify(data) == f'{before}<a href="{url}" rel="nofollow">{text}</a>{after}'


def test_parentheses_with_removing():
    expected = "(test.py)"
    assert linkify(expected, callbacks=[lambda *a: None]) == expected


@pytest.mark.parametrize(
    "data, expected_url, expected_after",
    [
        # Test valid ports
        ("http://foo.com:8000", "http://foo.com:8000", ""),
        ("http://foo.com:8000/", "http://foo.com:8000/", ""),
        # Test non ports
        ("http://bar.com:xkcd", "http://bar.com", ":xkcd"),
        ("http://foo.com:81/bar", "http://foo.com:81/bar", ""),
        ("http://foo.com:", "http://foo.com", ":"),
        # Test non-ascii ports
        ("http://foo.com:\u0663\u0669/", "http://foo.com", ":\u0663\u0669/"),
        (
            "http://foo.com:\U0001d7e0\U0001d7d8/",
            "http://foo.com",
            ":\U0001d7e0\U0001d7d8/",
        ),
    ],
)
def test_ports(data, expected_url, expected_after):
    """URLs can contain port numbers."""
    assert (
        linkify(data)
        == f'<a href="{expected_url}" rel="nofollow">{expected_url}</a>{expected_after}'
    )


def test_ignore_bad_protocols():
    assert linkify("foohttp://bar") == "foohttp://bar"
    assert (
        linkify("fohttp://exampl.com")
        == 'fohttp://<a href="http://exampl.com" rel="nofollow">exampl.com</a>'
    )


def test_link_emails_and_urls():
    """parse_email=True shouldn't prevent URLs from getting linkified."""
    assert linkify("http://example.com person@example.com", parse_email=True) == (
        '<a href="http://example.com" rel="nofollow">'
        + 'http://example.com</a> <a href="mailto:person@example.com">'
        + "person@example.com</a>"
    )


def test_links_case_insensitive():
    """Protocols and domain names are case insensitive."""
    expect = '<a href="HTTP://EXAMPLE.COM" rel="nofollow">HTTP://EXAMPLE.COM</a>'
    assert linkify("HTTP://EXAMPLE.COM") == expect


def test_elements_inside_links():
    assert (
        linkify('<a href="#">hello<br></a>')
        == '<a href="#" rel="nofollow">hello<br></a>'
    )

    assert (
        linkify('<a href="#"><strong>bold</strong> hello<br></a>')
        == '<a href="#" rel="nofollow"><strong>bold</strong> hello<br></a>'
    )


def test_drop_link_tags():
    """Verify that dropping link tags *just* drops the tag and not the content"""
    html = (
        'first <a href="http://example.com/1/">second</a> third <a href="http://example.com/2/">'
        + "fourth</a> fifth"
    )
    assert (
        linkify(html, callbacks=[lambda attrs, new: None])
        == "first second third fourth fifth"
    )


@pytest.mark.parametrize(
    "text, expected",
    [
        ("&lt;br&gt;", "&lt;br&gt;"),
        (
            "&lt;br&gt; http://example.com",
            '&lt;br&gt; <a href="http://example.com" rel="nofollow">http://example.com</a>',
        ),
        (
            "&lt;br&gt; <br> http://example.com",
            '&lt;br&gt; <br> <a href="http://example.com" rel="nofollow">http://example.com</a>',
        ),
    ],
)
def test_naughty_unescaping(text, expected):
    """Verify that linkify is not unescaping things it shouldn't be"""
    assert linkify(text) == expected


def test_hang():
    """This string would hang linkify. Issue #200"""
    assert (
        linkify("an@email.com<mailto:an@email.com>", parse_email=True)
        == '<a href="mailto:an@email.com">an@email.com</a>&lt;mailto:<a href="mailto:an@email.com">an@email.com</a>&gt;'  # noqa
    )


def test_hyphen_in_mail():
    """Test hyphens `-` in mails. Issue #300."""
    assert (
        linkify("ex@am-ple.com", parse_email=True)
        == '<a href="mailto:ex@am-ple.com">ex@am-ple.com</a>'
    )


def test_url_re_arg():
    """Verifies that a specified url_re is used"""
    fred_re = re.compile(r"""(fred\.com)""")

    linker = Linker(url_re=fred_re)
    assert (
        linker.linkify("a b c fred.com d e f")
        == 'a b c <a href="http://fred.com" rel="nofollow">fred.com</a> d e f'
    )

    assert (
        linker.linkify("a b c http://example.com d e f")
        == "a b c http://example.com d e f"
    )


def test_email_re_arg():
    """Verifies that a specified email_re is used"""
    fred_re = re.compile(r"""(fred@example\.com)""")

    linker = Linker(parse_email=True, email_re=fred_re)
    assert (
        linker.linkify("a b c fred@example.com d e f")
        == 'a b c <a href="mailto:fred@example.com">fred@example.com</a> d e f'
    )

    assert (
        linker.linkify("a b c jim@example.com d e f") == "a b c jim@example.com d e f"
    )


def test_recognized_tags_arg():
    """Verifies that recognized_tags works"""
    # The html parser doesn't recognize "sarcasm" as a tag, so it escapes it
    linker = Linker(recognized_tags={"p"})
    assert (
        linker.linkify("<p>http://example.com/</p><sarcasm>")
        == '<p><a href="http://example.com/" rel="nofollow">http://example.com/</a></p>&lt;sarcasm&gt;'  # noqa
    )

    # The html parser recognizes "sarcasm" as a tag and fixes it
    linker = Linker(recognized_tags={"p", "sarcasm"})
    assert (
        linker.linkify("<p>http://example.com/</p><sarcasm>")
        == '<p><a href="http://example.com/" rel="nofollow">http://example.com/</a></p><sarcasm></sarcasm>'  # noqa
    )


@pytest.mark.parametrize(
    "data",
    [
        "<span>text & </span>",
        "a < b",
        "link http://link.com",
        "text<em>",
        "jim &current joe",
        # Link with querystring items
        '<a href="http://example.com?foo=bar&bar=foo&amp;biz=bash">',
    ],
)
def test_linkify_idempotent(data):
    assert linkify(linkify(data)) == linkify(data)


class TestLinkify:
    def test_no_href_links(self):
        s = '<a name="anchor">x</a>'
        assert linkify(s) == s

    def test_rel_already_there(self):
        """Make sure rel attribute is updated not replaced"""
        linked = 'Click <a href="http://example.com" rel="tooltip">here</a>.'

        link_good = (
            'Click <a href="http://example.com" rel="tooltip nofollow">here</a>.'
        )

        assert linkify(linked) == link_good
        assert linkify(link_good) == link_good

    def test_only_text_is_linkified(self):
        some_text = "text"
        some_type = int
        no_type = None

        assert linkify(some_text) == some_text

        with pytest.raises(TypeError):
            linkify(some_type)

        with pytest.raises(TypeError):
            linkify(no_type)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("abc", "abc"),
        ("example.com", '<a href="http://example.com" rel="nofollow">example.com</a>'),
        (
            "http://example.com?b=1&c=2",
            '<a href="http://example.com?b=1&amp;c=2" rel="nofollow">http://example.com?b=1&amp;c=2</a>',
        ),
        (
            "http://example.com?b=1&amp;c=2",
            '<a href="http://example.com?b=1&amp;c=2" rel="nofollow">http://example.com?b=1&amp;c=2</a>',
        ),
        (
            "link: https://example.com/watch#anchor",
            'link: <a href="https://example.com/watch#anchor" rel="nofollow">https://example.com/watch#anchor</a>',
        ),
    ],
)
def test_linkify_filter(text, expected):
    cleaner = Cleaner(filters=[LinkifyFilter])
    assert cleaner.clean(text) == expected


class TestLinkPolicy:
    def linker(self):
        return Linker(policy=LinkPolicy())

    @pytest.mark.parametrize(
        "text",
        [
            # userinfo / @ confusion
            "http://paypal.com@evil.example/login",
            "http://user:pass@example.com/",
            # non-http(s) schemes
            "ftp://example.com/",
            # backslashes and control/whitespace characters
            r"http://example.com\@evil.com/path",
            "http://example.com/a\tb",
            "http://example.com/a\x01b",
            "http://example.com/a\x7fb",
            # executable schemes in the fragment
            "http://example.com/#javascript:alert(1)",
            "http://example.com/#JAVASCRIPT:alert(1)",
            "http://example.com/# vbscript:msgbox(1)",
            "http://example.com/#data:text/html,abc",
            "http://example.com/#file:///etc/passwd",
            # percent-encoded host
            "http://example%2fcom/",
            # numeric and hexadecimal IPs
            "http://192.168.1.1/",
            "http://0x7f.1/",
            "http://2130706433/",
            "http://[::1]/",
            # single-label, dotted and trailing-dot hosts
            "http://localhost/",
            "http://example.com./",
            "http://exa..mple.com/",
            # overlong label / hostname
            "http://%s.com/" % ("a" * 64),
            "http://%s/" % ".".join(["a" * 63] * 4 + ["com"]),
            # bad punycode that doesn't normalize back to itself
            "http://xn--fa-hia.de/",
            # mixed-script (Latin + Cyrillic) homograph label
            "http://payp\u0430l.com/",
            # malformed port
            "http://example.com:bad/",
        ],
    )
    def test_rejected_urls_keep_original_text(self, text):
        # No link is generated and the whole input text is preserved.
        assert self.linker().linkify(text) == text

    @pytest.mark.parametrize(
        "text, expected_href, expected_text",
        [
            (
                "http://M\u00fcnchen.de/",
                "http://xn--mnchen-3ya.de/",
                "http://M\u00fcnchen.de/",
            ),
            (
                "http://xn--mnchen-3ya.de/",
                "http://xn--mnchen-3ya.de/",
                "http://xn--mnchen-3ya.de/",
            ),
            (
                "https://EXAMPLE.com/Path?x=1#frag",
                "https://example.com/Path?x=1#frag",
                "https://EXAMPLE.com/Path?x=1#frag",
            ),
            (
                "example.com/path",
                "http://example.com/path",
                "example.com/path",
            ),
            # percent-encoded path components are fine--only hosts reject %%
            (
                "http://example.com/a%2f..%2fbar",
                "http://example.com/a%2f..%2fbar",
                "http://example.com/a%2f..%2fbar",
            ),
            # a label exactly at the 63 octet limit is accepted
            (
                "http://%s.com/" % ("a" * 63),
                "http://%s.com/" % ("a" * 63),
                "http://%s.com/" % ("a" * 63),
            ),
        ],
    )
    def test_accepted_urls_are_normalized(self, text, expected_href, expected_text):
        assert self.linker().linkify(text) == (
            '<a href="%s" rel="nofollow">%s</a>' % (expected_href, expected_text)
        )

    @pytest.mark.parametrize(
        "url",
        [
            "http://M\u00fcnchen.de/foo",
            "https://EXAMPLE.com:8080/a?b=1#c",
            "http://xn--mnchen-3ya.de/",
            "http://example.com/a%2fb",
        ],
    )
    def test_normalize_is_idempotent(self, url):
        policy = LinkPolicy()
        once = policy.normalize(url)
        assert once is not None
        assert policy.normalize(once) == once

    def test_policy_is_callable(self):
        policy = LinkPolicy()
        assert policy("http://example.com/") == policy.normalize(
            "http://example.com/"
        )
        assert policy("http://localhost/") is None

    def test_linkify_with_policy_is_idempotent(self):
        linker = self.linker()
        text = (
            "visit http://M\u00fcnchen.de/ and https://Example.com/a%2fb; "
            "the http://exa..mple.com/ stays text"
        )
        once = linker.linkify(text)
        assert linker.linkify(once) == once

    def test_percent_encoded_path_kept_but_percent_host_rejected(self):
        linker = self.linker()
        assert linker.linkify("http://example.com/a%2f..%2fb") == (
            '<a href="http://example.com/a%2f..%2fb" rel="nofollow">'
            "http://example.com/a%2f..%2fb</a>"
        )
        assert linker.linkify("http://example%2fcom/") == (
            "http://example%2fcom/"
        )

    def test_existing_a_tag_href_is_not_rewritten(self):
        # The policy only applies to auto-discovered URLs; existing <a> hrefs
        # are the sanitizer's job and must pass through untouched.
        text = '<a href="http://192.168.1.1/">already linked</a>'
        assert self.linker().linkify(text) == (
            '<a href="http://192.168.1.1/" rel="nofollow">already linked</a>'
        )

    def test_existing_link_not_wrapped_again(self):
        text = '<a href="http://example.com/x">already</a> and example.com/y'
        assert self.linker().linkify(text) == (
            '<a href="http://example.com/x" rel="nofollow">already</a> and '
            '<a href="http://example.com/y" rel="nofollow">example.com/y</a>'
        )

    def test_rejected_match_keeps_surrounding_text_intact(self):
        assert self.linker().linkify("see http://exa..mple.com/ now") == (
            "see http://exa..mple.com/ now"
        )

    def test_linkify_filter_accepts_policy(self):
        class PolicyFilter(LinkifyFilter):
            def __init__(self, source, **kwargs):
                super().__init__(source, policy=LinkPolicy(), **kwargs)

        cleaner = Cleaner(filters=[PolicyFilter])
        assert cleaner.clean("see http://192.168.1.1/ and http://example.com/") == (
            "see http://192.168.1.1/ and "
            '<a href="http://example.com/" rel="nofollow">http://example.com/</a>'
        )

    @pytest.mark.parametrize(
        "text",
        [
            "http://paypal.com@evil.example/login",
            "http://exa..mple.com/",
            "http://192.168.1.1/",
            r"http://example.com\@evil.com/",
            "http://example%2fcom/",
            "http://%s.com/" % ("a" * 64),
        ],
    )
    def test_none_policy_keeps_legacy_behavior(self, text):
        assert Linker().linkify(text) == linkify(text)

    def test_punycode_roundtrip_spoof_rejected(self):
        # xn--fa-hia decodes but IDNA re-encodes it to a different label,
        # so it must not be accepted as a canonical hostname.
        assert LinkPolicy().normalize("http://xn--fa-hia.de/") is None

    def test_mixed_script_label_rejected_but_single_scripts_pass(self):
        policy = LinkPolicy()
        assert policy.normalize("http://payp\u0430l.com/") is None
        # An all-Cyrillic label uses one script and is acceptable
        assert (
            policy.normalize("http://\u0440\u043e\u0441\u0441\u0438\u044f.example/")
            is not None
        )
