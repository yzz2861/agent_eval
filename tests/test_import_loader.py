import pytest

from tinycss2 import parse_stylesheet
from tinycss2.loader import (
    ImportCycleError,
    ImportDepthError,
    ImportGraph,
    ImportParseError,
    ImportPolicyError,
    ImportSizeError,
    UnsupportedConditionError,
    load_stylesheet,
)

ROOT = 'https://example.test/styles/base.css?version=1#old'


def make_fetcher(stylesheets, calls=None):
    if calls is None:
        calls = []

    def fetcher(url):
        calls.append(url)
        return stylesheets[url]

    fetcher.calls = calls
    return fetcher


def test_import_graph_preserves_relative_media_conditions_and_requests_once():
    stylesheets = {
        'https://example.test/styles/base.css': (
            '@font-face { font-family: Local; }\n'
            '@import "fonts/regular.css" layer(fonts) '
            'supports(display: grid) screen and (min-width: 10px);\n'
            '@import "theme.css";\n'
            '@import "theme.css";\n'),
        'https://example.test/styles/fonts/regular.css': (
            '@font-face { font-family: Regular; }'),
        'https://example.test/styles/theme.css': 'body { color: black; }',
    }
    fetcher = make_fetcher(stylesheets)

    graph = load_stylesheet(ROOT, fetcher, css=stylesheets[next(iter(stylesheets))])

    assert graph.root_url == 'https://example.test/styles/base.css?version=1'
    assert graph.request_count == 2
    assert fetcher.calls == [
        'https://example.test/styles/fonts/regular.css',
        'https://example.test/styles/theme.css']
    assert len(graph.nodes) == 3
    assert graph.duplicate_urls == {'https://example.test/styles/theme.css'}
    assert graph.duplicate_cache_keys == [graph.edges[2].cache_key]
    edge = graph.edges[0]
    assert edge.condition.layer == 'fonts'
    assert edge.condition.supports == 'display: grid'
    assert edge.condition.media == 'screen and (min-width: 10px)'
    assert edge.cache_key[0] == edge.child_url
    assert edge.cache_key[1] == edge.condition.cache_key()
    assert graph.children(graph.root_url)[1].depth == 1


def test_deep_import_chain_is_limited_before_extra_request():
    stylesheets = {
        f'https://example.test/{index}.css': f'@import "/{index + 1}.css";'
        for index in range(4)}
    stylesheets['https://example.test/3.css'] = 'body { color: black; }'
    fetcher = make_fetcher(stylesheets)

    with pytest.raises(ImportDepthError) as info:
        load_stylesheet(
            'https://example.test/0.css', fetcher, max_depth=2)

    assert info.value.url == 'https://example.test/3.css'
    assert graph_like(info).request_count == 3
    assert fetcher.calls == [
        'https://example.test/0.css', 'https://example.test/1.css',
        'https://example.test/2.css']


def test_import_cycle_is_distinct_from_duplicate_and_does_not_fetch_again():
    stylesheets = {
        'https://example.test/a.css': '@import "/b.css";',
        'https://example.test/b.css': '@import "/a.css";',
    }
    fetcher = make_fetcher(stylesheets)

    with pytest.raises(ImportCycleError) as info:
        load_stylesheet('https://example.test/a.css', fetcher)

    assert info.value.url == 'https://example.test/a.css'
    assert graph_like(info).request_count == 2
    assert fetcher.calls == [
        'https://example.test/a.css', 'https://example.test/b.css']


def test_direct_self_import_is_cycle_without_second_request():
    stylesheets = {
        'https://example.test/a.css': '@import "/a.css";',
    }
    fetcher = make_fetcher(stylesheets)
    with pytest.raises(ImportCycleError):
        load_stylesheet('https://example.test/a.css', fetcher)
    assert fetcher.calls == ['https://example.test/a.css']


def test_relative_path_traversal_is_canonical_before_policy_check():
    stylesheets = {
        'https://example.test/public/base.css':
            '@import "../private/secret.css?token=abc";',
        'https://example.test/private/secret.css?token=abc': 'a { color: red; }',
    }
    calls = []

    def policy(url, root_url):
        if '/private/' in url:
            raise RuntimeError('blocked')

    with pytest.raises(ImportPolicyError) as info:
        load_stylesheet(
            'https://example.test/public/base.css',
            make_fetcher(stylesheets, calls),
            css=stylesheets['https://example.test/public/base.css'],
            url_policy=policy)

    assert info.value.url == \
        'https://example.test/private/secret.css?<redacted>'
    assert calls == []


def test_unsupported_nested_condition_is_distinct_from_parse_failure():
    css = '@import "x.css" screen and unknown(condition)'
    fetcher = make_fetcher({'https://example.test/x.css': ''})

    with pytest.raises(UnsupportedConditionError):
        load_stylesheet('https://example.test/base.css', fetcher, css=css)
    assert fetcher.calls == []

    with pytest.raises(ImportParseError):
        load_stylesheet(
            'https://example.test/base.css',
            make_fetcher({}),
            css='@import;')
    with pytest.raises(ImportParseError):
        load_stylesheet(
            'https://example.test/base.css',
            make_fetcher({}),
            css='@import url(foo bar);')


def test_block_import_bad_scheme_and_fetch_failure_are_distinct():
    with pytest.raises(ImportParseError, match='block'):
        load_stylesheet(
            'https://example.test/base.css', make_fetcher({}),
            css='@import "x.css" { color: red; }')

    with pytest.raises(ImportPolicyError):
        load_stylesheet(
            'https://example.test/base.css', make_fetcher({}),
            css='@import "file:///etc/secret";')

    def broken_fetcher(url):
        raise OSError('network unavailable')

    with pytest.raises(ImportParseError, match='could not be loaded'):
        load_stylesheet(
            'https://example.test/base.css', broken_fetcher,
            css='@import "child.css";')


def test_condition_policy_can_reject_media_while_parser_keeps_rule():
    def condition_policy(condition):
        if condition.media == '3d-glasses':
            raise UnsupportedConditionError('unsupported media')

    with pytest.raises(UnsupportedConditionError, match='unsupported media'):
        load_stylesheet(
            'https://example.test/base.css', make_fetcher({}),
            css='@import "x.css" 3d-glasses;',
            condition_policy=condition_policy)


@pytest.mark.parametrize('css', [
    '@import "x.css" layer(a) layer(b);',
    '@import "x.css" supports(display: grid) layer(a);',
    '@import "x.css" supports([display]);',
])
def test_invalid_import_conditions_are_unsupported_without_request(css):
    fetcher = make_fetcher({})
    with pytest.raises(UnsupportedConditionError):
        load_stylesheet('https://example.test/base.css', fetcher, css=css)
    assert fetcher.calls == []


def test_node_and_byte_budgets_are_separate_errors():
    stylesheets = {
        'https://example.test/base.css':
            '@import "a.css"; @import "b.css";',
        'https://example.test/a.css': 'a {}',
        'https://example.test/b.css': 'b {}',
    }
    fetcher = make_fetcher(stylesheets)
    with pytest.raises(ImportSizeError, match='number of nodes'):
        load_stylesheet(
            'https://example.test/base.css', fetcher, max_nodes=2)

    stylesheets = {
        'https://example.test/base.css': '@import "big.css";',
        'https://example.test/big.css': 'x' * 10,
    }
    with pytest.raises(ImportSizeError, match='byte size'):
        load_stylesheet(
            'https://example.test/base.css', make_fetcher(stylesheets),
            max_bytes=5)


def test_cache_key_includes_conditions_and_query_is_redacted_in_errors():
    stylesheets = {
        'https://example.test/base.css': (
            '@import "child.css?x=1" screen;\n'
            '@import "child.css?x=1" print;'),
        'https://example.test/child.css?x=1': 'a {}',
    }
    fetcher = make_fetcher(stylesheets)
    cache = {}
    cache[ImportGraph.content_cache_key(
        'https://example.test/base.css')] = stylesheets[
        'https://example.test/base.css']
    graph = load_stylesheet(
        'https://example.test/base.css', fetcher, cache=cache)

    assert graph.request_count == 1
    assert len(cache) == 2
    assert len(graph.nodes) == 3
    assert graph.edges[0].cache_key != graph.edges[1].cache_key

    def policy(url, root_url):
        if '/child.css' in url:
            raise RuntimeError(url)

    with pytest.raises(ImportPolicyError) as info:
        load_stylesheet(
            'https://example.test/base.css',
            make_fetcher(stylesheets),
            css='@import "child.css?secret=value";',
            url_policy=policy)
    assert 'secret=value' not in str(info.value)
    assert info.value.url.endswith('?<redacted>')


def test_canonical_url_normalization_and_policy_error_redaction():
    stylesheets = {
        'https://example.test/a/base.css': '@import "child.css#part";',
        'https://example.test/a/child.css': 'a {}',
    }
    graph = load_stylesheet(
        'HTTPS://EXAMPLE.TEST/a/base.css?x=1#root',
        make_fetcher(stylesheets),
        css=stylesheets['https://example.test/a/base.css'])

    assert graph.root_url == 'https://example.test/a/base.css?x=1'
    assert graph.edges[0].child_url == 'https://example.test/a/child.css'

    def policy(url, root_url):
        if 'child.css' in url:
            raise RuntimeError(f'blocked {url}')

    with pytest.raises(ImportPolicyError) as info:
        load_stylesheet(
            'https://example.test/a/base.css', make_fetcher({}),
            css='@import "child.css?token=secret#part";',
            url_policy=policy)
    assert 'token=secret' not in str(info.value)
    assert info.value.url == \
        'https://example.test/a/child.css?<redacted>'


def test_repeated_url_content_counts_bytes_once_across_conditions():
    stylesheets = {
        'https://example.test/base.css': (
            '@import "child.css" screen;\n'
            '@import "child.css" print;'),
        'https://example.test/child.css': 'a { color: red; }',
    }
    graph = load_stylesheet(
        'https://example.test/base.css', make_fetcher(stylesheets),
        max_bytes=100)

    assert len(graph.nodes) == 3
    child_nodes = [node for node in graph.nodes.values()
                   if node.url == 'https://example.test/child.css']
    assert len(child_nodes) == 2
    assert child_nodes[0].rules is child_nodes[1].rules
    assert graph.total_bytes == sum(
        len(css.encode('utf-8')) for css in set(stylesheets.values()))


def test_default_parse_api_still_returns_at_rule_tokens():
    rule, = parse_stylesheet(
        '@import "x.css" layer(a) supports(display: grid) screen;')
    assert rule.type == 'at-rule'
    assert rule.lower_at_keyword == 'import'
    assert rule.content is None


def test_nested_import_is_not_followed_as_stylesheet_edge():
    fetcher = make_fetcher({})
    graph = load_stylesheet(
        'https://example.test/base.css', fetcher,
        css='@media screen { @import "child.css"; }')
    assert graph.edges == []
    assert graph.request_count == 0
    assert fetcher.calls == []


def test_cached_import_is_still_checked_against_current_policy():
    stylesheets = {
        'https://example.test/base.css': (
            '@import "child.css" screen;\n'
            '@import "child.css" print;'),
        'https://example.test/child.css': 'a {}',
    }
    cache = {}
    allowed = load_stylesheet(
        'https://example.test/base.css', make_fetcher(stylesheets),
        cache=cache)
    assert allowed.request_count == 2

    def deny_child(url, root_url):
        if 'child.css' in url:
            raise ImportPolicyError('denied', url)

    with pytest.raises(ImportPolicyError):
        load_stylesheet(
            'https://example.test/base.css', make_fetcher(stylesheets),
            cache=cache, url_policy=deny_child)


def test_external_content_cache_avoids_request_for_cached_root_only():
    stylesheets = {
        'https://example.test/base.css': '@import "child.css";',
        'https://example.test/child.css': 'a {}',
    }
    fetcher = make_fetcher(stylesheets)
    cache = {ImportGraph.content_cache_key(
        'https://example.test/base.css'): stylesheets[
        'https://example.test/base.css']}
    graph = load_stylesheet(
        'https://example.test/base.css', fetcher, cache=cache)

    assert fetcher.calls == ['https://example.test/child.css']
    assert graph.request_count == 1
    assert graph.duplicate_urls == set()


def graph_like(exception_info):
    return exception_info.value.graph
