"""
Policy-driven loading of stylesheets connected by ``@import`` rules.

Parsing remains separate from loading. The low-level parser keeps its existing
token structures, while this module resolves URLs, enforces caller policy, and
builds a bounded import graph.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from .parser import parse_stylesheet
from .serializer import serialize

__all__ = [
    'ImportCondition', 'ImportCycleError', 'ImportDepthError', 'ImportEdge',
    'ImportGraph', 'ImportLoadError', 'ImportLoader', 'ImportNode',
    'ImportParseError', 'ImportPolicyError', 'ImportSizeError',
    'UnsupportedConditionError', 'default_url_policy', 'load_stylesheet']


class ImportLoadError(Exception):
    """Base class for stylesheet import loading errors."""

    def __init__(self, message, url=None, graph=None):
        super().__init__(message)
        self.url = _redact_url(url) if url else None
        self.graph = graph


class ImportParseError(ImportLoadError):
    """An import rule or imported stylesheet could not be parsed."""


class UnsupportedConditionError(ImportLoadError):
    """A layer, supports, or media condition is not supported."""


class ImportPolicyError(ImportLoadError):
    """A canonical URL was rejected by the loading policy."""


class ImportCycleError(ImportLoadError):
    """An import points to an active ancestor stylesheet."""


class ImportSizeError(ImportLoadError):
    """The graph exceeded its node or byte budget."""


class ImportDepthError(ImportLoadError):
    """An import exceeded the allowed nesting depth."""


@dataclass(frozen=True)
class ImportCondition:
    """Optional conditions attached to an ``@import`` rule."""

    layer: str | None = None
    supports: str | None = None
    media: str | None = None

    def cache_key(self):
        return (('layer', self.layer), ('supports', self.supports),
                ('media', self.media))


@dataclass
class ImportNode:
    """One conditional occurrence of a stylesheet in the import graph."""

    url: str
    depth: int
    condition: ImportCondition | None = None
    css: str | None = None
    rules: list = field(default_factory=list)
    byte_size: int = 0
    request_count: int = 0

    @property
    def cache_key(self):
        return self.url, \
            None if self.condition is None else self.condition.cache_key()


@dataclass(frozen=True)
class ImportEdge:
    """A directed parent-to-child import relationship."""

    parent_url: str
    child_url: str
    depth: int
    condition: ImportCondition
    cache_key: tuple
    source_line: int
    source_column: int


@dataclass
class ImportGraph:
    """Stylesheet nodes, import edges, budgets, and request statistics."""

    root_url: str
    max_depth: int
    max_nodes: int
    max_bytes: int
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    duplicate_urls: set = field(default_factory=set)
    duplicate_cache_keys: list = field(default_factory=list)
    fetched_urls: set = field(default_factory=set)
    seen_urls: set = field(default_factory=set)
    total_bytes: int = 0
    request_count: int = 0

    def node(self, key):
        return self.nodes[key]

    def children(self, url):
        return [edge for edge in self.edges if edge.parent_url == url]

    @staticmethod
    def cache_key(url, condition):
        return url, None if condition is None else condition.cache_key()

    @staticmethod
    def content_cache_key(url):
        return url, None


def _redact_url(url):
    parts = urlsplit(url)
    if not parts.query:
        return url
    return urlunsplit(parts._replace(query='<redacted>'))


def _canonical_url(url, base_url=None):
    if not isinstance(url, str) or not url.strip():
        raise ImportParseError('Import URL is empty.')
    try:
        resolved = urljoin(base_url + ('#' if base_url else ''), url) \
            if base_url else url
        parts = urlsplit(resolved)
        if parts.fragment:
            parts = parts._replace(fragment='')
        netloc = parts.netloc.lower() if parts.scheme.lower() in (
            'http', 'https') else parts.netloc
        canonical = urlunsplit((
            parts.scheme.lower(), netloc, parts.path, parts.query, ''))
        urlsplit(canonical)
    except ValueError:
        raise ImportParseError('Import URL could not be parsed.') from None
    if not urlsplit(canonical).scheme:
        raise ImportParseError('Import URL has no scheme.')
    return canonical


def default_url_policy(url, root_url=None):
    """Accept canonical URLs with a non-empty scheme and host."""
    parts = urlsplit(url)
    if not parts.scheme:
        raise ImportPolicyError('Import URL scheme is not allowed.', url)
    if not parts.hostname:
        raise ImportPolicyError('Import URL has no host.', url)


class ImportLoader:
    """Load stylesheets while building a bounded ``@import`` graph."""

    def __init__(self, fetcher, url_policy=default_url_policy, max_depth=5,
                 max_nodes=64, max_bytes=1024 * 1024, cache=None,
                 condition_policy=None):
        self.fetcher = fetcher
        self.url_policy = url_policy
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.max_bytes = max_bytes
        self.cache = {} if cache is None else cache
        self.condition_policy = condition_policy

    def load(self, url, css=None):
        canonical = _canonical_url(url)
        self._check_policy(canonical, canonical)
        graph = ImportGraph(
            canonical, self.max_depth, self.max_nodes, self.max_bytes)
        try:
            self._load_node(
                canonical, condition=None, css=css, graph=graph,
                ancestors=(), depth=0)
        except ImportLoadError as error:
            if error.graph is None:
                error.graph = graph
            raise
        return graph

    def _load_node(self, url, condition, css, graph, ancestors, depth):
        if url in ancestors:
            raise ImportCycleError('Import cycle detected.', url, graph)
        if condition is not None:
            self._check_policy(url, graph.root_url)

        key = graph.cache_key(url, condition)
        if key in graph.nodes:
            graph.duplicate_urls.add(url)
            graph.duplicate_cache_keys.append(key)
            return graph.nodes[key]
        if len(graph.nodes) >= graph.max_nodes:
            raise ImportSizeError(
                'Import graph exceeded the maximum number of nodes.', url,
                graph)

        node = ImportNode(url=url, depth=depth, condition=condition)
        graph.nodes[key] = node
        if url in graph.seen_urls:
            graph.duplicate_urls.add(url)
        graph.seen_urls.add(url)
        if graph.content_cache_key(url) in self.cache:
            graph.fetched_urls.add(url)

        if css is None:
            content_key = graph.content_cache_key(url)
            cached = self.cache.get(content_key)
            if cached is None:
                try:
                    cached = self.fetcher(url)
                except ImportLoadError:
                    raise
                except Exception:
                    raise ImportParseError(
                        'Stylesheet could not be loaded.', url, graph)
                self.cache[content_key] = cached
                graph.request_count += 1
                node.request_count = 1
                graph.fetched_urls.add(url)
            css = cached

        if isinstance(css, bytes):
            try:
                css = css.decode('utf-8')
            except UnicodeDecodeError:
                raise ImportParseError(
                    'Stylesheet is not valid UTF-8.', url, graph)
        if not isinstance(css, str):
            raise ImportParseError(
                'Fetcher must return CSS text or UTF-8 bytes.', url, graph)

        node.css = css
        node.byte_size = len(css.encode('utf-8'))
        existing_content = next((
            existing for existing in graph.nodes.values()
            if existing is not node and existing.url == url), None)
        if existing_content is None:
            graph.total_bytes += node.byte_size
        else:
            node.rules = existing_content.rules
            return node
        if graph.total_bytes > graph.max_bytes:
            raise ImportSizeError(
                'Import graph exceeded the maximum byte size.', url, graph)

        try:
            rules = parse_stylesheet(css, skip_comments=True)
        except Exception:
            raise ImportParseError(
                'Stylesheet could not be parsed.', url, graph) from None
        if any(rule.type == 'error' for rule in rules):
            raise ImportParseError(
                'Stylesheet contains a syntax error.', url, graph)
        node.rules = rules

        for rule in rules:
            if rule.type != 'at-rule' or rule.lower_at_keyword != 'import':
                continue
            if rule.content is not None:
                raise ImportParseError(
                    '@import rule must not contain a block.', url, graph)
            child_condition, target = self._parse_import(
                rule, url, graph)
            child_depth = depth + 1
            if child_depth > graph.max_depth:
                raise ImportDepthError(
                    'Import nesting depth limit exceeded.', target, graph)
            if target in (*ancestors, url):
                raise ImportCycleError(
                    'Import cycle detected.', target, graph)
            edge = ImportEdge(
                url, target, child_depth, child_condition,
                graph.cache_key(target, child_condition), rule.source_line,
                rule.source_column)
            graph.edges.append(edge)
            self._load_node(
                target, child_condition, None, graph, (*ancestors, url),
                child_depth)
        return node

    def _check_policy(self, url, root_url):
        try:
            self.url_policy(url, root_url)
        except Exception:
            raise ImportPolicyError(
                'Import URL was rejected by policy.', url) from None

    def _parse_import(self, rule, parent_url, graph):
        tokens = list(rule.prelude)
        if any(token.type == 'error' for token in tokens):
            raise ImportParseError(
                'Invalid @import rule token.', parent_url, graph)
        index = _skip_whitespace(tokens, 0)
        if index >= len(tokens):
            raise ImportParseError('Import rule has no URL.', parent_url, graph)
        target, index = _read_import_url(tokens, index, parent_url, graph)
        index = _skip_whitespace(tokens, index)
        condition = ImportCondition()
        kinds = []
        while index < len(tokens):
            token = tokens[index]
            if _is_function(token, 'layer'):
                kinds.append('layer')
                condition = ImportCondition(
                    layer=_parse_layer_arguments(
                        token.arguments, parent_url, graph),
                    supports=condition.supports, media=condition.media)
            elif _is_ident(token, 'layer'):
                kinds.append('layer')
                condition = ImportCondition(
                    layer='', supports=condition.supports,
                    media=condition.media)
            elif _is_function(token, 'supports'):
                kinds.append('supports')
                condition = ImportCondition(
                    layer=condition.layer,
                    supports=_parse_supports_arguments(
                        token.arguments, parent_url, graph),
                    media=condition.media)
            else:
                break
            index = _skip_whitespace(tokens, index + 1)

        if any(kinds.count(kind) > 1 for kind in ('layer', 'supports')):
            raise UnsupportedConditionError(
                'Duplicate import condition.', parent_url, graph)
        if 'supports' in kinds and kinds.index('supports') < \
                (kinds.index('layer') if 'layer' in kinds else -1):
            raise UnsupportedConditionError(
                'Import conditions are in the wrong order.', parent_url,
                graph)
        if index < len(tokens):
            media = serialize(tokens[index:]).strip()
            if not media:
                raise UnsupportedConditionError(
                    'Empty media condition.', parent_url, graph)
            for token in tokens[index:]:
                if token.type in ('function', '{} block', '[] block'):
                    raise UnsupportedConditionError(
                        'Unsupported media condition.', parent_url, graph)
                if _is_ident(token, 'layer') or _is_function(token, 'layer'):
                    raise UnsupportedConditionError(
                        'Unexpected layer condition.', parent_url, graph)
                if _is_function(token, 'supports'):
                    raise UnsupportedConditionError(
                        'Unexpected supports condition.', parent_url, graph)
            condition = ImportCondition(
                layer=condition.layer, supports=condition.supports,
                media=media)
        if self.condition_policy is not None:
            try:
                self.condition_policy(condition)
            except ImportLoadError:
                raise
            except Exception:
                raise UnsupportedConditionError(
                    'Import condition was rejected.', parent_url, graph) \
                    from None
        return condition, target


def load_stylesheet(url, fetcher, css=None, **options):
    """Load a stylesheet graph using :class:`ImportLoader`."""
    return ImportLoader(fetcher, **options).load(url, css=css)


def _skip_whitespace(tokens, index):
    while index < len(tokens) and tokens[index].type == 'whitespace':
        index += 1
    return index


def _read_import_url(tokens, index, parent_url, graph):
    if index >= len(tokens):
        raise ImportParseError('Import rule has no URL.', parent_url, graph)
    token = tokens[index]
    if token.type == 'string':
        raw_url = token.value
    elif token.type == 'url':
        raw_url = token.value
    elif _is_function(token, 'url'):
        strings = [item for item in token.arguments
                   if item.type != 'whitespace']
        if len(strings) != 1 or strings[0].type != 'string':
            raise ImportParseError(
                'url() import must contain one string.', parent_url, graph)
        raw_url = strings[0].value
    else:
        raise ImportParseError(
            'Import rule must start with a string or url() token.',
            parent_url, graph)
    try:
        return _canonical_url(raw_url, parent_url), index + 1
    except ImportParseError as error:
        error.graph = graph
        raise


def _is_ident(token, name):
    return token.type == 'ident' and token.lower_value == name


def _is_function(token, name):
    return token.type == 'function' and token.lower_name == name


def _has_unexpected_layer_tokens(tokens):
    return any(token.type not in (
        'ident', 'literal', 'whitespace') for token in tokens)


def _parse_layer_arguments(tokens, url, graph):
    significant = [token for token in tokens if token.type != 'whitespace']
    if not significant or _has_unexpected_layer_tokens(tokens):
        raise UnsupportedConditionError(
            'Unsupported layer condition.', url, graph)
    expected_ident = True
    for token in significant:
        if expected_ident:
            if token.type != 'ident':
                break
            expected_ident = False
        elif token != '.' or token.value != '.':
            break
        else:
            expected_ident = True
    else:
        if not expected_ident:
            return serialize(tokens).strip()
    raise UnsupportedConditionError(
        'Unsupported layer condition.', url, graph)


def _parse_supports_arguments(tokens, url, graph):
    if not any(token.type != 'whitespace' for token in tokens):
        raise UnsupportedConditionError(
            'Empty supports condition.', url, graph)
    for token in tokens:
        if token.type in ('{} block', '[] block'):
            raise UnsupportedConditionError(
                'Unsupported supports condition.', url, graph)
    return serialize(tokens).strip()
