import re
import unicodedata


class UnsafeURLError(ValueError):
    """A URL cannot safely be serialized in CSS."""

    def __init__(self, message, source_line=None, source_column=None):
        super().__init__(message)
        self.source_line = source_line
        self.source_column = source_column


_SAFE_URL_SCHEMES = frozenset({'data', 'http', 'https'})
_SAFE_DATA_MEDIA_TYPES = frozenset({
    'image/gif',
    'image/jpeg',
    'image/png',
    'image/webp',
})
_SCHEME_RE = re.compile(r'[A-Za-z][A-Za-z0-9+.-]*\Z')


def serialize(nodes):
    """Serialize nodes to CSS syntax.

    This should be used for :term:`component values`
    instead of just :meth:`tinycss2.ast.Node.serialize` on each node
    as it takes care of corner cases such as ``;`` between declarations,
    and consecutive identifiers
    that would otherwise parse back as the same token.

    :type nodes: :term:`iterable`
    :param nodes: An iterable of :class:`tinycss2.ast.Node` objects.
    :returns: A :obj:`string <str>` representing the nodes.

    """
    chunks = []
    _serialize_to(nodes, chunks.append)
    return ''.join(chunks)


def serialize_identifier(value):
    """Serialize any string as a CSS identifier

    :type value: :obj:`str`
    :param value: A string representing a CSS value.
    :returns:
        A :obj:`string <str>` that would parse as an
        :class:`tinycss2.ast.IdentToken` whose
        :attr:`tinycss2.ast.IdentToken.value` attribute equals the passed
        ``value`` argument.

    """
    if value == '-':
        return r'\-'

    if value[:2] == '--':
        return '--' + serialize_name(value[2:])

    if value[0] == '-':
        result = '-'
        value = value[1:]
    else:
        result = ''
    c = value[0]
    result += (
        c if c in ('abcdefghijklmnopqrstuvwxyz_'
                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ') or ord(c) > 0x7F else
        r'\A ' if c == '\n' else
        r'\D ' if c == '\r' else
        r'\C ' if c == '\f' else
        '\\%X ' % ord(c) if c in '0123456789' else
        '\\' + c
    )
    result += serialize_name(value[1:])
    return result


def serialize_name(value):
    return ''.join(
        c if c in ('abcdefghijklmnopqrstuvwxyz-_0123456789'
                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ') or ord(c) > 0x7F else
        r'\A ' if c == '\n' else
        r'\D ' if c == '\r' else
        r'\C ' if c == '\f' else
        '\\' + c
        for c in value
    )


_replacement_string_value = {
    '"': r'\"',
    '\\': r'\\',
    '\n': r'\A ',
    '\r': r'\D ',
    '\f': r'\C ',
}
_re_string_value = ''.join(re.escape(char) for char in _replacement_string_value)
_re_string_value = re.compile(f'[{_re_string_value}]', re.MULTILINE)
def _serialize_string_value_match(match):
    return _replacement_string_value[match.group(0)]
def serialize_string_value(value):
    return _re_string_value.sub(_serialize_string_value_match, value)


def serialize_url(value):
    return ''.join(
        r"\'" if c == "'" else
        r'\"' if c == '"' else
        r'\\' if c == '\\' else
        r'\ ' if c == ' ' else
        r'\9 ' if c == '\t' else
        r'\A ' if c == '\n' else
        r'\D ' if c == '\r' else
        r'\C ' if c == '\f' else
        r'\(' if c == '(' else
        r'\)' if c == ')' else
        c
        for c in value
    )


def safe_serialize_url(value, quoted=False):
    """Validate a decoded URL and serialize it for a CSS URL context."""
    _validate_safe_url(value)
    return f'url({_serialize_safe_url(value, quoted)})'


def _serialize_safe_url(value, quoted=False):
    if quoted:
        return f'"{serialize_string_value(value)}"'
    return serialize_url(value)


def safe_url_function_arguments(arguments):
    """Return the decoded URL represented by ``url()`` function arguments."""
    significant = []
    for node in arguments:
        if node.type == 'comment':
            raise UnsafeURLError('Unsafe URL: comments are not allowed')
        if node.type != 'whitespace':
            significant.append(node)

    if not significant:
        return '', False
    if len(significant) == 1 and significant[0].type == 'string':
        return significant[0].value, True
    if (len(significant) == 2 and significant[0].type == 'string' and
            significant[1].type == 'error' and
            significant[1].kind == 'eof-in-string'):
        return significant[0].value, True
    raise UnsafeURLError('Unsafe URL: unsupported url() argument')


def _validate_safe_url(value):
    if '\ufffd' in value:
        raise UnsafeURLError(
            'Unsafe URL: replacement characters are not allowed')
    if any(unicodedata.category(char) == 'Cc' or char == '\x7f'
           for char in value):
        raise UnsafeURLError('Unsafe URL: control characters are not allowed')
    if '\\' in value:
        raise UnsafeURLError('Unsafe URL: backslashes are not allowed')

    scheme_end = value.find(':')
    if scheme_end == -1 or not _SCHEME_RE.fullmatch(value[:scheme_end]):
        return

    scheme = value[:scheme_end].lower()
    if scheme not in _SAFE_URL_SCHEMES:
        raise UnsafeURLError('Unsafe URL: scheme is not allowed')
    if scheme == 'data':
        _validate_data_url(value[scheme_end + 1:])


def _validate_data_url(value):
    comma_position = value.find(',')
    if comma_position == -1:
        raise UnsafeURLError('Unsafe URL: malformed data URL')

    prefix = value[:comma_position]
    parts = prefix.split(';')
    media_type = parts[0].lower()
    if media_type not in _SAFE_DATA_MEDIA_TYPES:
        raise UnsafeURLError('Unsafe URL: data URL media type is not allowed')
    if len(parts) > 2 or (len(parts) == 2 and parts[1].lower() != 'base64'):
        raise UnsafeURLError('Unsafe URL: data URL parameters are not allowed')


# https://drafts.csswg.org/css-syntax/#serialization-tables
def _serialize_to(nodes, write):
    """Serialize an iterable of nodes to CSS syntax.

    White chunks as a string by calling the provided :obj:`write` callback.

    """
    bad_pairs = BAD_PAIRS
    previous_type = None
    for node in nodes:
        serialization_type = (node.type if node.type != 'literal'
                              else node.value)
        if (previous_type, serialization_type) in bad_pairs:
            write('/**/')
        elif previous_type == '\\' and not (
                serialization_type == 'whitespace' and
                node.value.startswith('\n')):
            write('\n')
        node._serialize_to(write)
        if serialization_type == 'declaration':
            write(';')
        previous_type = serialization_type


BAD_PAIRS = set(
    [(a, b)
        for a in ('ident', 'at-keyword', 'hash', 'dimension', '#', '-', 'number')
        for b in ('ident', 'function', 'url', 'number', 'percentage',
                  'dimension', 'unicode-range')] +
    [(a, b)
        for a in ('ident', 'at-keyword', 'hash', 'dimension')
        for b in ('-', '-->')] +
    [(a, b)
        for a in ('#', '-', 'number', '@')
        for b in ('ident', 'function', 'url')] +
    [(a, b)
        for a in ('unicode-range', '.', '+')
        for b in ('number', 'percentage', 'dimension')] +
    [('@', b) for b in ('ident', 'function', 'url', 'unicode-range', '-')] +
    [('unicode-range', b) for b in ('ident', 'function', '?')] +
    [(a, '=') for a in '$*^~|'] +
    [('ident', '() block'), ('|', '|'), ('/', '*')]
)
