import re
import sys

from webencodings import ascii_lower

from .ast import (  # isort: skip
    AtKeywordToken, Comment, CurlyBracketsBlock, DimensionToken, FunctionBlock,
    HashToken, IdentToken, LiteralToken, NumberToken, ParenthesesBlock, ParseError,
    PercentageToken, SquareBracketsBlock, StringToken, UnicodeRangeToken, URLToken,
    WhitespaceToken)
from .limits import _Budget
from .serializer import serialize_string_value, serialize_url

_NUMBER_RE = re.compile(r'[-+]?([0-9]*\.)?[0-9]+([eE][+-]?[0-9]+)?')
_HEX_ESCAPE_RE = re.compile(r'([0-9A-Fa-f]{1,6})[ \n\t]?')


def parse_component_value_list(css, skip_comments=False, limits=None):
    """Parse a list of component values.

    :type css: :obj:`str`
    :param css: A CSS string.
    :type skip_comments: :obj:`bool`
    :param skip_comments:
        Ignore CSS comments.
        The return values (and recursively its blocks and functions)
        will not contain any :class:`~tinycss2.ast.Comment` object.
    :type limits: :class:`~tinycss2.limits.ResourceLimits` or :obj:`None`
    :param limits:
        Per-parse resource limits.  A fresh budget is always created for
        each call, so counters are never shared between parses.  When
        :obj:`None`, the documented default limits are used.
    :returns: A list of :term:`component values`.

    """
    css = (css.replace('\0', '\uFFFD')
           # This turns out to be faster than a regexp:
           .replace('\r\n', '\n').replace('\r', '\n').replace('\f', '\n'))
    length = len(css)
    budget = _Budget(limits)
    if length > budget.limits.max_characters:
        return [ParseError(
            1, 1, 'input-too-long',
            f'Input has {length} characters, limit is '
            f'{budget.limits.max_characters}')]
    token_start_pos = pos = 0  # Character index in the css source.
    line = 1  # First line is line 1.
    last_newline = -1
    root = tokens = []
    end_char = None  # Pop the stack when encountering this character.
    stack = []  # Stack of nested blocks: (tokens, end_char) tuples.
    nesting_depth = 0

    def emit(node):
        """Append a token, enforcing the output token budget."""
        error = budget.add_token()
        if error is not None:
            tokens.append(ParseError(line, column, *error))
            return error
        tokens.append(node)
        return None

    def push_block(block, end_marker, content):
        """Open a nested block, enforcing the nesting budget."""
        nonlocal tokens, end_char, nesting_depth
        error = budget.add_token()
        if error is not None:
            return error
        if nesting_depth >= budget.limits.max_nesting:
            return ('nesting-too-deep',
                    f'Nesting depth exceeds {budget.limits.max_nesting}')
        tokens.append(block)
        stack.append((tokens, end_char))
        end_char = end_marker
        tokens = content
        nesting_depth += 1
        return None

    while pos < length:
        newline = css.rfind('\n', token_start_pos, pos)
        if newline != -1:
            line += 1 + css.count('\n', token_start_pos, newline)
            last_newline = newline
        # First character in a line is in column 1.
        column = pos - last_newline
        token_start_pos = pos
        c = css[pos]
        budget.begin_token()

        if c in ' \n\t':
            pos += 1
            while css.startswith((' ', '\n', '\t'), pos):
                pos += 1
            if emit(WhitespaceToken(line, column, css[token_start_pos:pos])):
                break
            continue
        elif (c in 'Uu' and pos + 2 < length and css[pos + 1] == '+' and
              css[pos + 2] in '0123456789abcdefABCDEF?'):
            start, end, pos = _consume_unicode_range(css, pos + 2)
            if emit(UnicodeRangeToken(line, column, start, end)):
                break
            continue
        elif css.startswith('-->', pos):  # Check before identifiers
            if emit(LiteralToken(line, column, '-->')):
                break
            pos += 3
            continue
        elif _is_ident_start(css, pos):
            value, pos, size_error = _consume_ident(css, pos, budget)
            if size_error is not None:
                emit(ParseError(line, column, *size_error))
                break
            if not css.startswith('(', pos):  # Not a function
                if emit(IdentToken(line, column, value)):
                    break
                continue
            pos += 1  # Skip the '('
            try:
                is_url = ascii_lower(value) == 'url'
            except UnicodeEncodeError:
                is_url = False
            if is_url:
                url_pos = pos
                while css.startswith((' ', '\n', '\t'), url_pos):
                    url_pos += 1
                if url_pos >= length or css[url_pos] not in ('"', "'"):
                    value, pos, error = _consume_url(css, pos, budget)
                    if value is not None and not _is_budget_error(error):
                        repr = f'url({serialize_url(value)})'
                        if error is not None:
                            error_key = error[0]
                            if error_key == 'eof-in-string':
                                repr = repr[:-2]
                            else:
                                assert error_key == 'eof-in-url'
                                repr = repr[:-1]
                        if emit(URLToken(line, column, value, repr)):
                            break
                    if error is not None:
                        if emit(ParseError(line, column, *error)):
                            break
                        if _is_budget_error(error):
                            break
                    continue
            arguments = []
            block_error = push_block(
                FunctionBlock(line, column, value, arguments), ')', arguments)
            if block_error is not None:
                emit(ParseError(line, column, *block_error))
                break
            continue

        match = _NUMBER_RE.match(css, pos)
        if match:
            pos = match.end()
            repr_ = css[token_start_pos:pos]
            value = float(repr_)
            int_value = int(repr_) if not any(match.groups()) else None
            if pos < length and _is_ident_start(css, pos):
                unit, pos, size_error = _consume_ident(css, pos, budget)
                if size_error is not None:
                    emit(ParseError(line, column, *size_error))
                    break
                if emit(DimensionToken(
                        line, column, value, int_value, repr_, unit)):
                    break
            elif css.startswith('%', pos):
                pos += 1
                if emit(PercentageToken(
                        line, column, value, int_value, repr_)):
                    break
            else:
                if emit(NumberToken(
                        line, column, value, int_value, repr_)):
                    break
        elif c == '@':
            pos += 1
            if pos < length and _is_ident_start(css, pos):
                value, pos, size_error = _consume_ident(css, pos, budget)
                if size_error is not None:
                    emit(ParseError(line, column, *size_error))
                    break
                if emit(AtKeywordToken(line, column, value)):
                    break
            else:
                if emit(LiteralToken(line, column, '@')):
                    break
        elif c == '#':
            pos += 1
            if pos < length and (
                    css[pos] in '0123456789abcdefghijklmnopqrstuvwxyz'
                                '-_ABCDEFGHIJKLMNOPQRSTUVWXYZ' or
                    ord(css[pos]) > 0x7F or  # Non-ASCII
                    # Valid escape:
                    (css[pos] == '\\' and not css.startswith('\\\n', pos))):
                is_identifier = _is_ident_start(css, pos)
                value, pos, size_error = _consume_ident(css, pos, budget)
                if size_error is not None:
                    emit(ParseError(line, column, *size_error))
                    break
                if emit(HashToken(line, column, value, is_identifier)):
                    break
            else:
                if emit(LiteralToken(line, column, '#')):
                    break
        elif c == '{':
            content = []
            block = CurlyBracketsBlock(line, column, content)
            block_error = push_block(block, '}', content)
            pos += 1
            if block_error is not None:
                emit(ParseError(line, column, *block_error))
                break
        elif c == '[':
            content = []
            block = SquareBracketsBlock(line, column, content)
            block_error = push_block(block, ']', content)
            pos += 1
            if block_error is not None:
                emit(ParseError(line, column, *block_error))
                break
        elif c == '(':
            content = []
            block = ParenthesesBlock(line, column, content)
            block_error = push_block(block, ')', content)
            pos += 1
            if block_error is not None:
                emit(ParseError(line, column, *block_error))
                break
        elif c == end_char:  # Matching }, ] or )
            # The top-level end_char is None (never equal to a character),
            # so we never get here if the stack is empty.
            tokens, end_char = stack.pop()
            nesting_depth -= 1
            pos += 1
        elif c in '}])':
            if emit(ParseError(line, column, c, 'Unmatched ' + c)):
                break
            pos += 1
        elif c in ('"', "'"):
            if nesting_depth >= budget.limits.max_nesting:
                emit(ParseError(
                    line, column, 'nesting-too-deep',
                    f'Nesting depth exceeds {budget.limits.max_nesting}'))
                break
            value, pos, error = _consume_quoted_string(css, pos, budget)
            if value is not None and not _is_budget_error(error):
                repr = f'"{serialize_string_value(value)}"'
                if error is not None:
                    repr = repr[:-1]
                if emit(StringToken(line, column, value, repr)):
                    break
            if error is not None:
                if emit(ParseError(line, column, *error)):
                    break
                if _is_budget_error(error):
                    break
        elif css.startswith('/*', pos):  # Comment
            pos, error = _consume_comment(
                css, pos, budget, skip_comments, line, column, emit)
            if error is not None:
                if emit(ParseError(line, column, *error)):
                    break
                break
        elif css.startswith('<!--', pos):
            if emit(LiteralToken(line, column, '<!--')):
                break
            pos += 4
        elif css.startswith('||', pos):
            if emit(LiteralToken(line, column, '||')):
                break
            pos += 2
        elif c in '~|^$*':
            pos += 1
            if css.startswith('=', pos):
                pos += 1
                if emit(LiteralToken(line, column, c + '=')):
                    break
            else:
                if emit(LiteralToken(line, column, c)):
                    break
        else:
            if emit(LiteralToken(line, column, c)):
                break
            pos += 1
    return root


def _is_name_start(css, pos):
    """Return true if the given character is a name-start code point."""
    # https://www.w3.org/TR/css-syntax-3/#name-start-code-point
    c = css[pos]
    return (
        c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_' or
        ord(c) > 0x7F)


def _is_ident_start(css, pos):
    """Return True if the given position is the start of a CSS identifier."""
    # https://drafts.csswg.org/css-syntax/#would-start-an-identifier
    if _is_name_start(css, pos):
        return True
    elif css[pos] == '-':
        pos += 1
        return (
            # Name-start code point or hyphen:
            (pos < len(css) and (_is_name_start(css, pos) or css[pos] == '-')) or
            # Valid escape:
            (css.startswith('\\', pos) and not css.startswith('\\\n', pos)))
    elif css[pos] == '\\':
        return not css.startswith('\\\n', pos)
    return False


# Errors raised by the resource budget: they stop tokenization immediately
# because continuing could keep spending the very resource that was exceeded.
_BUDGET_ERRORS = frozenset((
    'token-too-long', 'too-many-escapes', 'too-many-tokens',
    'nesting-too-deep'))


def _is_budget_error(error):
    return error is not None and error[0] in _BUDGET_ERRORS


def _consume_ident(css, pos, budget):
    """Return (unescaped_value, new_pos, budget_error).

    Assumes pos starts at a valid identifier. See :func:`_is_ident_start`.

    The budget error is :obj:`None` unless a resource limit was exceeded;
    when it is set the value still contains everything consumed so far and
    ``new_pos`` points just after the last consumed character.

    """
    # http://dev.w3.org/csswg/css-syntax/#consume-a-name
    chunks = []
    length = len(css)
    start_pos = pos
    budget_error = None
    while pos < length:
        c = css[pos]
        if c in ('abcdefghijklmnopqrstuvwxyz-_0123456789'
                 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') or ord(c) > 0x7F:
            pos += 1
        elif c == '\\' and not css.startswith('\\\n', pos):
            # Valid escape
            chunk = css[start_pos:pos]
            if budget.add_token_bytes(chunk) is not None:
                budget_error = ('token-too-long',
                                'Token exceeds '
                                f'{budget.limits.max_token_bytes} bytes')
                break
            chunks.append(chunk)
            budget_error = budget.charge_escape()
            if budget_error is not None:
                break
            c, pos = _consume_escape(css, pos + 1)
            if budget.add_token_bytes(c) is not None:
                budget_error = ('token-too-long',
                                'Token exceeds '
                                f'{budget.limits.max_token_bytes} bytes')
                break
            chunks.append(c)
            start_pos = pos
        else:
            break
    if budget_error is None:
        budget_error = budget.add_token_bytes(css[start_pos:pos])
    chunks.append(css[start_pos:pos])
    return ''.join(chunks), pos, budget_error


def _consume_quoted_string(css, pos, budget):
    """Return (unescaped_value, new_pos, error)."""
    # https://drafts.csswg.org/css-syntax/#consume-a-string-token
    error = None
    quote = css[pos]
    assert quote in ('"', "'")
    pos += 1
    chunks = []
    length = len(css)
    start_pos = pos
    while pos < length:
        c = css[pos]
        if c == quote:
            if budget.add_token_bytes(css[start_pos:pos]) is not None:
                error = ('token-too-long',
                         'Token exceeds '
                         f'{budget.limits.max_token_bytes} bytes')
                pos += 1
                break
            chunks.append(css[start_pos:pos])
            pos += 1
            break
        elif c == '\\':
            if budget.add_token_bytes(css[start_pos:pos]) is not None:
                error = ('token-too-long',
                         'Token exceeds '
                         f'{budget.limits.max_token_bytes} bytes')
                break
            chunks.append(css[start_pos:pos])
            pos += 1
            if pos < length:
                if css[pos] == '\n':  # Ignore escaped newlines
                    pos += 1
                else:
                    escape_error = budget.charge_escape()
                    if escape_error is not None:
                        error = escape_error
                        break
                    c, pos = _consume_escape(css, pos)
                    if budget.add_token_bytes(c) is not None:
                        error = ('token-too-long',
                                 'Token exceeds '
                                 f'{budget.limits.max_token_bytes} bytes')
                        break
                    chunks.append(c)
            # else: Escaped EOF, do nothing
            start_pos = pos
        elif c == '\n':  # Unescaped newline
            return None, pos, ('bad-string', 'Bad string token')
        else:
            pos += 1
    else:
        error = ('eof-in-string', 'EOF in string')
        if budget.add_token_bytes(css[start_pos:pos]) is not None:
            error = ('token-too-long',
                     'Token exceeds '
                     f'{budget.limits.max_token_bytes} bytes')
        chunks.append(css[start_pos:pos])
    return ''.join(chunks), pos, error


def _consume_comment(css, pos, budget, skip_comments, line, column, emit):
    """Consume a comment in a single forward scan.

    Returns the position just after the closing ``*/`` (or the end of the
    input for an unclosed comment) and an optional budget error tuple.
    Nested comment openers are counted while moving forward instead of
    restarting a search, so error recovery never rescans an already
    consumed prefix.

    """
    length = len(css)
    content_start = pos + 2
    scan = content_start
    nested_openers = 0

    def comment_too_large(comment_end):
        size = len(css[content_start:comment_end].encode(
            'utf-8', 'surrogatepass'))
        if size > budget.limits.max_token_bytes:
            return ('token-too-long',
                    'Token exceeds '
                    f'{budget.limits.max_token_bytes} bytes')
        return None

    while scan < length:
        if css.startswith('*/', scan):
            end = scan
            pos = scan + 2
            break
        if css.startswith('/*', scan):
            nested_openers += 1
            if nested_openers > budget.limits.max_nesting:
                return scan, ('nesting-too-deep',
                              'Comment nesting depth exceeds '
                              f'{budget.limits.max_nesting}')
            scan += 2
        else:
            scan += 1
    else:
        end = length
        pos = length
    if not skip_comments:
        budget_error = comment_too_large(end)
        if budget_error is not None:
            return pos, budget_error
        budget_error = emit(Comment(line, column, css[content_start:end]))
        if budget_error is not None:
            return pos, budget_error
    return pos, None


def _consume_escape(css, pos):
    r"""Return (unescaped_char, new_pos).

    Assumes a valid escape: pos is just after '\' and not followed by '\n'.

    """
    # https://drafts.csswg.org/css-syntax/#consume-an-escaped-character
    hex_match = _HEX_ESCAPE_RE.match(css, pos)
    if hex_match:
        codepoint = int(hex_match.group(1), 16)
        return (
            chr(codepoint) if 0 < codepoint <= sys.maxunicode else '\uFFFD',
            hex_match.end())
    elif pos < len(css):
        return css[pos], pos + 1
    else:
        return '\uFFFD', pos


def _consume_url(css, pos, budget):
    """Return (unescaped_url, new_pos)

    The given pos is assumed to be just after the '(' of 'url('.

    """
    error = None
    length = len(css)
    # https://drafts.csswg.org/css-syntax/#consume-a-url-token
    # Skip whitespace
    while css.startswith((' ', '\n', '\t'), pos):
        pos += 1
    if pos >= length:  # EOF
        return '', pos, ('eof-in-url', 'EOF in URL')
    c = css[pos]
    if c in ('"', "'"):
        value, pos, error = _consume_quoted_string(css, pos, budget)
    elif c == ')':
        return '', pos + 1, error
    else:
        chunks = []
        start_pos = pos
        while 1:
            if pos >= length:  # EOF
                if budget.add_token_bytes(css[start_pos:pos]) is not None:
                    return None, pos, ('token-too-long',
                                       'Token exceeds '
                                       f'{budget.limits.max_token_bytes} '
                                       'bytes')
                chunks.append(css[start_pos:pos])
                return ''.join(chunks), pos, ('eof-in-url', 'EOF in URL')
            c = css[pos]
            if c == ')':
                if budget.add_token_bytes(css[start_pos:pos]) is not None:
                    return None, pos, ('token-too-long',
                                       'Token exceeds '
                                       f'{budget.limits.max_token_bytes} '
                                       'bytes')
                chunks.append(css[start_pos:pos])
                pos += 1
                return ''.join(chunks), pos, error
            elif c in ' \n\t':
                if budget.add_token_bytes(css[start_pos:pos]) is not None:
                    return None, pos, ('token-too-long',
                                       'Token exceeds '
                                       f'{budget.limits.max_token_bytes} '
                                       'bytes')
                chunks.append(css[start_pos:pos])
                value = ''.join(chunks)
                pos += 1
                break
            elif c == '\\' and not css.startswith('\\\n', pos):
                # Valid escape
                plain_chunk = css[start_pos:pos]
                if budget.add_token_bytes(plain_chunk) is not None:
                    return None, pos, ('token-too-long',
                                       'Token exceeds '
                                       f'{budget.limits.max_token_bytes} '
                                       'bytes')
                chunks.append(plain_chunk)
                escape_error = budget.charge_escape()
                if escape_error is not None:
                    return None, pos, escape_error
                c, pos = _consume_escape(css, pos + 1)
                if budget.add_token_bytes(c) is not None:
                    return None, pos, ('token-too-long',
                                       'Token exceeds '
                                       f'{budget.limits.max_token_bytes} '
                                       'bytes')
                chunks.append(c)
                start_pos = pos
            elif (c in
                  '"\'('
                  # https://drafts.csswg.org/css-syntax/#non-printable-character
                  '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0e'
                  '\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19'
                  '\x1a\x1b\x1c\x1d\x1e\x1f\x7f'):
                value = None  # Parse error
                pos += 1
                break
            else:
                pos += 1

    if value is not None:
        while css.startswith((' ', '\n', '\t'), pos):
            pos += 1
        if pos < length:
            if css[pos] == ')':
                return value, pos + 1, error
        else:
            if error is None:
                error = ('eof-in-url', 'EOF in URL')
            return value, pos, error

    # https://drafts.csswg.org/css-syntax/#consume-the-remnants-of-a-bad-url0
    while pos < length:
        if css.startswith('\\)', pos):
            pos += 2
        elif css[pos] == ')':
            pos += 1
            break
        else:
            pos += 1
    return None, pos, ('bad-url', 'bad URL token')


def _consume_unicode_range(css, pos):
    """Return (range, new_pos)

    The given pos is assume to be just after the '+' of 'U+' or 'u+'.

    """
    # https://drafts.csswg.org/css-syntax/#consume-a-unicode-range-token
    length = len(css)
    start_pos = pos
    max_pos = min(pos + 6, length)
    while pos < max_pos and css[pos] in '0123456789abcdefABCDEF':
        pos += 1
    start = css[start_pos:pos]

    start_pos = pos
    # Same max_pos as before: total of hex digits and question marks <= 6
    while pos < max_pos and css[pos] == '?':
        pos += 1
    question_marks = pos - start_pos

    if question_marks:
        end = start + 'F' * question_marks
        start = start + '0' * question_marks
    elif (pos + 1 < length and css[pos] == '-' and
          css[pos + 1] in '0123456789abcdefABCDEF'):
        pos += 1
        start_pos = pos
        max_pos = min(pos + 6, length)
        while pos < max_pos and css[pos] in '0123456789abcdefABCDEF':
            pos += 1
        end = css[start_pos:pos]
    else:
        end = start
    return int(start, 16), int(end, 16), pos
