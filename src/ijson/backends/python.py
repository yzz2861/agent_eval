'''
Pure-python parsing backend.
'''
from json.decoder import scanstring, JSONDecodeError
import re

from ijson import common, utils
import codecs


LEXEME_RE = re.compile(r'[a-z0-9eE\.\+-]+|\S')
INTEGER_RE = re.compile(r'-?[0-9]+')
UNARY_LEXEMES = set('[]{},')
EOF = -1, None

# The Unicode byte order mark, which is what a UTF-8 BOM (b'\xef\xbb\xbf')
# decodes into
BOM = '\ufeff'

# BOM handling policies: 'compat' skips a BOM found at the very beginning of
# the input and leaves any other BOM to the regular parsing machinery (which
# will reject it as an unexpected symbol), while 'strict' allows a single BOM
# at the very beginning of the input and rejects any other BOM as an illegal
# character
BOM_POLICIES = ('compat', 'strict')


class UnexpectedSymbol(common.JSONError):
    def __init__(self, symbol, pos):
        super(UnexpectedSymbol, self).__init__(
            'Unexpected symbol %r at %d' % (symbol, pos)
        )


@utils.coroutine
def utf8_encoder(target):
    """
    Incrementally decodes incoming UTF-8 bytes, allowing multi-byte characters
    to be split across chunks, and sends the resulting text to the target.
    Invalid byte sequences are reported immediately with their absolute byte
    offset in the input; the message deliberately does not echo any of the
    decoded text.
    """
    decoder = codecs.getincrementaldecoder('utf-8')()
    decode = decoder.decode
    send = target.send
    nbytes = 0
    while True:
        try:
            final = False
            bdata = (yield)
        except GeneratorExit:
            final = True
            bdata = b''
        if not bdata:
            # An empty chunk signals the end of the input; any bytes still
            # buffered by the decoder are an incomplete (hence invalid)
            # multi-byte sequence
            final = True
        try:
            sdata = decode(bdata, final)
        except UnicodeDecodeError as e:
            try:
                target.close()
            except:
                pass
            # e.object holds the bytes being decoded when the error happened,
            # including any bytes buffered from previous chunks
            pos = nbytes - (len(e.object) - len(bdata)) + e.start
            msg = 'Invalid UTF-8 byte sequence at byte offset %d' % (pos,)
            if e.reason == 'unexpected end of data':
                raise common.IncompleteJSONError(msg)
            raise common.JSONError(msg)
        except:
            try:
                target.close()
            except:
                pass
            raise
        nbytes += len(bdata)
        if sdata:
            send(sdata)
        elif not bdata:
            target.close()
            break

@utils.coroutine
def Lexer(target, bom_policy='compat'):
    """
    Parses lexemes out of the incoming content, and sends them to parse_value.
    A special EOF result is sent when the data source has been exhausted to
    give parse_value the possibility of raising custom exceptions due to missing
    content.

    A BOM is skipped when found as the very first character of the input. With
    the 'strict' bom_policy, a BOM found anywhere else (outside of string
    literals, where it is simply data) is rejected as an illegal character.
    """
    try:
        data = (yield)
    except GeneratorExit:
        data = ''
    buf = data
    pos = 0
    discarded = 0
    send = target.send
    while True:
        match = LEXEME_RE.search(buf, pos)
        if match:
            lexeme = match.group()
            if lexeme == BOM:
                bom_pos = discarded + match.start()
                if bom_pos == 0:
                    # A BOM at the very start of the input is always skipped
                    pos = match.end()
                    continue
                if bom_policy == 'strict':
                    raise common.JSONError(
                        'BOM (byte order mark) is only allowed at the start of '
                        'the input, but found one at %d' % (bom_pos,)
                    )
            if lexeme == '"':
                pos = match.start()
                start = pos + 1
                while True:
                    try:
                        end = buf.index('"', start)
                        escpos = end - 1
                        while buf[escpos] == '\\':
                            escpos -= 1
                        if (end - escpos) % 2 == 0:
                            start = end + 1
                        else:
                            break
                    except ValueError:
                        try:
                            data = (yield)
                        except GeneratorExit:
                            data = ''
                        if not data:
                            raise common.IncompleteJSONError('Incomplete string lexeme')
                        buf += data
                send((discarded + pos, buf[pos:end + 1]))
                pos = end + 1
            else:
                while lexeme not in UNARY_LEXEMES and match.end() == len(buf):
                    try:
                        data = (yield)
                    except GeneratorExit:
                        data = ''
                    if not data:
                        break
                    buf += data
                    match = LEXEME_RE.search(buf, pos)
                    lexeme = match.group()
                send((discarded + match.start(), lexeme))
                pos = match.end()
        else:
            # Don't ask data from an already exhausted source
            if data:
                try:
                    data = (yield)
                except GeneratorExit:
                    data = ''
            if not data:
                # Normally should raise StopIteration, but can raise
                # IncompleteJSONError too, which is the point of sending EOF
                try:
                    target.send(EOF)
                except StopIteration:
                    pass
                break
            discarded += len(buf)
            buf = data
            pos = 0


# Parsing states
_PARSE_VALUE = 0
_PARSE_ARRAY_ELEMENT_END = 1
_PARSE_OBJECT_KEY = 2
_PARSE_OBJECT_END = 3

# infinity singletons for overflow checks
inf = float("inf")
neg_inf = float("-inf")

@utils.coroutine
def parse_value(target, multivalue, use_float):
    """
    Parses results coming out of the Lexer into ijson events, which are sent to
    `target`. A stack keeps track of the type of object being parsed at the time
    (a value, and object or array -- the last two being values themselves).

    A special EOF result coming from the Lexer indicates that no more content is
    expected. This is used to check for incomplete content and raise the
    appropriate exception, which wouldn't be possible if the Lexer simply closed
    this co-routine (either explicitly via .close(), or implicitly by itself
    finishing and decreasing the only reference to the co-routine) since that
    causes a GeneratorExit exception that cannot be replaced with a custom one.
    """

    state_stack = [_PARSE_VALUE]
    pop = state_stack.pop
    push = state_stack.append
    send = target.send
    prev_pos, prev_symbol = None, None
    to_number = common.integer_or_float if use_float else common.integer_or_decimal
    while True:

        if prev_pos is None:
            pos, symbol = (yield)
            if (pos, symbol) == EOF:
                if state_stack:
                    raise common.IncompleteJSONError('Incomplete JSON content')
                break
        else:
            pos, symbol = prev_pos, prev_symbol
            prev_pos, prev_symbol = None, None
        try:
            state = state_stack[-1]
        except IndexError:
            if multivalue:
                state = _PARSE_VALUE
                push(state)
            else:
                raise common.JSONError('Additional data found')
        assert state_stack

        if state == _PARSE_VALUE:
            # Simple, common cases
            if symbol == 'null':
                send(('null', None))
                pop()
            elif symbol == 'true':
                send(('boolean', True))
                pop()
            elif symbol == 'false':
                send(('boolean', False))
                pop()
            elif symbol[0] == '"':
                send(('string', parse_string(symbol, pos)))
                pop()
            # Array start
            elif symbol == '[':
                send(('start_array', None))
                pos, symbol = (yield)
                if (pos, symbol) == EOF:
                    raise common.IncompleteJSONError('Incomplete JSON content')
                if symbol == ']':
                    send(('end_array', None))
                    pop()
                else:
                    prev_pos, prev_symbol = pos, symbol
                    push(_PARSE_ARRAY_ELEMENT_END)
                    push(_PARSE_VALUE)
            # Object start
            elif symbol == '{':
                send(('start_map', None))
                pos, symbol = (yield)
                if (pos, symbol) == EOF:
                    raise common.IncompleteJSONError('Incomplete JSON content')
                if symbol == '}':
                    send(('end_map', None))
                    pop()
                else:
                    prev_pos, prev_symbol = pos, symbol
                    push(_PARSE_OBJECT_KEY)
            # A number
            else:
                # JSON numbers can't contain leading zeros
                if ((len(symbol) > 1 and symbol[0] == '0' and symbol[1] not in ('e', 'E', '.')) or
                    (len(symbol) > 2 and symbol[0:2] == '-0' and symbol[2] not in ('e', 'E', '.'))):
                    raise common.JSONError('Invalid JSON number: %s' % (symbol,))
                # JSON numbers can't start with a plus sign
                if symbol[0] == '+':
                    raise common.JSONError(f'Invalid JSON number: {symbol}')
                # Fractions need a leading digit and must be followed by a digit
                dot = symbol.find('.')
                if dot != -1 and not (symbol[dot - 1:dot].isdigit() and symbol[dot + 1:dot + 2].isdigit()):
                    raise common.JSONError('Invalid JSON number: %s' % (symbol,))
                try:
                    number = to_number(symbol)
                    if number == inf or number == neg_inf:
                        raise common.JSONError("float overflow: %s" % (symbol,))
                except:
                    if 'true'.startswith(symbol) or 'false'.startswith(symbol) or 'null'.startswith(symbol):
                        raise common.IncompleteJSONError('Incomplete JSON content')
                    # a well-formed integer that int() still refused is one
                    # longer than sys.get_int_max_str_digits(); let that
                    # error through as the other backends do
                    if INTEGER_RE.fullmatch(symbol):
                        raise
                    raise UnexpectedSymbol(symbol, pos)
                else:
                    send(('number', number))
                    pop()

        elif state == _PARSE_OBJECT_KEY:
            if symbol[0] != '"':
                raise UnexpectedSymbol(symbol, pos)
            send(('map_key', parse_string(symbol, pos)))
            pos, symbol = (yield)
            if (pos, symbol) == EOF:
                raise common.IncompleteJSONError('Incomplete JSON content')
            if symbol != ':':
                raise UnexpectedSymbol(symbol, pos)
            state_stack[-1] = _PARSE_OBJECT_END
            push(_PARSE_VALUE)

        elif state == _PARSE_OBJECT_END:
            if symbol == ',':
                state_stack[-1] = _PARSE_OBJECT_KEY
            elif symbol != '}':
                raise UnexpectedSymbol(symbol, pos)
            else:
                send(('end_map', None))
                pop()
                pop()

        elif state == _PARSE_ARRAY_ELEMENT_END:
            if symbol == ',':
                state_stack[-1] = _PARSE_ARRAY_ELEMENT_END
                push(_PARSE_VALUE)
            elif symbol != ']':
                raise UnexpectedSymbol(symbol, pos)
            else:
                send(('end_array', None))
                pop()
                pop()


def _check_surrogate_escapes(symbol, pos):
    """
    Scans the \\uXXXX escapes of a raw string lexeme (which includes the
    surrounding quotes, and starts at absolute position pos) and makes sure
    that UTF-16 surrogates only appear as valid high+low pairs. Lone
    surrogates are rejected with their absolute position; the string content
    itself is never echoed back in the error message.
    """
    i = 1
    end = len(symbol) - 1
    while i < end:
        if symbol[i] == '\\':
            if symbol[i + 1:i + 2] == 'u':
                try:
                    code = int(symbol[i + 2:i + 6], 16)
                except ValueError:
                    # Not a valid escape; scanstring will reject it later
                    i += 2
                    continue
                if 0xD800 <= code <= 0xDBFF:
                    # A high surrogate must be immediately followed by a
                    # low surrogate escape
                    try:
                        follows = (
                            symbol[i + 6:i + 8] == '\\u' and
                            0xDC00 <= int(symbol[i + 8:i + 12], 16) <= 0xDFFF
                        )
                    except ValueError:
                        follows = False
                    if not follows:
                        raise common.JSONError(
                            'Lone high surrogate in string at %d' % (pos + i,)
                        )
                    i += 12
                    continue
                if 0xDC00 <= code <= 0xDFFF:
                    raise common.JSONError(
                        'Lone low surrogate in string at %d' % (pos + i,)
                    )
                i += 6
            else:
                i += 2
        else:
            i += 1


def parse_string(symbol, pos):
    """
    Decodes a raw string lexeme (including the surrounding quotes) found at
    absolute position pos, validating its escapes (including UTF-16 surrogate
    pairing) and rejecting unescaped control characters. Errors carry the
    absolute position of the offending construct and never echo the string
    content.
    """
    if '\\u' in symbol:
        _check_surrogate_escapes(symbol, pos)
    try:
        return scanstring(symbol, 1)[0]
    except JSONDecodeError as e:
        # Some of the json module's messages end in " at" already
        msg = e.msg[:-3] if e.msg.endswith(' at') else e.msg
        raise common.JSONError('%s at %d' % (msg, pos + e.pos))


def basic_parse_basecoro(target, multiple_values=False, allow_comments=False,
                         use_float=False, bom_policy='compat'):
    '''
    Iterator yielding unprefixed events.

    Parameters:

    - file: a readable file-like object with JSON input
    - bom_policy: how to handle byte order marks; 'compat' (the default)
      skips a BOM at the very start of the input, while 'strict' only allows
      a single BOM there and rejects any other as an illegal character
    '''
    if allow_comments:
        raise ValueError("Comments are not supported by the python backend")
    if bom_policy not in BOM_POLICIES:
        raise ValueError(
            "bom_policy must be one of %r, got %r" % (BOM_POLICIES, bom_policy)
        )
    return utf8_encoder(Lexer(parse_value(target, multiple_values, use_float), bom_policy))


common.enrich_backend(globals(), c_comments=False)
