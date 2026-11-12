'''
Pure-python parsing backend.
'''
from json.decoder import scanstring
import re

from ijson import common, numbers, utils
import codecs


LEXEME_RE = re.compile(r'[a-z0-9eE\.\+-]+|\S')
INTEGER_RE = re.compile(r'-?[0-9]+')
UNARY_LEXEMES = set('[]{},')
EOF = -1, None


def _unpack_chunk(incoming):
    """Accepts decoded text or a (text, original_byte_length) tuple produced
    by utf8_encoder and returns both parts."""
    if isinstance(incoming, tuple):
        return incoming
    if not incoming:
        return incoming, 0
    return incoming, len(incoming.encode('utf-8'))


class UnexpectedSymbol(common.JSONError):
    def __init__(self, symbol, pos):
        super(UnexpectedSymbol, self).__init__(
            'Unexpected symbol %r at %d' % (symbol, pos)
        )


@utils.coroutine
def utf8_encoder(target):
    decoder = codecs.getincrementaldecoder('utf-8')()
    decode = decoder.decode
    send = target.send
    pending_bytes = 0
    while True:
        try:
            final = False
            bdata = (yield)
        except GeneratorExit:
            final = True
            bdata = b''
        try:
            sdata = decode(bdata, final)
        except UnicodeDecodeError as e:
            try:
                target.close()
            except:
                pass
            raise common.IncompleteJSONError(e)
        except:
            try:
                target.close()
            except:
                pass
            raise
        # account for every byte read: those retained by the incremental
        # decoder as part of an incomplete multibyte sequence stay pending
        # and are attributed to the characters once decoding completes
        if bdata:
            pending_bytes += len(bdata)
        if sdata:
            decoded_bytes = len(sdata.encode('utf-8'))
            pending_bytes -= decoded_bytes
            # forward the decoded text with the byte length it represents
            # so the Lexer reports true byte offsets across chunk splits
            send((sdata, decoded_bytes))
        elif not bdata:
            if final:
                # On close, drive the downstream EOF handling through the
                # normal path so pending events are still delivered.
                try:
                    send(('', 0))
                except StopIteration:
                    pass
                return
            # an empty chunk on the generator path marks end-of-input
            try:
                target.send(('', 0))
            except StopIteration:
                return
            # an empty non-final chunk carries no information
            continue

@utils.coroutine
def Lexer(target, number_limits, current_path=None):
    """
    Parses lexemes out of the incoming content, and sends them to parse_value.
    A special EOF result is sent when the data source has been exhausted to
    give parse_value the possibility of raising custom exceptions due to
    missing content.

    Chunks are either plain decoded text or ``(text, byte_length)`` tuples
    produced by utf8_encoder; the byte length lets this coroutine report true
    byte offsets even when multibyte UTF-8 characters are split across chunks.
    """
    incoming = (yield)
    data, data_bytes = _unpack_chunk(incoming)
    buf = data
    pos = 0
    pos_bytes = 0  # byte offset of buf[pos] in the original stream
    send = target.send

    def advance(new_pos):
        nonlocal pos, pos_bytes
        if new_pos > pos:
            pos_bytes += len(buf[pos:new_pos].encode('utf-8'))
            pos = new_pos

    while True:
        match = LEXEME_RE.search(buf, pos)
        if match:
            lexeme = match.group()
            if lexeme == '"':
                string_byte_start = pos_bytes + len(
                    buf[pos:match.start()].encode('utf-8'))
                advance(match.start())
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
                        chunk = (yield)
                        data, _ = _unpack_chunk(chunk)
                        if not data:
                            raise common.IncompleteJSONError(
                                'Incomplete string lexeme')
                        buf += data
                lexeme_text = buf[pos:end + 1]
                advance(end + 1)
                send((string_byte_start, lexeme_text))
            else:
                token_start = match.start()
                token_byte_start = pos_bytes + len(
                    buf[pos:token_start].encode('utf-8'))
                streaming_token = False
                while lexeme not in UNARY_LEXEMES and match.end() == len(buf):
                    is_number_like = bool(lexeme) and lexeme[0] in '-0123456789'
                    if is_number_like:
                        numbers.check_token_length(
                            lexeme, number_limits, offset=token_byte_start,
                            path=current_path() if current_path else None)
                    # Only number-like tokens are streamed linearly; other
                    # unterminated lexemes (true/false/null fragments) use
                    # the original regex-based accumulation below.
                    if not is_number_like:
                        chunk = (yield)
                        data, data_bytes = _unpack_chunk(chunk)
                        if not data:
                            break
                        pos_bytes += data_bytes
                        buf += data
                        match = LEXEME_RE.search(buf, pos)
                        lexeme = match.group()
                        continue

                    chunk = (yield)
                    data, data_bytes = _unpack_chunk(chunk)
                    if not data:
                        # end of input: the accumulated token is complete
                        break
                    separators = ' \t\n\r[],{}:'
                    cut = 0
                    while cut < len(data) and data[cut] not in separators:
                        cut += 1
                    if number_limits.max_token_length is not None and \
                            len(lexeme) + cut > number_limits.max_token_length:
                        numbers.check_token_length(
                            lexeme + data[:cut], number_limits,
                            offset=token_byte_start,
                            path=current_path() if current_path else None)
                    lexeme += data[:cut]
                    extra = data[cut:]
                    numbers.check_token_length(
                        lexeme, number_limits, offset=token_byte_start,
                        path=current_path() if current_path else None)
                    if extra:
                        buf = buf[:token_start] + lexeme + extra
                        match = LEXEME_RE.search(buf, pos)
                        lexeme = match.group()
                        break
                    streaming_token = True
                if streaming_token and match.end() == len(buf):
                    buf = buf[:token_start] + lexeme
                    match = LEXEME_RE.search(buf, pos)
                number_byte_start = pos_bytes + len(
                    buf[pos:match.start()].encode('utf-8'))
                send((number_byte_start, lexeme))
                advance(match.end())
        else:
            # Don't ask data from an already exhausted source
            if data:
                chunk = (yield)
                data, data_bytes = _unpack_chunk(chunk)
            if not data:
                # Normally should raise StopIteration, but can raise
                # IncompleteJSONError too, which is the point of sending EOF
                try:
                    target.send(EOF)
                except StopIteration:
                    pass
                break
            # pos_bytes already points at the end of the fully-consumed
            # previous buffer; the new chunk starts there, so only the state
            # is reset (the chunk's own bytes are counted as it is consumed)
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
def parse_value(target, multivalue, use_float, number_limits):
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
    # Mirrors the path stack built by common.parse_basecoro so limit
    # failures can be reported with their JSON location even at the
    # basic_parse level.
    path_stack = ['']
    while True:

        if prev_pos is None:
            try:
                pos, symbol = (yield)
            except numbers.NumberLimitError as exc:
                # raised by the Lexer while it was accumulating a token; the
                # path stack already reflects the value's container
                if exc.path is None:
                    exc.set_path(path_stack[-1] or '')
                raise
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
                send(('string', parse_string(symbol)))
                pop()
            # Array start
            elif symbol == '[':
                send(('start_array', None))
                path_stack.append(path_stack[-1] + '.item' if path_stack[-1] else 'item')
                pos, symbol = (yield)
                if (pos, symbol) == EOF:
                    raise common.IncompleteJSONError('Incomplete JSON content')
                if symbol == ']':
                    send(('end_array', None))
                    path_stack.pop()
                    pop()
                else:
                    prev_pos, prev_symbol = pos, symbol
                    push(_PARSE_ARRAY_ELEMENT_END)
                    push(_PARSE_VALUE)
            # Object start
            elif symbol == '{':
                send(('start_map', None))
                path_stack.append(None)
                pos, symbol = (yield)
                if (pos, symbol) == EOF:
                    raise common.IncompleteJSONError('Incomplete JSON content')
                if symbol == '}':
                    send(('end_map', None))
                    path_stack.pop()
                    pop()
                else:
                    prev_pos, prev_symbol = pos, symbol
                    push(_PARSE_OBJECT_KEY)
            # A number
            else:
                number_path = path_stack[-1] or ''
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
                    number = numbers.convert_number(
                        symbol, use_float=use_float, limits=number_limits,
                        offset=pos, path=number_path
                    )
                    if number == inf or number == neg_inf:
                        raise common.JSONError("float overflow: %s" % (symbol,))
                except numbers.NumberLimitError:
                    raise
                except common.JSONError:
                    # e.g. an explicit float overflow produced by the shared
                    # conversion code; don't turn it into an UnexpectedSymbol
                    raise
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
            key = parse_string(symbol)
            send(('map_key', key))
            base = path_stack[-2]
            path_stack[-1] = base + '.' + key if base else key
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
                path_stack.pop()
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
                path_stack.pop()
                pop()
                pop()


def parse_string(symbol):
    return scanstring(symbol, 1)[0]


def basic_parse_basecoro(target, multiple_values=False, allow_comments=False,
                         use_float=False, number_limits=None):
    '''
    Iterator yielding unprefixed events.

    Parameters:

    - file: a readable file-like object with JSON input
    '''
    if allow_comments:
        raise ValueError("Comments are not supported by the python backend")
    limits = numbers.resolve_number_limits(number_limits)
    value_coro = parse_value(target, multiple_values, use_float, limits)
    def current_path():
        # parse_value keeps the same path stack convention as the public
        # parse_basecoro; read it directly so failures raised while the Lexer
        # accumulates a token still carry their JSON location.
        frame = value_coro.gi_frame
        if frame is None:
            return ''
        stack = frame.f_locals.get('path_stack') or ['']
        return '.'.join(part for part in stack if part)
    return utf8_encoder(Lexer(value_coro, limits, current_path))


common.enrich_backend(globals(), c_comments=False)
