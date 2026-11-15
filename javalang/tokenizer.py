import unicodedata
import bisect
from collections import namedtuple

import six


Position = namedtuple('Position', ['line', 'column'])


class LexerError(Exception):
    def __init__(self, message=u'', position=None, token_position=None):
        Exception.__init__(self, message)
        self.message = message
        self.position = position
        self.token_position = token_position
        self.token_start = token_position
        self.line = position.line if position else None
        self.column = position.column if position else None
        self.token_line = token_position.line if token_position else None
        self.token_column = token_position.column if token_position else None


class JavaToken(object):
    def __init__(self, value, position=None, javadoc=None):
        self.value = value
        self.position = position
        self.javadoc = javadoc

    def __repr__(self):
        if self.position:
            return '%s "%s" line %d, position %d' % (
                self.__class__.__name__, self.value, self.position[0], self.position[1]
                )
        else:
            return '%s "%s"' % (self.__class__.__name__, self.value)

    def __str__(self):
        return repr(self)

    def __eq__(self, other):
        raise Exception("Direct comparison not allowed")

class EndOfInput(JavaToken):
    pass

class Keyword(JavaToken):
    VALUES = set(['abstract', 'assert', 'boolean', 'break', 'byte', 'case',
                  'catch', 'char', 'class', 'const', 'continue', 'default',
                  'do', 'double', 'else', 'enum', 'extends', 'final',
                  'finally', 'float', 'for', 'goto', 'if', 'implements',
                  'import', 'instanceof', 'int', 'interface', 'long', 'native',
                  'new', 'package', 'private', 'protected', 'public', 'return',
                  'short', 'static', 'strictfp', 'super', 'switch',
                  'synchronized', 'this', 'throw', 'throws', 'transient', 'try',
                  'void', 'volatile', 'while'])


class Modifier(Keyword):
    VALUES = set(['abstract', 'default', 'final', 'native', 'private',
                  'protected', 'public', 'static', 'strictfp', 'synchronized',
                  'transient', 'volatile'])

class BasicType(Keyword):
    VALUES = set(['boolean', 'byte', 'char', 'double',
                  'float', 'int', 'long', 'short'])

class Literal(JavaToken):
    pass

class Integer(Literal):
    pass

class DecimalInteger(Literal):
    pass

class OctalInteger(Integer):
    pass

class BinaryInteger(Integer):
    pass

class HexInteger(Integer):
    pass

class FloatingPoint(Literal):
    pass

class DecimalFloatingPoint(FloatingPoint):
    pass

class HexFloatingPoint(FloatingPoint):
    pass

class Boolean(Literal):
    VALUES = set(["true", "false"])

class Character(Literal):
    pass

class String(Literal):
    pass

class Null(Literal):
    pass

class Separator(JavaToken):
    VALUES = set(['(', ')', '{', '}', '[', ']', ';', ',', '.'])

class Operator(JavaToken):
    MAX_LEN = 4
    VALUES = set(['>>>=', '>>=', '<<=',  '%=', '^=', '|=', '&=', '/=',
                  '*=', '-=', '+=', '<<', '--', '++', '||', '&&', '!=',
                  '>=', '<=', '==', '%', '^', '|', '&', '/', '*', '-',
                  '+', ':', '?', '~', '!', '<', '>', '=', '...', '->', '::'])

    # '>>>' and '>>' are excluded so that >> becomes two tokens and >>> becomes
    # three. This is done because we can not distinguish the operators >> and
    # >>> from the closing of multipel type parameter/argument lists when
    # lexing. The job of potentially recombining these symbols is left to the
    # parser

    INFIX = set(['||', '&&', '|', '^', '&', '==', '!=', '<', '>', '<=', '>=',
                 '<<', '>>', '>>>', '+', '-', '*', '/', '%'])

    PREFIX = set(['++', '--', '!', '~', '+', '-'])

    POSTFIX = set(['++', '--'])

    ASSIGNMENT = set(['=', '+=', '-=', '*=', '/=', '&=', '|=', '^=', '%=',
                      '<<=', '>>=', '>>>='])

    LAMBDA = set(['->'])

    METHOD_REFERENCE = set(['::',])

    def is_infix(self):
        return self.value in self.INFIX

    def is_prefix(self):
        return self.value in self.PREFIX

    def is_postfix(self):
        return self.value in self.POSTFIX

    def is_assignment(self):
        return self.value in self.ASSIGNMENT


class Annotation(JavaToken):
    pass

class Identifier(JavaToken):
    pass


class JavaTokenizer(object):

    IDENT_START_CATEGORIES = set(['Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nl', 'Pc', 'Sc'])

    IDENT_PART_CATEGORIES = set(['Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Mc', 'Mn', 'Nd', 'Nl', 'Pc', 'Sc'])

    # JLS 3.6: only these characters count as whitespace. In particular
    # U+2028 is an input character, not a Java line terminator.
    JAVA_WHITESPACE = frozenset(u' \t\f\r\n')
    JAVA_LINE_TERMINATORS = frozenset(u'\r\n')

    HEX_DIGITS = frozenset(u'0123456789abcdefABCDEF')

    # Explicit string-literal scanner states.
    STRING_NORMAL = 0
    STRING_ESCAPE = 1
    STRING_OCTAL = 2

    def __init__(self, data, ignore_errors=False):
        self.data = data
        self.ignore_errors = ignore_errors
        self.errors = []

        # Kept for compatibility with callers that inspected these fields.
        # Token and error positions are derived from the original source.
        self.current_line = 1
        self.start_of_line = -1

        self.operators = [set() for i in range(0, Operator.MAX_LEN)]

        for v in Operator.VALUES:
            self.operators[len(v) - 1].add(v)

        self.javadoc = None

        self.source = u''
        self._source_offsets = []
        self._line_starts = [0]
        self._token_start = 0

    def reset(self):
        self.i = 0
        self.j = 0
        self._token_start = 0

    def _build_line_starts(self, source):
        line_starts = [0]
        i = 0
        length = len(source)

        while i < length:
            c = source[i]

            if c == u'\r':
                i += 1
                if i < length and source[i] == u'\n':
                    i += 1
                line_starts.append(i)
            elif c == u'\n':
                i += 1
                line_starts.append(i)
            else:
                i += 1

        return line_starts

    def _position_for_raw_offset(self, offset):
        if offset < 0:
            offset = 0
        if offset > len(self.source):
            offset = len(self.source)

        line_index = bisect.bisect_right(self._line_starts, offset) - 1
        if line_index < 0:
            line_index = 0

        line_start = self._line_starts[line_index]
        return Position(line_index + 1, offset - line_start + 1)

    def _raw_offset(self, logical_index):
        if logical_index < len(self._source_offsets):
            return self._source_offsets[logical_index]
        return len(self.source)

    def _position_at(self, logical_index):
        return self._position_for_raw_offset(self._raw_offset(logical_index))

    def _line_text(self, line_number):
        line_index = line_number - 1
        if line_index < 0 or line_index >= len(self._line_starts):
            return u''

        start = self._line_starts[line_index]
        if line_index + 1 < len(self._line_starts):
            end = self._line_starts[line_index + 1]
        else:
            end = len(self.source)

        return self.source[start:end].rstrip(u'\r\n').strip()

    @staticmethod
    def _display_char(char):
        if char is None:
            return u''
        char = u'%s' % (char,)
        return (char.replace(u'\r', u'\\r')
                    .replace(u'\n', u'\\n')
                    .replace(u'\t', u'\\t'))

    def _error_at_raw(self, message, raw_offset, char=None, token_raw_offset=None):
        position = self._position_for_raw_offset(raw_offset)

        if token_raw_offset is None:
            token_raw_offset = raw_offset
        token_position = self._position_for_raw_offset(token_raw_offset)

        line_text = self._line_text(position.line)
        message = (u'%s at "%s", line %s, column %s '
                   u'(token starts at line %s, column %s): %s') % (
                       message, self._display_char(char),
                       position.line, position.column,
                       token_position.line, token_position.column,
                       line_text)

        error = LexerError(message, position, token_position)
        self.errors.append(error)

        if not self.ignore_errors:
            raise error

        return error

    def _error(self, message, index=None, char=None, token_start=None):
        if index is None:
            index = self.i

        raw_offset = self._raw_offset(index)

        if char is None and index < len(self.data):
            char = self.data[index]

        if token_start is not None:
            token_raw_offset = self._raw_offset(token_start)
        else:
            token_raw_offset = self._token_start

        return self._error_at_raw(message, raw_offset, char, token_raw_offset)

    def error(self, message, char=None):
        return self._error(message, self.i, char, getattr(self, '_token_start', None))

    def consume_whitespace(self):
        i = self.i

        while i < self.length and self.data[i] in self.JAVA_WHITESPACE:
            i += 1

        self.i = i

    def read_string(self):
        start = self.i
        delim = self.data[start]
        self._token_start = self._raw_offset(start)

        state = self.STRING_NORMAL
        octal_remaining = 0
        i = start + 1
        length = self.length

        while i < length:
            c = self.data[i]

            if state == self.STRING_NORMAL:
                if c == delim:
                    i += 1
                    self.j = i
                    return
                elif c == u'\\':
                    state = self.STRING_ESCAPE
                    i += 1
                elif c in self.JAVA_LINE_TERMINATORS:
                    self._error('Unterminated character/string literal',
                                i, c, start)
                    self.j = i
                    return
                else:
                    i += 1

            elif state == self.STRING_ESCAPE:
                if c in u'btnfru"\'\\':
                    state = self.STRING_NORMAL
                    i += 1
                elif c in u'01234567':
                    if c in u'0123':
                        octal_remaining = 2
                    else:
                        octal_remaining = 1
                    state = self.STRING_OCTAL
                    i += 1
                elif c in self.JAVA_LINE_TERMINATORS:
                    self._error('Unterminated character/string literal',
                                i, c, start)
                    self.j = i
                    return
                else:
                    self._error('Illegal escape character', i, c, start)
                    state = self.STRING_NORMAL
                    i += 1

            else:
                if c in u'01234567' and octal_remaining > 0:
                    octal_remaining -= 1
                    i += 1
                    if octal_remaining == 0:
                        state = self.STRING_NORMAL
                else:
                    state = self.STRING_NORMAL

        self._error('Unterminated character/string literal',
                    start, delim, start)
        self.j = length

    def try_operator(self):
        for l in range(min(self.length - self.i, Operator.MAX_LEN), 0, -1):
            if self.data[self.i:self.i + l] in self.operators[l - 1]:
                self.j = self.i + l
                return True
        return False

    def read_comment(self):
        start = self.i
        self._token_start = self._raw_offset(start)

        if self.data[start + 1] == u'/':
            i = start + 2

            while i < self.length and self.data[i] not in self.JAVA_LINE_TERMINATORS:
                i += 1

            self.i = i
            return self.data[start:i]

        close = self.data.find(u'*/', start + 2)

        if close == -1:
            self._error('Unterminated block comment', start, u'/*', start)

            # Recover from a bad comment by consuming only its opener. The
            # caller can then continue lexing the remaining input instead of
            # silently treating it as part of the comment.
            self.i = start + 2
            return self.data[start:self.i]

        self.i = close + 2
        return self.data[start:close + 2]

    def read_decimal_float_or_integer(self):
        orig_i = self.i
        self.j = self.i

        self.read_decimal_integer()

        if self.j >= len(self.data) or self.data[self.j] not in '.eEfFdD':
            return DecimalInteger

        if self.data[self.j] == '.':
            self.i = self.j + 1
            self.read_decimal_integer()

        if self.j < len(self.data) and self.data[self.j] in 'eE':
            self.j = self.j + 1

            if self.j < len(self.data) and self.data[self.j] in '-+':
                self.j = self.j + 1

            self.i = self.j
            self.read_decimal_integer()

        if self.j < len(self.data) and self.data[self.j] in 'fFdD':
            self.j = self.j + 1

        self.i = orig_i
        return DecimalFloatingPoint

    def read_hex_integer_or_float(self):
        orig_i = self.i
        self.j = self.i + 2

        self.read_hex_integer()

        if self.j >= len(self.data) or self.data[self.j] not in '.pP':
            return HexInteger

        if self.data[self.j] == '.':
            self.j = self.j + 1
            self.read_digits('0123456789abcdefABCDEF')

        if self.j < len(self.data) and self.data[self.j] in 'pP':
            self.j = self.j + 1
        else:
            self.error('Invalid hex float literal')

        if self.j < len(self.data) and self.data[self.j] in '-+':
            self.j = self.j + 1

        self.i = self.j
        self.read_decimal_integer()

        if self.j < len(self.data) and self.data[self.j] in 'fFdD':
            self.j = self.j + 1

        self.i = orig_i
        return HexFloatingPoint

    def read_digits(self, digits):
        tmp_i = 0
        c = None

        while self.j + tmp_i < len(self.data):
            c = self.data[self.j + tmp_i]

            if c in digits:
                self.j += 1 + tmp_i
                tmp_i = 0
            elif c == '_':
                tmp_i += 1
            else:
                break

        if c is not None and c in 'lL':
            self.j += 1

    def read_decimal_integer(self):
        self.j = self.i
        self.read_digits('0123456789')

    def read_hex_integer(self):
        self.j = self.i + 2
        self.read_digits('0123456789abcdefABCDEF')

    def read_bin_integer(self):
        self.j = self.i + 2
        self.read_digits('01')

    def read_octal_integer(self):
        self.j = self.i + 1
        self.read_digits('01234567')

    def read_integer_or_float(self, c, c_next):
        if c == '0' and c_next is not None and c_next in 'xX':
            return self.read_hex_integer_or_float()
        elif c == '0' and c_next is not None and c_next in 'bB':
            self.read_bin_integer()
            return BinaryInteger
        elif c == '0' and c_next is not None and c_next in '01234567':
            self.read_octal_integer()
            return OctalInteger
        else:
            return self.read_decimal_float_or_integer()

    def try_separator(self):
        if self.data[self.i] in Separator.VALUES:
            self.j = self.i + 1
            return True
        return False

    def decode_data(self):
        # If data is already unicode don't try to redecode.
        if isinstance(self.data, six.text_type):
            return self.data

        # utf-8-sig accepts both plain UTF-8 and UTF-8 with a leading BOM.
        codecs = ['utf-8-sig', 'utf-8', 'iso-8859-1']

        for codec in codecs:
            try:
                return self.data.decode(codec)
            except (UnicodeDecodeError, LookupError):
                pass

        raise LexerError('Could not decode input data')

    def is_java_identifier_start(self, c):
        return unicodedata.category(c) in self.IDENT_START_CATEGORIES

    def read_identifier(self):
        self.j = self.i + 1

        while self.j < len(self.data) and unicodedata.category(self.data[self.j]) in self.IDENT_PART_CATEGORIES:
            self.j += 1

        ident = self.data[self.i:self.j]
        if ident in Keyword.VALUES:
            token_type = Keyword

            if ident in BasicType.VALUES:
                token_type = BasicType
            elif ident in Modifier.VALUES:
                token_type = Modifier

        elif ident in Boolean.VALUES:
            token_type = Boolean
        elif ident == 'null':
            token_type = Null
        else:
            token_type = Identifier

        return token_type

    def pre_tokenize(self):
        source = self.decode_data()

        # A leading BOM is not part of Java source and must not affect the
        # reported column of the first token.
        if source.startswith(u'\ufeff'):
            source = source[1:]

        self.source = source
        self._line_starts = self._build_line_starts(source)

        translated = []
        source_offsets = []

        i = 0
        length = len(source)
        backslash_run = 0

        while i < length:
            c = source[i]

            if c == u'\\':
                # JLS 3.3: a backslash is eligible to start a Unicode escape
                # only if it is preceded by an even number of contiguous raw
                # backslashes. This is what keeps \"\\\\u0041\" from being
                # decoded as \"\\u0041\".
                eligible = (backslash_run % 2 == 0)

                if eligible:
                    marker_end = i + 1
                    while marker_end < length and source[marker_end] == u'u':
                        marker_end += 1

                    if marker_end > i + 1:
                        hex_start = marker_end
                        hex_end = hex_start + 4
                        digits = source[hex_start:hex_end]

                        if (hex_end <= length and len(digits) == 4 and
                                all(d in self.HEX_DIGITS for d in digits)):
                            translated.append(six.unichr(int(digits, 16)))
                            source_offsets.append(i)
                            i = hex_end
                            backslash_run = 0
                            continue

                        # Point the error at the first missing/non-hex
                        # character while remembering the escape's backslash
                        # as the token start. Resume at that same character so
                        # the rest of the input is still available to the
                        # lexer.
                        invalid_offset = hex_start
                        for offset in range(hex_start, hex_end):
                            if offset < length and source[offset] in self.HEX_DIGITS:
                                invalid_offset = offset + 1
                            else:
                                invalid_offset = offset
                                break

                        if invalid_offset > length:
                            invalid_offset = length

                        self._error_at_raw(
                            'Invalid unicode escape', invalid_offset,
                            source[invalid_offset:invalid_offset + 1], i)

                        i = invalid_offset
                        backslash_run = 0
                        continue

                translated.append(c)
                source_offsets.append(i)
                backslash_run += 1
                i += 1
            else:
                translated.append(c)
                source_offsets.append(i)
                backslash_run = 0
                i += 1

        self.data = u''.join(translated)
        self._source_offsets = source_offsets
        self.length = len(self.data)

    def tokenize(self):
        self.reset()

        # Convert unicode escapes
        self.pre_tokenize()

        while self.i < self.length:
            token_type = None
            start = self.i
            self._token_start = self._raw_offset(start)

            c = self.data[start]
            c_next = None
            startswith = c

            if start + 1 < self.length:
                c_next = self.data[start + 1]
                startswith = c + c_next

            if c in self.JAVA_WHITESPACE:
                self.consume_whitespace()
                continue

            elif startswith in ("//", "/*"):
                comment = self.read_comment()
                if comment.startswith("/**"):
                    self.javadoc = comment
                continue

            elif startswith == '..' and self.try_operator():
                # Ensure we don't mistake a '...' operator as a sequence of
                # three '.' separators. This is done as an optimization instead
                # of moving try_operator higher in the chain because operators
                # aren't as common and try_operator is expensive
                token_type = Operator

            elif c == '@':
                token_type = Annotation
                self.j = start + 1

            elif c == '.' and c_next and c_next.isdigit():
                token_type = self.read_decimal_float_or_integer()

            elif self.try_separator():
                token_type = Separator

            elif c in ("'", '"'):
                token_type = String
                self.read_string()

            elif c in '0123456789':
                token_type = self.read_integer_or_float(c, c_next)

            elif self.is_java_identifier_start(c):
                token_type = self.read_identifier()

            elif self.try_operator():
                token_type = Operator

            else:
                self._error('Could not process token', start, c, start)
                self.i = start + 1
                continue

            position = self._position_at(start)
            token = token_type(self.data[start:self.j], position, self.javadoc)
            yield token

            if self.javadoc:
                self.javadoc = None

            self.i = self.j

def tokenize(code, ignore_errors=False):
    tokenizer = JavaTokenizer(code, ignore_errors)
    return tokenizer.tokenize()

def reformat_tokens(tokens):
    indent = 0
    closed_block = False
    ident_last = False

    output = list()

    for token in tokens:
        if closed_block:
            closed_block = False
            indent -= 4

            output.append('\n')
            output.append(' ' * indent)
            output.append('}')

            if isinstance(token, (Literal, Keyword, Identifier)):
                output.append('\n')
                output.append(' ' * indent)

        if token.value == '{':
            indent += 4
            output.append(' {\n')
            output.append(' ' * indent)

        elif token.value == '}':
            closed_block = True

        elif token.value == ',':
            output.append(', ')

        elif isinstance(token, (Literal, Keyword, Identifier)):
            if ident_last:
                # If the last token was a literla/keyword/identifer put a space in between
                output.append(' ')
            ident_last = True
            output.append(token.value)

        elif isinstance(token, Operator):
            output.append(' ' + token.value + ' ')

        elif token.value == ';':
            output.append(';\n')
            output.append(' ' * indent)

        else:
            output.append(token.value)

        ident_last = isinstance(token, (Literal, Keyword, Identifier))

    if closed_block:
        output.append('\n}')

    output.append('\n')

    return ''.join(output)
