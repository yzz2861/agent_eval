# ------------------------------------------------------------------------------
# pycparser: c_lexer.py
#
# CLexer class: lexer for the C language
#
# Eli Bendersky [https://eli.thegreenplace.net/]
# License: BSD
# ------------------------------------------------------------------------------
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from string import ascii_letters, digits, hexdigits
from typing import Literal, assert_never

Dialect = Literal["legacy", "c23"]


@dataclass(slots=True)
class Token:
    type: str
    value: str
    lineno: int
    column: int
    filename: str


class CLexer:
    """A standalone lexer for C.

    Constructor parameters:
        error_func:
            Called with (msg, line, column) on lexing errors.
        dialect:
            "legacy" preserves the existing keyword set. "c23" also recognizes
            C23 keywords and predefined constants.

    Call input(text) to initialize lexing, and then keep calling token() to
    get the next token, until it returns None (at end of input).

    Non-keyword identifiers are emitted as ID tokens. The parser handles
    scopes and classifies typedef names as TYPEID.
    """

    def __init__(
        self,
        error_func: Callable[[str, int, int], None],
        *,
        dialect: Dialect = "legacy",
    ) -> None:
        if dialect not in ("legacy", "c23"):
            raise ValueError(f"Unknown dialect {dialect!r}; expected 'legacy' or 'c23'")
        # Select keywords once per lexer. input() resets the scanning state
        # without changing this map or affecting lexers using another dialect.
        self._keyword_map = _keyword_map.copy()
        if dialect == "c23":
            self._keyword_map.update(_c23_keywords)

        self.error_func = error_func
        self._init_state()

    def input(self, text: str, filename: str = "") -> None:
        """Initialize the lexer to the given input text.

        filename is an optional name identifying the initial file from which the
        input comes. The lexer may modify it if #line directives are
        encountered.
        """
        self._init_state()
        self._lexdata = text
        self._filename = filename

    def _init_state(self) -> None:
        self._lexdata = ""
        self._filename = ""
        self._pos = 0
        self._line_start = 0
        self._pending_tok: Token | None = None
        self._lineno = 1
        self._in_attribute = False

    @property
    def filename(self) -> str:
        return self._filename

    def token(self) -> Token | None:
        # Lexing strategy overview:
        #
        # - We maintain a current position (self._pos), line number, and the
        #   byte offset of the current line start. The lexer is a simple loop
        #   that skips whitespace/newlines and emits one token per call.
        #
        # - A small amount of logic is handled manually before regex matching:
        #
        #   * Preprocessor-style directives: if we see '#', we check whether
        #     it's a #line or #pragma directive and consume it inline. #line
        #     updates lineno/filename and produces no tokens. #pragma can yield
        #     both PPPRAGMA and PPPRAGMASTR, but token() returns a single token,
        #     so we stash the PPPRAGMASTR as _pending_tok to return on the next
        #     token() call. Otherwise we return PPHASH.
        #   * Newlines update lineno/line-start tracking so tokens can record
        #     accurate columns.
        #
        # - The bulk of tokens are recognized in _match_token:
        #
        #   * String literals, character constants, and comments are scanned
        #     by bounded state machines (see _scan_quoted_literal and the
        #     comment handling in _match_token). They run in time linear in
        #     the input size, report errors at the exact offset in the
        #     original text, and consume the whole erroneous construct so no
        #     fabricated tokens are produced from its contents.
        #
        #   * _regex_rules: regex patterns for identifiers, literals, and other
        #     complex tokens (including error-producing patterns). The lexer
        #     uses a combined _regex_master to scan options at the same time.
        #   * _fixed_tokens: exact string matches for operators and punctuation,
        #     resolved by longest match.
        #
        # - Error patterns call the error callback and advance past the
        #   erroneous construct, keeping line tracking accurate so subsequent
        #   tokens report correct coordinates.
        text = self._lexdata
        n = len(text)

        if self._pending_tok is not None:
            tok = self._pending_tok
            self._pending_tok = None
            return tok

        while self._pos < n:
            match text[self._pos]:
                case " " | "\t" | "\f" | "\v":
                    self._pos += 1
                case "\n":
                    self._lineno += 1
                    self._pos += 1
                    self._line_start = self._pos
                case "#":
                    if _line_pattern.match(text, self._pos + 1):
                        self._pos += 1
                        self._handle_ppline()
                        continue
                    if _pragma_pattern.match(text, self._pos + 1):
                        self._pos += 1
                        toks = self._handle_pppragma()
                        if len(toks) > 1:
                            self._pending_tok = toks[1]
                        if len(toks) > 0:
                            return toks[0]
                        continue
                    tok = self._make_token("PPHASH", "#", self._pos)
                    self._pos += 1
                    return tok
                case _:
                    if tok := self._match_token():
                        return tok
                    else:
                        continue

    def _match_token(self) -> Token | None:
        """Match one token at the current position.

        Returns a Token on success, or None if no token could be matched and
        an error was reported. This method always advances _pos by the matched
        length, or by 1 on error/no-match.
        """
        text = self._lexdata
        pos = self._pos
        char = text[pos]
        # Attribute arguments are balanced token sequences, not C expressions.
        # Keep them opaque so the parser does not interpret their contents as
        # C expressions or declarations.
        if self._in_attribute:
            if char == "(":
                return self._attribute_arguments()
            if match := _attribute_end.match(text, pos):
                self._in_attribute = False
                return self._attribute_token("ATTRIBUTE_END", match.end())
        # Only run regexp check if we are starting an attribute, to avoid
        # costly regex matching for every token.
        elif char == "[" and (match := _attribute_begin.match(text, pos)):
            self._in_attribute = True
            return self._attribute_token("ATTRIBUTE_BEGIN", match.end())
        # An identifier start other than a literal prefix (L, u, U) can only
        # begin an identifier or keyword, so match it without the master regex.
        if char in _identifier_only_first_chars:
            m = _identifier_pattern.match(text, pos)
            assert m is not None
            end = m.end()
            value = text[pos:end]
            tok_type = (
                "ID" if self._in_attribute else self._keyword_map.get(value, "ID")
            )
            tok = self._make_token(tok_type, value, pos)
            self._pos = end
            return tok
        # Quoted literals and comments are scanned by bounded state machines
        # rather than regexes. The scanners never backtrack, report errors at
        # exact offsets in the original text, and consume the whole erroneous
        # construct so its contents cannot fabricate tokens.
        if char == '"':
            return self._string_token(pos, "STRING_LITERAL")
        if char == "'":
            return self._char_const_token(pos)
        if char == "/":
            if text.startswith("/*", pos):
                self._error(_comment_error_message, pos)
                end = text.find("*/", pos + 2)
                self._advance_to(len(text) if end < 0 else end + 2)
                return None
            if text.startswith("//", pos):
                self._error(_comment_error_message, pos)
                end = text.find("\n", pos + 2)
                self._advance_to(len(text) if end < 0 else end)
                return None
        if char in "LuU":
            prefix_len, quote = _literal_prefix(text, pos)
            if prefix_len:
                return self._prefixed_literal_token(pos, prefix_len, quote)
        # We pick the longest match between:
        # - the master regex (identifiers, literals, error patterns, etc.)
        # - fixed operator/punctuator literals from the bucket for text[pos]
        #
        # The longest match is required to ensure we properly lex something
        # like ".123" (a floating-point constant) as a single entity (with
        # FLOAT_CONST), rather than a PERIOD followed by a number.
        #
        # The fixed-literal buckets are already length-sorted, so within that
        # bucket we can take the first match. However, we still compare its
        # length to the regex match because the regex may have matched a longer
        # token that should take precedence.
        best = None

        if char in _regex_first_chars and (m := _regex_master.match(text, pos)):
            tok_type = m.lastgroup
            # All master-regex alternatives are named; lastgroup shouldn't be None.
            assert tok_type is not None
            value = m.group(tok_type)
            length = len(value)
            action, msg = _regex_actions[tok_type]
            best = (length, tok_type, value, action, msg)

        if bucket := _fixed_tokens_by_first.get(char):
            for entry in bucket:
                if text.startswith(entry.literal, pos):
                    length = len(entry.literal)
                    if best is None or length > best[0]:
                        best = (
                            length,
                            entry.tok_type,
                            entry.literal,
                            _RegexAction.TOKEN,
                            None,
                        )
                    break

        if best is None:
            self._error(f"Illegal character {char!r}", pos)
            self._advance_to(self._pos + 1)
            return None

        length, tok_type, value, action, msg = best
        match action:
            case _RegexAction.TOKEN:
                pass
            case _RegexAction.ERROR:
                # All ERROR rules provide a message.
                assert msg is not None
                self._error(msg, pos)
                self._advance_to(self._pos + max(1, length))
                return None
            case _RegexAction.ID:
                tok_type = (
                    "ID" if self._in_attribute else self._keyword_map.get(value, "ID")
                )
            case _:
                assert_never(action)

        tok = self._make_token(tok_type, value, pos)
        self._pos += length

        return tok

    def _advance_to(self, end: int) -> None:
        """Advance _pos to end, keeping line tracking accurate.

        Every code path that consumes input must go through here (or update
        _lineno/_line_start itself) so that tokens and errors following an
        erroneous construct still report coordinates in the original text.
        """
        segment = self._lexdata[self._pos : end]
        if "\n" in segment:
            self._lineno += segment.count("\n")
            self._line_start = self._pos + segment.rfind("\n") + 1
        self._pos = end

    def _scan_quoted_literal(self, start: int, quote: str) -> "_QuotedLiteral":
        """Scan a quoted literal whose opening quote is at start.

        A bounded two-state (ordinary character / escape sequence) machine:
        it examines each input character at most once, so scanning is linear
        in the literal length regardless of how the escapes are spelled.
        Stops at the closing quote, at an unescaped newline, or at end of
        input; never crosses a newline, so line tracking stays exact.
        """
        text = self._lexdata
        n = len(text)
        pos = start + 1
        cchars = 0
        bad_escape = -1
        while pos < n:
            ch = text[pos]
            if ch == quote:
                return _QuotedLiteral(pos + 1, True, cchars, bad_escape)
            if ch == "\n":
                break
            if ch == "\\":
                extent, valid = _escape_extent(text, pos)
                if not valid and bad_escape < 0:
                    bad_escape = pos
                pos += extent
            else:
                pos += 1
            cchars += 1
        return _QuotedLiteral(pos, False, cchars, bad_escape)

    def _string_token(self, start: int, tok_type: str) -> Token | None:
        """Scan a string literal whose opening quote is at start.

        On success, emit a tok_type token spanning the whole literal. On
        failure, report the error at the opening quote and consume the
        literal's extent (up to the closing quote, or to the end of the line
        for unterminated literals) without emitting a token.
        """
        result = self._scan_quoted_literal(start, '"')
        if result.closed and result.bad_escape < 0:
            tok = self._make_token(tok_type, self._lexdata[start : result.end], start)
            self._advance_to(result.end)
            return tok
        if result.closed:
            self._error("String contains invalid escape code", start)
        else:
            self._error('Unmatched "', start)
        self._advance_to(result.end)
        return None

    def _char_const_token(self, start: int) -> Token | None:
        """Scan a character constant whose opening quote is at start.

        A single c-char yields CHAR_CONST, two to four c-chars yield a
        multicharacter INT_CONST_CHAR. Anything else (empty, too long,
        invalid escape, or unterminated) is reported and consumed without
        emitting a token.
        """
        result = self._scan_quoted_literal(start, "'")
        if not result.closed:
            self._error("Unmatched '", start)
            self._advance_to(result.end)
            return None
        value = self._lexdata[start : result.end]
        if result.bad_escape >= 0 or not 1 <= result.cchars <= 4:
            self._error(f"Invalid char constant {value}", start)
            self._advance_to(result.end)
            return None
        tok_type = "CHAR_CONST" if result.cchars == 1 else "INT_CONST_CHAR"
        tok = self._make_token(tok_type, value, start)
        self._advance_to(result.end)
        return tok

    def _prefixed_literal_token(self, pos: int, prefix_len: int, quote: str) -> Token:
        """Scan a prefixed literal (L/u8/u/U followed by ' or \") at pos.

        On success, emit the prefixed token spanning prefix and literal. On
        failure, fall back to emitting the prefix as an identifier and let
        the quote be re-scanned unprefixed on the next token() call; this
        preserves maximal-munch behavior (e.g. L'ab' is ID + INT_CONST_CHAR)
        and reports the error at the quote itself.
        """
        text = self._lexdata
        prefix = text[pos : pos + prefix_len]
        tok_type = _prefixed_literal_types[prefix, quote]
        result = self._scan_quoted_literal(pos + prefix_len, quote)
        if (
            result.closed
            and result.bad_escape < 0
            and (quote == '"' or result.cchars == 1)
        ):
            tok = self._make_token(tok_type, text[pos : result.end], pos)
            self._advance_to(result.end)
            return tok
        tok = self._make_token("ID", prefix, pos)
        self._advance_to(pos + prefix_len)
        return tok

    def _attribute_token(self, kind: str, end: int) -> Token:
        """Emit the text from _pos up to end and advance lexer state.

        Attribute delimiters can contain whitespace, and argument clauses can
        span lines. Record the token's starting coordinates before updating
        line tracking for the entire consumed span.
        """
        value = self._lexdata[self._pos : end]
        tok = self._make_token(kind, value, self._pos)
        self._advance_to(end)
        return tok

    def _attribute_arguments(self) -> Token | None:
        """Scan an attribute argument clause with _pos at its opening '('.

        Return one ATTRIBUTE_ARGUMENTS token containing the raw text inside
        the outer parentheses. A stack tracks the expected closing delimiters
        for nested (), [], and {}. Comments and quoted literals are skipped
        while balancing, but preserved in the token value. This bypasses normal
        token classification, keeping arbitrary attribute arguments separate
        from C expressions and scope tracking.

        Report malformed clauses at the opening parenthesis. If the error
        callback returns, consume the remaining input and return None.
        """
        text = self._lexdata
        start = self._pos
        pos = start + 1
        closers = [")"]
        pairs = {"(": ")", "[": "]", "{": "}"}
        error = "Unterminated attribute arguments"
        while pos < len(text):
            ch = text[pos]
            if text.startswith("/*", pos):
                end = text.find("*/", pos + 2)
                if end < 0:
                    break
                pos = end + 2
                continue
            if text.startswith("//", pos):
                end = text.find("\n", pos + 2)
                pos = len(text) if end < 0 else end
                continue
            # Consume whole identifiers and preprocessing numbers first, so
            # digits in literal prefixes aren't confused with numbers and
            # digit separators aren't mistaken for character-literal quotes.
            if match := _attribute_word.match(text, pos):
                pos = match.end()
                continue
            if ch in {"'", '"'}:
                quote = ch
                pos += 1
                while pos < len(text) and text[pos] not in {quote, "\n"}:
                    pos += 2 if text[pos] == "\\" else 1
                if pos >= len(text) or text[pos] != quote:
                    break
                pos += 1
                continue
            if ch in pairs:
                closers.append(pairs[ch])
            elif ch in ")]}":
                if ch != closers[-1]:
                    error = "Mismatched delimiter in attribute arguments"
                    break
                closers.pop()
                if not closers:
                    tok = self._attribute_token("ATTRIBUTE_ARGUMENTS", pos + 1)
                    tok.value = tok.value[1:-1]
                    return tok
            pos += 1
        self._error(error, start)
        self._advance_to(len(text))
        return None

    def _make_token(self, tok_type: str, value: str, pos: int) -> Token:
        """Create a Token at an absolute input position.

        Expects tok_type/value and the absolute byte offset pos in the current
        input. Does not advance lexer state; callers manage _pos themselves.
        Returns a Token with the current filename and line/column coordinates.
        """
        column = pos - self._line_start + 1
        tok = Token(tok_type, value, self._lineno, column, self._filename)
        return tok

    def _error(self, msg: str, pos: int) -> None:
        column = pos - self._line_start + 1
        self.error_func(msg, self._lineno, column)

    def _handle_ppline(self) -> None:
        # Since #line directives aren't supposed to return tokens but should
        # only affect the lexer's state (update line/filename for coords), this
        # method does a bit of parsing on its own. It doesn't return anything,
        # but its side effect is to update self._pos past the directive, and
        # potentially update self._lineno and self._filename, based on the
        # directive's contents.
        #
        # Accepted #line forms from preprocessors:
        # - "#line 66 \"kwas\\df.h\""
        # - "# 9"
        # - "#line 10 \"include/me.h\" 1 2 3" (extra numeric flags)
        # - "# 1 \"file.h\" 3"
        # Errors we must report:
        # - "#line \"file.h\"" (filename before line number)
        # - "#line df" (garbage instead of number/string)
        #
        # We scan the directive line once (after an optional 'line' keyword),
        # validating the order: NUMBER, optional STRING, then any NUMBERs.
        # The NUMBERs tail is only accepted if a filename STRING was present.
        text = self._lexdata
        n = len(text)
        line_end = text.find("\n", self._pos)
        if line_end == -1:
            line_end = n
        line = text[self._pos : line_end]
        pos = 0
        line_len = len(line)

        def skip_ws() -> None:
            nonlocal pos
            while pos < line_len and line[pos] in " \t":
                pos += 1

        skip_ws()
        if line.startswith("line", pos):
            pos += 4

        def success(pp_line: str | None, pp_filename: str | None) -> None:
            if pp_line is None:
                self._error("line number missing in #line", self._pos + line_len)
            else:
                try:
                    self._lineno = int(pp_line.replace("'", ""))
                except ValueError:
                    self._error("invalid #line directive", self._pos + line_len)
                    return
                if pp_filename is not None:
                    self._filename = pp_filename
            self._pos = line_end + 1
            self._line_start = self._pos

        def fail(msg: str, offset: int) -> None:
            self._error(msg, self._pos + offset)
            self._pos = line_end + 1
            self._line_start = self._pos

        skip_ws()
        if pos >= line_len:
            success(None, None)
            return
        if line[pos] == '"':
            fail("filename before line number in #line", pos)
            return

        # Line numbers allow digit separators, but no integer suffixes.
        m = re.match(_decimal_digits, line[pos:])
        if not m:
            fail("invalid #line directive", pos)
            return

        pp_line = m.group(0)
        pos += len(pp_line)
        skip_ws()
        if pos >= line_len:
            success(pp_line, None)
            return

        if line[pos] != '"':
            fail("invalid #line directive", pos)
            return

        m = re.match(_string_literal, line[pos:])
        if not m:
            fail("invalid #line directive", pos)
            return

        pp_filename = m.group(0).lstrip('"').rstrip('"')
        pos += len(m.group(0))

        # Consume arbitrary sequence of numeric flags after the directive
        while True:
            skip_ws()
            if pos >= line_len:
                break
            m = re.match(_decimal_digits, line[pos:])
            if not m:
                fail("invalid #line directive", pos)
                return
            pos += len(m.group(0))

        success(pp_line, pp_filename)

    def _handle_pppragma(self) -> list[Token]:
        # Parse a full #pragma line; returns a list of tokens with 1 or 2
        # tokens - PPPRAGMA and an optional PPPRAGMASTR. If an empty list is
        # returned, it means an error occurred, or we're at the end of input.
        #
        # Examples:
        # - "#pragma" -> PPPRAGMA only
        # - "#pragma once" -> PPPRAGMA, PPPRAGMASTR("once")
        # - "# pragma omp parallel private(th_id)" -> PPPRAGMA, PPPRAGMASTR("omp parallel private(th_id)")
        # - "#\tpragma {pack: 2, smack: 3}" -> PPPRAGMA, PPPRAGMASTR("{pack: 2, smack: 3}")
        text = self._lexdata
        n = len(text)
        pos = self._pos

        while pos < n and text[pos] in " \t":
            pos += 1
        if pos >= n:
            self._pos = pos
            return []

        if not text.startswith("pragma", pos):
            self._error("invalid #pragma directive", pos)
            self._pos = pos + 1
            return []

        pragma_pos = pos
        pos += len("pragma")
        toks = [self._make_token("PPPRAGMA", "pragma", pragma_pos)]

        while pos < n and text[pos] in " \t":
            pos += 1

        start = pos
        while pos < n and text[pos] != "\n":
            pos += 1
        if pos > start:
            toks.append(self._make_token("PPPRAGMASTR", text[start:pos], start))
        if pos < n and text[pos] == "\n":
            self._lineno += 1
            pos += 1
            self._line_start = pos
        self._pos = pos
        return toks


##
## Reserved keywords
##
_keywords: tuple[str, ...] = (
    "AUTO",
    "BREAK",
    "CASE",
    "CHAR",
    "CONST",
    "CONTINUE",
    "DEFAULT",
    "DO",
    "DOUBLE",
    "ELSE",
    "ENUM",
    "EXTERN",
    "FLOAT",
    "FOR",
    "GOTO",
    "IF",
    "INLINE",
    "INT",
    "LONG",
    "REGISTER",
    "OFFSETOF",
    "RESTRICT",
    "RETURN",
    "SHORT",
    "SIGNED",
    "SIZEOF",
    "STATIC",
    "STRUCT",
    "SWITCH",
    "TYPEDEF",
    "UNION",
    "UNSIGNED",
    "VOID",
    "VOLATILE",
    "WHILE",
    "__BUILTIN_VA_ARG",
    "__INT128",
    "_BOOL",
    "_COMPLEX",
    "_GENERIC",
    "_NORETURN",
    "_THREAD_LOCAL",
    "_STATIC_ASSERT",
    "_ATOMIC",
    "_ALIGNOF",
    "_ALIGNAS",
    "_PRAGMA",
)

_keyword_map: dict[str, str] = {}

for keyword in _keywords:
    # Keywords from new C standard are mixed-case, like _Bool, _Alignas, etc.
    if keyword.startswith("_") and len(keyword) > 1 and keyword[1].isalpha():
        _keyword_map[keyword[:2].upper() + keyword[2:].lower()] = keyword
    else:
        _keyword_map[keyword.lower()] = keyword

# Alternate spellings share token types with the existing grammar. The other
# keywords are reserved even where the parser does not yet support their syntax.
_c23_keywords = {
    "alignas": "_ALIGNAS",
    "alignof": "_ALIGNOF",
    "bool": "_BOOL",
    "static_assert": "_STATIC_ASSERT",
    "thread_local": "_THREAD_LOCAL",
    "true": "BOOL_CONST",
    "false": "BOOL_CONST",
    "nullptr": "NULLPTR",
    "constexpr": "CONSTEXPR",
    "typeof": "TYPEOF",
    "typeof_unqual": "TYPEOF_UNQUAL",
    "_BitInt": "_BITINT",
    "_Decimal32": "_DECIMAL32",
    "_Decimal64": "_DECIMAL64",
    "_Decimal128": "_DECIMAL128",
    "_Imaginary": "_IMAGINARY",
}

##
## Regexes for use in tokens
##

# valid C identifiers (K&R2: A.2.3), plus '$' (supported by some compilers)
_identifier = r"[a-zA-Z_$][0-9a-zA-Z_$]*"
_attribute_begin = re.compile(r"\[\s*\[")
_attribute_end = re.compile(r"\]\s*\]")
_attribute_word = re.compile(rf"{_identifier}|(?:[0-9]|\.[0-9])(?:[eEpP][+-]|[\w.'])*")

# Accept digit separators in all dialects, retaining them in token values.
# A quote must be between two digits of the appropriate base; it cannot
# touch a prefix, decimal point, exponent marker/sign, or suffix.
_decimal_digits = "[0-9](?:'?[0-9])*"
_hex_prefix = "0[xX]"
_hex_digits = "[0-9a-fA-F](?:'?[0-9a-fA-F])*"
_bin_prefix = "0[bB]"
_bin_digits = "[01](?:'?[01])*"

# integer constants (K&R2: A.2.5.1)
# C23 wb/WB allows u/U before or after it, but no long suffix. Recognize it
# in every dialect and let the parser enforce C23. Keep these alternatives
# ahead of bare u/U so that an unsigned bit-precise suffix is consumed whole.
_integer_suffix_opt = (
    r"(([uU](wb|WB))|((wb|WB)[uU]?)|"
    r"([uU]ll)|([uU]LL)|(ll[uU]?)|(LL[uU]?)|([uU][lL])|([lL][uU]?)|[uU])?"
)
_decimal_constant = (
    "(0" + _integer_suffix_opt + ")|([1-9](?:'?[0-9])*" + _integer_suffix_opt + ")"
)
_octal_constant = "0(?:'?[0-7])*" + _integer_suffix_opt
_hex_constant = _hex_prefix + _hex_digits + _integer_suffix_opt
_bin_constant = _bin_prefix + _bin_digits + _integer_suffix_opt

_bad_octal_constant = "0(?:'?[0-7])*'?[89]"

# Comments are not supported; the lexer reports them and skips their extent.
_comment_error_message = (
    "Comments are not supported, see https://github.com/eliben/pycparser#3using."
)

# String literals and character constants are scanned by a bounded state
# machine (see CLexer._scan_quoted_literal), not by regexes, so malformed
# literals cannot cause exponential backtracking
# (https://github.com/eliben/pycparser/issues/61).
#
# Tokens preserve their source spelling; the lexer does not decode escapes or
# validate Unicode code points. Escape handling is deliberately permissive:
# simple escapes accept extra letters and punctuation, and numeric escapes
# accept decimal digits, not just octal digits. The permissive spellings also
# support Windows paths in #line filenames, which are matched with
# _string_literal.

# Characters that may follow a backslash in a string or character literal.
_escape_follow_chars = frozenset(ascii_letters + digits + "._~!=&^-\\?'\"")
_hex_digit_chars = frozenset(hexdigits)


def _escape_extent(text: str, pos: int) -> tuple[int, bool]:
    r"""Measure the escape sequence starting at the backslash at pos.

    Returns (extent, valid). extent is the number of input characters the
    escape occupies, counting the backslash; the whole extent forms a single
    c-char. valid is False when the backslash is not followed by a character
    that may begin an escape (or by nothing at all).

    - Decimal escapes consume the whole run of digits: \123 cannot be split
      into \1 followed by the characters 2 and 3.
    - Hexadecimal escapes consume the whole run of hex digits. A \x with no
      following hex digit is a simple escape.
    - Universal character names consume exactly four hex digits after \u or
      eight after \U. A following hex digit is then a separate character,
      unlike with \x. Incomplete forms are simple escapes.
    """
    n = len(text)
    follow = pos + 1
    if follow >= n:
        return 1, False
    ch = text[follow]
    if ch in digits:
        end = follow
        while end < n and text[end] in digits:
            end += 1
        return end - pos, True
    if ch == "x":
        end = follow + 1
        while end < n and text[end] in _hex_digit_chars:
            end += 1
        if end > follow + 1:
            return end - pos, True
        return 2, True
    if ch == "u" or ch == "U":
        width = 4 if ch == "u" else 8
        digits_start = follow + 1
        if digits_start + width <= n and all(
            c in _hex_digit_chars for c in text[digits_start : digits_start + width]
        ):
            return 1 + 1 + width, True
        return 2, True
    if ch in _escape_follow_chars:
        return 2, True
    return 1, False


@dataclass(slots=True)
class _QuotedLiteral:
    # end: offset just past the closing quote; for unterminated literals, the
    #   offset of the terminating newline or the end of input
    # closed: whether the closing quote was found
    # cchars: number of c-chars scanned; each escape sequence counts as one
    # bad_escape: offset of the first invalid escape, or -1 if none
    end: int
    closed: bool
    cchars: int
    bad_escape: int


# Token types for string and character literals with encoding prefixes.
_prefixed_literal_types: dict[tuple[str, str], str] = {
    ("L", '"'): "WSTRING_LITERAL",
    ("u8", '"'): "U8STRING_LITERAL",
    ("u", '"'): "U16STRING_LITERAL",
    ("U", '"'): "U32STRING_LITERAL",
    ("L", "'"): "WCHAR_CONST",
    ("u8", "'"): "U8CHAR_CONST",
    ("u", "'"): "U16CHAR_CONST",
    ("U", "'"): "U32CHAR_CONST",
}


def _literal_prefix(text: str, pos: int) -> tuple[int, str]:
    """Match a literal encoding prefix (L, u8, u, U) at pos.

    Returns (prefix_length, quote) when the characters at pos form a prefix
    directly followed by a quote, or (0, "") otherwise.
    """
    ch = text[pos]
    follow = text[pos + 1 : pos + 3]
    if ch == "u" and follow.startswith("8") and follow[1:2] in ("'", '"'):
        return 2, follow[1]
    if follow[:1] in ("'", '"'):
        return 1, follow[0]
    return 0, ""


# Strings in #line filenames: permissive escapes keep Windows paths such as
# "..\dir\file" lexing as a single string.
_string_char = r"""([^"\\\n]|""" + r"(\\[0-9a-zA-Z._~!=&\^\-\\?'\"])" + ")"
_string_literal = '"' + _string_char + '*"'

# floating constants (K&R2: A.2.5.3)
_exponent_part = "([eE][-+]?" + _decimal_digits + ")"
_fractional_constant = (
    "(("
    + _decimal_digits
    + r")?\."
    + _decimal_digits
    + ")|("
    + _decimal_digits
    + r"\.)"
)
_unsuffixed_floating_constant = (
    "((("
    + _fractional_constant
    + ")"
    + _exponent_part
    + "?)|("
    + _decimal_digits
    + _exponent_part
    + "))"
)
# Recognize C23 decimal suffixes in every dialect; the parser rejects them
# outside C23. Each suffix must be entirely lowercase or uppercase.
# The hexadecimal float pattern below keeps only f/F/l/L.
_floating_constant = _unsuffixed_floating_constant + "(df|dd|dl|DF|DD|DL|[FfLl])?"
_binary_exponent_part = "([pP][+-]?" + _decimal_digits + ")"
_hex_fractional_constant = (
    "(((" + _hex_digits + r""")?\.""" + _hex_digits + ")|(" + _hex_digits + r"""\.))"""
)
_hex_floating_constant = (
    "("
    + _hex_prefix
    + "("
    + _hex_digits
    + "|"
    + _hex_fractional_constant
    + ")"
    + _binary_exponent_part
    + "[FfLl]?)"
)


class _RegexAction(Enum):
    TOKEN = 0
    ID = 1
    ERROR = 2


@dataclass(frozen=True)
class _RegexRule:
    # tok_type: name of the token emitted for a match
    # regex_pattern: the raw regex (no anchors) to match at the current position
    # action: TOKEN for normal tokens, ID for identifiers, ERROR to report
    # error_message: message used for ERROR entries
    tok_type: str
    regex_pattern: str
    action: _RegexAction
    error_message: str | None


_regex_rules: list[_RegexRule] = [
    _RegexRule("HEX_FLOAT_CONST", _hex_floating_constant, _RegexAction.TOKEN, None),
    _RegexRule("FLOAT_CONST", _floating_constant, _RegexAction.TOKEN, None),
    _RegexRule("INT_CONST_HEX", _hex_constant, _RegexAction.TOKEN, None),
    _RegexRule("INT_CONST_BIN", _bin_constant, _RegexAction.TOKEN, None),
    _RegexRule(
        "BAD_CONST_OCT",
        _bad_octal_constant,
        _RegexAction.ERROR,
        "Invalid octal constant",
    ),
    _RegexRule("INT_CONST_OCT", _octal_constant, _RegexAction.TOKEN, None),
    _RegexRule("INT_CONST_DEC", _decimal_constant, _RegexAction.TOKEN, None),
    _RegexRule("ID", _identifier, _RegexAction.ID, None),
]

_regex_actions: dict[str, tuple[_RegexAction, str | None]] = {}
_regex_pattern_parts: list[str] = []
for _rule in _regex_rules:
    _regex_actions[_rule.tok_type] = (_rule.action, _rule.error_message)
    _regex_pattern_parts.append(f"(?P<{_rule.tok_type}>{_rule.regex_pattern})")
# The master regex is a single alternation of all token patterns, each wrapped
# in a named group. We match once at the current position and then use
# `lastgroup` to recover which token kind fired; this avoids iterating over all
# regexes on every character while keeping the same token-level semantics.
_regex_master: re.Pattern[str] = re.compile("|".join(_regex_pattern_parts))
_identifier_pattern: re.Pattern[str] = re.compile(_identifier)
# Identifier start characters that cannot begin a literal prefix (L, u, U).
_identifier_only_first_chars = frozenset(ascii_letters + "_$").difference("LuU")
# Every master-regex alternative starts with one of these characters. Other
# characters (most punctuators) can skip the regex and go to the fixed tokens.
# Quoted literals and comments are handled by bounded state machines before
# the master regex is consulted, so their start characters are absent here.
_regex_first_chars = frozenset(ascii_letters + digits + "_$.")


@dataclass(frozen=True)
class _FixedToken:
    tok_type: str
    literal: str


_fixed_tokens: list[_FixedToken] = [
    _FixedToken("ELLIPSIS", "..."),
    _FixedToken("LSHIFTEQUAL", "<<="),
    _FixedToken("RSHIFTEQUAL", ">>="),
    _FixedToken("PLUSPLUS", "++"),
    _FixedToken("MINUSMINUS", "--"),
    _FixedToken("ARROW", "->"),
    _FixedToken("LAND", "&&"),
    _FixedToken("LOR", "||"),
    _FixedToken("LSHIFT", "<<"),
    _FixedToken("RSHIFT", ">>"),
    _FixedToken("LE", "<="),
    _FixedToken("GE", ">="),
    _FixedToken("EQ", "=="),
    _FixedToken("NE", "!="),
    _FixedToken("TIMESEQUAL", "*="),
    _FixedToken("DIVEQUAL", "/="),
    _FixedToken("MODEQUAL", "%="),
    _FixedToken("PLUSEQUAL", "+="),
    _FixedToken("MINUSEQUAL", "-="),
    _FixedToken("ANDEQUAL", "&="),
    _FixedToken("OREQUAL", "|="),
    _FixedToken("XOREQUAL", "^="),
    _FixedToken("EQUALS", "="),
    _FixedToken("PLUS", "+"),
    _FixedToken("MINUS", "-"),
    _FixedToken("TIMES", "*"),
    _FixedToken("DIVIDE", "/"),
    _FixedToken("MOD", "%"),
    _FixedToken("OR", "|"),
    _FixedToken("AND", "&"),
    _FixedToken("NOT", "~"),
    _FixedToken("XOR", "^"),
    _FixedToken("LNOT", "!"),
    _FixedToken("LT", "<"),
    _FixedToken("GT", ">"),
    _FixedToken("CONDOP", "?"),
    _FixedToken("LPAREN", "("),
    _FixedToken("RPAREN", ")"),
    _FixedToken("LBRACKET", "["),
    _FixedToken("RBRACKET", "]"),
    _FixedToken("LBRACE", "{"),
    _FixedToken("RBRACE", "}"),
    _FixedToken("COMMA", ","),
    _FixedToken("PERIOD", "."),
    _FixedToken("SEMI", ";"),
    _FixedToken("COLON", ":"),
    _FixedToken("COLONCOLON", "::"),
]

# To avoid scanning all fixed tokens on every character, we bucket them by the
# first character. When matching at position i, we only look at the bucket for
# text[i], and we pre-sort that bucket by token length so the first match is
# also the longest. This preserves longest-match semantics (e.g. '>>=' before
# '>>' before '>') while reducing the number of comparisons.
_fixed_tokens_by_first: dict[str, list[_FixedToken]] = {}
for _entry in _fixed_tokens:
    _fixed_tokens_by_first.setdefault(_entry.literal[0], []).append(_entry)
for _bucket in _fixed_tokens_by_first.values():
    _bucket.sort(key=lambda item: len(item.literal), reverse=True)

_line_pattern: re.Pattern[str] = re.compile(r"([ \t]*line\W)|([ \t]*\d+)")
_pragma_pattern: re.Pattern[str] = re.compile(r"[ \t]*pragma\W")
