# ------------------------------------------------------------------------------
# pycparser: c_lexer.py
#
# CLexer class: lexer for the C language
#
# Eli Bendersky [https://eli.thegreenplace.net/]
# License: BSD
# ------------------------------------------------------------------------------
import inspect
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from string import ascii_letters, digits
from typing import Literal, assert_never

Dialect = Literal["legacy", "c23"]


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """A position in a C source.

    Logical coordinates follow preprocessor line markers (``#line`` and
    ``# N "file"`` directives) and therefore describe where the code was
    written before preprocessing. Physical coordinates describe where the
    lexed text actually lives, so a failure inside an included file keeps both
    the logical origin and the concrete physical source.
    """

    filename: str
    lineno: int
    column: int


@dataclass(slots=True)
class FileFrame:
    """Scanning state for one source in the include stack."""
    lexdata: str
    logical_filename: str
    logical_lineno: int
    physical_filename: str
    physical_lineno: int
    physical_line_start: int
    pos: int
    line_start: int
    shared_physical: bool = False

@dataclass(slots=True)
class Token:
    type: str
    value: str
    lineno: int
    column: int
    filename: str = ""
    logical: SourceLocation | None = None
    physical: SourceLocation | None = None


    def __post_init__(self) -> None:
        if self.logical is None:
            self.logical = SourceLocation(self.filename, self.lineno, self.column)
        if self.physical is None:
            self.physical = SourceLocation(
                self.logical.filename, self.logical.lineno, self.logical.column
            )


class CLexer:
    """A standalone lexer for C.

    Constructor parameters:
        error_func:
            Called with (msg, line, column) on lexing errors.
        dialect:
            "legacy" preserves the existing keyword set. "c23" also recognizes
            C23 keywords and predefined constants.
        include_func:
            Optional callback invoked when an ``#include`` directive is
            encountered. It is called with the directive's filename (a raw
            string, without the surrounding quotes or angle brackets) and
            returns the text of the included file, or None when the file is
            unavailable. None makes the lexer report an error and continue
            with the parent file without swallowing any tokens.

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
        include_func: Callable[[str], str | None] | None = None,
    ) -> None:
        if dialect not in ("legacy", "c23"):
            raise ValueError(f"Unknown dialect {dialect!r}; expected 'legacy' or 'c23'")
        # Select keywords once per lexer. input() resets the scanning state
        # without changing this map or affecting lexers using another dialect.
        self._keyword_map = _keyword_map.copy()
        if dialect == "c23":
            self._keyword_map.update(_c23_keywords)

        self.error_func = error_func
        try:
            params = inspect.signature(error_func).parameters
        except (TypeError, ValueError):
            params = {}
        self._error_func_accepts_locations = (
            any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
            or "location" in params
        )
        self.include_func = include_func
        self._init_state()

    def input(self, text: str, filename: str = "") -> None:
        """Initialize the lexer to the given input text.

        filename is an optional name identifying the initial file from which the
        input comes. Line markers and includes update the logical filename,
        which is exposed through the filename property.
        """
        self._init_state()
        self._push_frame(text, filename)

    def _init_state(self) -> None:
        self._lexdata = ""
        self._pos = 0
        self._line_start = 0
        self._physical_line_start = 0
        self._physical_lineno = 1
        self._physical_filename = ""
        self._pending_tok: Token | None = None
        self._in_attribute = False
        self._file_stack: list[FileFrame] = []
        # Frames popped while unwinding unbalanced line markers.
        self._popped_frames: list[FileFrame] = []

    def _push_frame(self, text: str, filename: str) -> None:
        frame = FileFrame(
            lexdata=text,
            logical_filename=filename,
            logical_lineno=1,
            physical_filename=filename,
            physical_lineno=1,
            physical_line_start=0,
            pos=0,
            line_start=0,
        )
        self._file_stack.append(frame)
        self._sync_state(frame)

    def _sync_state(self, frame: FileFrame) -> None:
        self._lexdata = frame.lexdata
        self._pos = frame.pos
        self._line_start = frame.line_start
        self._physical_line_start = frame.physical_line_start
        self._physical_lineno = frame.physical_lineno
        self._physical_filename = frame.physical_filename
        self._lineno = frame.logical_lineno
        self._filename = frame.logical_filename

    def _capture_state(self) -> None:
        frame = self._file_stack[-1]
        frame.pos = self._pos
        frame.line_start = self._line_start
        frame.physical_line_start = self._physical_line_start
        frame.physical_lineno = self._physical_lineno
        frame.logical_lineno = self._lineno
        frame.logical_filename = self._filename
        # Same-buffer line-marker overlays share one physical cursor;
        # propagate it down to the frame that owns the buffer so a
        # later pop resumes at the advanced position, not the old one.
        if getattr(frame, "shared_physical", False):
            root = self._file_stack[0]
            root.pos = self._pos
            root.line_start = self._line_start
            root.physical_line_start = self._physical_line_start
            root.physical_lineno = self._physical_lineno

    def _pop_frame(self) -> bool:
        if len(self._file_stack) <= 1:
            return False
        self._capture_state()
        self._popped_frames.append(self._file_stack.pop())
        self._sync_state(self._file_stack[-1])
        return True

    @property
    def filename(self) -> str:
        return self._filename

    def token(self) -> Token | None:
        # Lexing strategy overview:
        #
        # - We maintain a current position (self._pos), line number, and the
        #   byte offset of the current line start. The lexer is a simple loop
        #   that skips whitespace/newlines and emits one token per call.
        #   A stack of FileFrame objects lets an #include switch to another
        #   text buffer and transparently resume the parent afterwards.
        #
        # - A small amount of logic is handled manually before regex matching:
        #
        #   * Preprocessor-style directives: if we see '#', we check whether
        #     it's a #line, #include or #pragma directive and consume it
        #     inline. #line updates the logical position and produces no
        #     tokens; #include delegates to the include callback and pushes a
        #     new frame on success. #pragma can yield both PPPRAGMA and
        #     PPPRAGMASTR, but token() returns a single token, so we stash the
        #     PPPRAGMASTR as _pending_tok to return on the next token() call.
        #     Otherwise we return PPHASH.
        #   * Newlines update lineno/line-start tracking so tokens can record
        #     accurate columns.
        #
        # - The bulk of tokens are recognized in _match_token:
        #
        #   * _regex_rules: regex patterns for identifiers, literals, and other
        #     complex tokens (including error-producing patterns). The lexer
        #     uses a combined _regex_master to scan options at the same time.
        #   * _fixed_tokens: exact string matches for operators and punctuation,
        #     resolved by longest match.
        #
        # - Error patterns call the error callback and advance minimally, which
        #   keeps lexing resilient while reporting useful diagnostics.
        text = self._lexdata
        n = len(text)

        if self._pending_tok is not None:
            tok = self._pending_tok
            self._pending_tok = None
            return tok

        while True:
            while self._pos < n:
                match text[self._pos]:
                    case " " | "\t" | "\f" | "\v":
                        self._pos += 1
                    case "\n":
                        self._lineno += 1
                        self._physical_lineno += 1
                        self._pos += 1
                        self._line_start = self._pos
                        self._physical_line_start = self._pos
                    case "#":
                        directive = self._match_directive(text, self._pos + 1)
                        if directive == "line":
                            self._pos += 1
                            self._handle_ppline()
                            text = self._lexdata
                            n = len(text)
                            continue
                        if directive == "include":
                            self._pos += 1
                            included_tok = self._handle_ppinclude()
                            if included_tok is not None:
                                return included_tok
                            text = self._lexdata
                            n = len(text)
                            continue
                        if directive == "pragma":
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
            # Reached the end of the current text buffer. Pop any included
            # frame and resume its parent; the top-level frame ends lexing.
            if not self._pop_frame():
                return None
            text = self._lexdata
            n = len(text)

    def _match_directive(self, text: str, pos: int) -> str | None:
        """Classify the '#' directive whose body starts at pos."""
        if _line_pattern.match(text, pos):
            return "line"
        if _pragma_pattern.match(text, pos):
            return "pragma"
        if _include_pattern.match(text, pos):
            return "include"
        return None

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
        # A plain string literal can't also match BAD_STRING_LITERAL, the only
        # master-regex alternative before it that can start with '"'. Match it
        # directly to skip the costly failed attempt at a bad escape.
        if char == '"' and (m := _string_literal_pattern.match(text, pos)):
            tok = self._make_token("STRING_LITERAL", m.group(), pos)
            self._pos = m.end()
            return tok
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
            self._pos += 1
            return None

        length, tok_type, value, action, msg = best
        match action:
            case _RegexAction.TOKEN:
                pass
            case _RegexAction.ERROR:
                if tok_type == "BAD_CHAR_CONST":
                    msg = f"Invalid char constant {value}"
                # All other ERROR rules provide a message.
                assert msg is not None
                self._error(msg, pos)
                self._pos += max(1, length)
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

    def _attribute_token(self, kind: str, end: int) -> Token:
        """Emit the text from _pos up to end and advance lexer state.

        Attribute delimiters can contain whitespace, and argument clauses can
        span lines. Record the token's starting coordinates before updating
        line tracking for the entire consumed span.
        """
        value = self._lexdata[self._pos : end]
        tok = self._make_token(kind, value, self._pos)
        newline_count = value.count("\n")
        self._lineno += newline_count
        self._physical_lineno += newline_count
        if newline_count:
            last_newline = self._pos + value.rfind("\n") + 1
            self._line_start = last_newline
            self._physical_line_start = last_newline
        self._pos = end
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
        self._pos = len(text)
        return None

    def _make_token(self, tok_type: str, value: str, pos: int) -> Token:
        column = pos - self._line_start + 1
        logical = SourceLocation(self._filename, self._lineno, column)
        physical = self._physical_location(pos)
        return Token(
            tok_type,
            value,
            self._lineno,
            column,
            self._filename,
            logical,
            physical,
        )

    def _physical_location(self, pos: int) -> SourceLocation:
        return SourceLocation(
            self._physical_filename,
            self._physical_lineno,
            pos - self._physical_line_start + 1,
        )

    def _error(self, msg: str, pos: int) -> None:
        physical = self._physical_location(pos)
        logical = SourceLocation(
            self._filename,
            self._lineno,
            pos - self._line_start + 1,
        )
        # Keep the legacy (msg, line, column) positional signature so
        # existing 3-argument error callbacks keep working; the dual
        # positions are only passed when the callback accepts them.
        if self._error_func_accepts_locations:
            self.error_func(
                msg,
                logical.lineno,
                logical.column,
                location=logical,
                physical=physical,
            )
        else:
            self.error_func(msg, logical.lineno, logical.column)

    def _consume_directive_line(self, line_end: int) -> None:
        """Advance physical scanning past a directive line.

        Logical line numbering is controlled by the marker itself, so
        only the physical counters move here.
        """
        text = self._lexdata
        if line_end < len(text):
            self._pos = line_end + 1
            self._physical_lineno += 1
            self._line_start = self._pos
            self._physical_line_start = self._pos
        else:
            self._pos = line_end

    def _fail_directive(self, msg: str, line_end: int, error_pos: int) -> None:
        self._error(msg, error_pos)
        self._consume_directive_line(line_end)

    def _handle_ppline(self) -> None:
        # A line marker ("# N" / "#line N [file] [flags...]") carries no
        # tokens. It remaps the logical position and, when a filename with
        # entry/return flags is present, drives the include file stack.
        text = self._lexdata
        n = len(text)
        line_end = text.find("\n", self._pos)
        if line_end == -1:
            line_end = n
        line = text[self._pos:line_end]
        line_len = len(line)
        pos = 0

        def skip_ws() -> None:
            nonlocal pos
            while pos < line_len and line[pos] in " \t":
                pos += 1

        skip_ws()
        explicit_line_keyword = line.startswith("line", pos)
        if explicit_line_keyword:
            pos += 4
        skip_ws()
        if pos >= line_len:
            self._fail_directive(
                "line number missing in #line", line_end, self._pos + line_len
            )
            return
        if line[pos] == "\"":
            self._fail_directive(
                "filename before line number in #line",
                line_end,
                self._pos + pos,
            )
            return

        match = re.match(_decimal_digits, line[pos:])
        if not match:
            self._fail_directive(
                "invalid #line directive", line_end, self._pos + pos
            )
            return
        pp_line = match.group(0)
        pos += len(pp_line)
        skip_ws()

        pp_filename = None
        if pos < line_len and line[pos] == "\"":
            match = re.match(_string_literal, line[pos:])
            if not match:
                self._fail_directive(
                    "invalid #line directive", line_end, self._pos + pos
                )
                return
            quoted = match.group(0)
            pp_filename = quoted[1:-1]
            pos += len(quoted)

        flags = []
        while pos < line_len:
            skip_ws()
            if pos >= line_len:
                break
            match = re.match(_decimal_digits, line[pos:])
            if not match:
                self._fail_directive(
                    "invalid #line directive", line_end, self._pos + pos
                )
                return
            flags.append(int(match.group(0).replace("\x27", "")))
            pos += len(match.group(0))

        try:
            new_lineno = int(pp_line.replace("\x27", ""))
        except ValueError:
            self._fail_directive(
                "invalid #line directive", line_end, self._pos + line_len
            )
            return

        self._consume_directive_line(line_end)
        if pp_filename is not None:
            self._apply_line_marker_file(
                pp_filename, flags, explicit_line_keyword, line_end
            )
        self._lineno = new_lineno

    def _apply_line_marker_file(
        self,
        filename: str,
        flags: list[int],
        explicit_line_keyword: bool,
        line_end: int,
    ) -> None:
        """Apply the filename/flags part of a line marker to the stack."""
        # GCC-style markers use flag 1 for an entry and flag 2 for a
        # return. A plain "#line N file" without flags only remaps the
        # logical filename inside the current source.
        if explicit_line_keyword or not flags:
            self._filename = filename
            return
        first_flag = flags[0]
        if first_flag == 1:
            # A new entry while a same-buffer overlay is active means
            # the previous logical file ended without an explicit
            # return marker. Settle it first so its shared cursor is
            # handed back rather than scanned twice.
            if len(self._file_stack) > 1 and getattr(
                self._file_stack[-1], "shared_physical", False
            ):
                top = self._file_stack[-1]
                parent = self._file_stack[-2]
                parent.pos = self._pos
                parent.line_start = self._line_start
                parent.physical_line_start = self._physical_line_start
                parent.physical_lineno = self._physical_lineno
                self._file_stack.pop()
                self._popped_frames.append(top)
                self._sync_state(parent)
            # An entry marker overlays a new logical file on the SAME
            # physical buffer. The overlay frame borrows the parent
            # physical state, so there is one scanning cursor shared by
            # the nested logical files (real includes get separate text).
            self._capture_state()
            parent = self._file_stack[-1]
            nested = FileFrame(
                lexdata=parent.lexdata,
                logical_filename=filename,
                logical_lineno=1,
                physical_filename=parent.physical_filename,
                physical_lineno=parent.physical_lineno,
                physical_line_start=parent.physical_line_start,
                pos=parent.pos,
                line_start=parent.line_start,
            )
            nested.shared_physical = True
            self._file_stack.append(nested)
            self._filename = filename
        elif first_flag == 2:
            # A return marker drops the same-buffer overlay and resumes
            # the enclosing logical file. Its physical cursor was shared,
            # so no position is rewound or replayed. A missing or
            # non-shared frame degrades to a plain filename remap.
            if len(self._file_stack) > 1:
                top = self._file_stack[-1]
                if getattr(top, "shared_physical", False):
                    # Hand the advanced physical cursor back to
                    # the parent so scanning continues, not replays.
                    parent = self._file_stack[-2]
                    parent.pos = self._pos
                    parent.line_start = self._line_start
                    parent.physical_line_start = self._physical_line_start
                    parent.physical_lineno = self._physical_lineno
                    self._file_stack.pop()
                    self._popped_frames.append(top)
                    self._sync_state(parent)
            if filename:
                self._filename = filename
        else:
            # System-header/extern flags (3, 4...): only annotate.
            self._filename = filename

    def _handle_ppinclude(self) -> Token | None:
        # Handle "# include \"name\"" / "#include <name>" by delegating to
        # the include callback. A failure (missing file, bad encoding,
        # malformed filename) is reported through the error callback but
        # never consumes surrounding tokens: malformed directives rewind to
        # the "#" and emit it normally, while failed lookups simply resume
        # the enclosing source.
        text = self._lexdata
        n = len(text)
        line_end = text.find("\n", self._pos)
        if line_end == -1:
            line_end = n
        line = text[self._pos:line_end]
        hash_pos = self._pos - 1
        stripped = line.lstrip(" \t")
        body = stripped[len("include"):]
        filename, quoted, malformed = self._parse_include_filename(body)
        if malformed or filename is None:
            # Rewind to the "#" and hand it back as a normal
            # PPHASH token so the directive is never silently dropped or looped on.
            self._pos = hash_pos
            self._error("malformed #include directive", hash_pos)
            tok = self._make_token("PPHASH", "#", hash_pos)
            self._pos = hash_pos + 1
            return tok
        if self.include_func is None:
            # No resolver configured: surface the "#" instead of dropping it.
            self._pos = hash_pos
            self._error("include callback not set", hash_pos)
            tok = self._make_token("PPHASH", "#", hash_pos)
            self._pos = hash_pos + 1
            return tok
        try:
            included = self.include_func(filename)
        except UnicodeDecodeError as exc:
            self._error(f"bad encoding in include {filename!r}: {exc}", hash_pos)
            self._consume_directive_line(line_end)
            return
        except OSError as exc:
            self._error(f"cannot include {filename!r}: {exc}", hash_pos)
            self._consume_directive_line(line_end)
            return
        if included is None:
            self._error(f"include file not found: {filename!r}", hash_pos)
            self._consume_directive_line(line_end)
            return
        if not isinstance(included, str):
            self._error("include callback must return str or None", hash_pos)
            self._consume_directive_line(line_end)
            return
        # Commit the directive in the parent, then push the included text.
        self._consume_directive_line(line_end)
        self._capture_state()
        self._push_frame(included, filename)

    def _parse_include_filename(
        self, body: str
    ) -> tuple[str | None, bool, bool]:
        """Parse the filename part of an #include directive body.

        Returns (filename, quoted, malformed). quoted distinguishes
        "name" from <name>; malformed marks a missing/closing quote or
        angle bracket. A missing filename yields (None, False, True).
        """
        pos = 0
        while pos < len(body) and body[pos] in " \t":
            pos += 1
        if pos >= len(body):
            return None, False, True
        opener = body[pos]
        if opener == "\"":
            end = body.find("\"", pos + 1)
            if end == -1:
                return None, True, True
            name = body[pos + 1:end]
            tail = body[end + 1:].strip(" \t")
            if tail:
                return None, True, True
            return name, True, False
        if opener == "<":
            end = body.find(">", pos + 1)
            if end == -1:
                return None, False, True
            name = body[pos + 1:end]
            tail = body[end + 1:].strip(" \t")
            if tail:
                return None, False, True
            return name, False, False
        return None, False, True

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
            self._physical_lineno += 1
            pos += 1
            self._physical_line_start = pos
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

# comments are not supported
_unsupported_c_style_comment = r"\/\*"
_unsupported_cxx_style_comment = r"\/\/"

# Character constants and escape sequences.
#
# Tokens preserve their source spelling; the lexer does not decode escapes or
# validate Unicode code points. Each complete escape must match as one character
# in _cconst_char, which is used for both single and multicharacter constants.
# Matching is deliberately permissive: simple escapes accept extra letters and
# punctuation, and numeric escapes accept decimal digits, not just octal digits.
#
# _cconst_char is also repeated in the error patterns. If an escape can match in
# several ways, long malformed constants can cause exponential backtracking
# (https://github.com/eliben/pycparser/issues/61). The lookaheads prevent this:
# - Decimal and hexadecimal escapes consume the whole run of digits. For
#   example, \123 cannot be split into \1 followed by the characters 2 and 3.
# - A simple \x escape is allowed only when no hexadecimal digit follows it.
# - A complete Unicode escape cannot fall back to a simple \u or \U escape.
# _bad_escape also excludes all decimal digits to agree with this permissiveness.

# Universal character names consume exactly four hex digits after u or eight
# after U. A following hex digit is a separate character, unlike with \x.
_unicode_escape = r"(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})"
# This lookahead runs immediately after the backslash. If a complete Unicode
# escape follows, only _unicode_escape may match it: \u00e9 cannot be read as
# \u followed by 0, 0, e, 9. Incomplete forms retain the permissive behavior
# of simple escapes.
_simple_escape = (
    rf"(?!{_unicode_escape})" r"""([a-wyzA-Z._~!=&\^\-\\?'"]|x(?![0-9a-fA-F]))"""
)
_decimal_escape = r"""(\d+)(?!\d)"""
_hex_escape = r"""(x[0-9a-fA-F]+)(?![0-9a-fA-F])"""
_bad_escape = r"""([\\][^a-zA-Z._~^!=&\^\-\\?'"x0-9])"""

_escape_sequence = (
    r"""(\\("""
    + _simple_escape
    + "|"
    + _decimal_escape
    + "|"
    + _hex_escape
    + "|"
    + _unicode_escape
    + "))"
)

# Strings do not need to count the characters represented by escapes. Match
# just the backslash and a permitted following character; _string_char consumes
# any remaining numeric or Unicode digits as ordinary text. This avoids matching
# complete escape sequences repeatedly. The permissive spellings also support
# Windows paths in #line filenames, which are matched with _string_literal.
_escape_sequence_start_in_string = r"""(\\[0-9a-zA-Z._~!=&\^\-\\?'"])"""

_cconst_char = r"""([^'\\\n]|""" + _escape_sequence + ")"
_char_const = "'" + _cconst_char + "'"
_wchar_const = "L" + _char_const
_u8char_const = "u8" + _char_const
_u16char_const = "u" + _char_const
_u32char_const = "U" + _char_const
_multicharacter_constant = "'" + _cconst_char + "{2,4}'"
_unmatched_quote = "('" + _cconst_char + "*\\n)|('" + _cconst_char + "*$)"
_bad_char_const = (
    r"""('""" + _cconst_char + """[^'\n]+')|('')|('""" + _bad_escape + r"""[^'\n]*')"""
)

# String literals, including wide and Unicode prefixes.
_string_char = r"""([^"\\\n]|""" + _escape_sequence_start_in_string + ")"
_string_literal = '"' + _string_char + '*"'
_wstring_literal = "L" + _string_literal
_u8string_literal = "u8" + _string_literal
_u16string_literal = "u" + _string_literal
_u32string_literal = "U" + _string_literal
_bad_string_literal = '"' + _string_char + "*" + _bad_escape + _string_char + '*"'

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
    _RegexRule(
        "UNSUPPORTED_C_STYLE_COMMENT",
        _unsupported_c_style_comment,
        _RegexAction.ERROR,
        "Comments are not supported, see https://github.com/eliben/pycparser#3using.",
    ),
    _RegexRule(
        "UNSUPPORTED_CXX_STYLE_COMMENT",
        _unsupported_cxx_style_comment,
        _RegexAction.ERROR,
        "Comments are not supported, see https://github.com/eliben/pycparser#3using.",
    ),
    _RegexRule(
        "BAD_STRING_LITERAL",
        _bad_string_literal,
        _RegexAction.ERROR,
        "String contains invalid escape code",
    ),
    _RegexRule("WSTRING_LITERAL", _wstring_literal, _RegexAction.TOKEN, None),
    _RegexRule("U8STRING_LITERAL", _u8string_literal, _RegexAction.TOKEN, None),
    _RegexRule("U16STRING_LITERAL", _u16string_literal, _RegexAction.TOKEN, None),
    _RegexRule("U32STRING_LITERAL", _u32string_literal, _RegexAction.TOKEN, None),
    _RegexRule("STRING_LITERAL", _string_literal, _RegexAction.TOKEN, None),
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
    _RegexRule("INT_CONST_CHAR", _multicharacter_constant, _RegexAction.TOKEN, None),
    _RegexRule("CHAR_CONST", _char_const, _RegexAction.TOKEN, None),
    _RegexRule("WCHAR_CONST", _wchar_const, _RegexAction.TOKEN, None),
    _RegexRule("U8CHAR_CONST", _u8char_const, _RegexAction.TOKEN, None),
    _RegexRule("U16CHAR_CONST", _u16char_const, _RegexAction.TOKEN, None),
    _RegexRule("U32CHAR_CONST", _u32char_const, _RegexAction.TOKEN, None),
    _RegexRule("UNMATCHED_QUOTE", _unmatched_quote, _RegexAction.ERROR, "Unmatched '"),
    _RegexRule("BAD_CHAR_CONST", _bad_char_const, _RegexAction.ERROR, None),
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
_string_literal_pattern: re.Pattern[str] = re.compile(_string_literal)
# Identifier start characters that cannot begin a literal prefix (L, u, U).
_identifier_only_first_chars = frozenset(ascii_letters + "_$").difference("LuU")
# Every master-regex alternative starts with one of these characters. Other
# characters (most punctuators) can skip the regex and go to the fixed tokens.
_regex_first_chars = frozenset(ascii_letters + digits + "_$.'\"/")


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
_include_pattern: re.Pattern[str] = re.compile(r"[ \t]*include\W")
