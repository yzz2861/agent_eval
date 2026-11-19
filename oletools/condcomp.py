#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
condcomp.py
===========

Static, non-executing conditional-compilation view for VBA macros.

olevba's plain keyword report scans the whole module as a single flat text.
When a macro hides its dangerous statements behind VBA conditional-compilation
directives (``#If VBA7 / #ElseIf / #Else / #End If``), the mutually exclusive
branches are then reported together as if they could run in the same
execution. This module instead models the ``#If`` region tree and binds every
statement to the condition under which it is actually reachable.

Main properties:

* No macro is ever executed: this is a purely static text/AST analysis.
* Supports ``#Const`` declarations, explicit environment values supplied by
  the caller, nested ``#If``/``#ElseIf``/``#Else`` blocks and the built-in
  conditional-compilation constants (``VBA7``, ``Win64``, ``Win16`` ...).
* Conditions that depend on an unknown constant are *not* collapsed to a single
  guess: every still-possible branch is enumerated as a separate scenario and
  the required constant assignment is reported.
* Auto-executable entry points and suspicious calls are linked into attack
  chains only when they are condition-compatible. Two statements living in
  mutually exclusive branches can never be joined into the same chain.
* Syntactically broken directives only make the affected region uncertain; the
  rest of the module keeps being analysed normally.
* Every reported item carries the module name and the original source line
  number (1-based, in the raw extracted module text).

Usage (programmatic)::

    from oletools import condcomp
    report = condcomp.analyze_vba_modules(modules, env={'VBA7': 1, 'Win64': 1})
    for scenario in report.scenarios:
        ...

See olevba.py for the command-line integration (``--cond-comp``).

Author: oletools contributors
"""

# === LICENSE =================================================================

# condcomp is part of the python-oletools package:
# http://www.decalage.info/python/oletools
#
# condcomp is (c) 2024 oletools contributors
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function

__version__ = '0.10'

import re
import logging

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log = logging.getLogger(__name__)
# add a NullHandler to avoid "No handler found" warnings on Python 2:
try:
    log.addHandler(logging.NullHandler())
except AttributeError:  # pragma: no cover - Python 2 fallback
    class _NullHandler(logging.Handler):
        def emit(self, record):
            pass
    log.addHandler(_NullHandler())


# === THREE-VALUED LOGIC =====================================================

#: condition is definitely true in the current evaluation context
TRUE = 1
#: condition is definitely false in the current evaluation context
FALSE = 0
#: condition cannot be decided because it depends on an unknown constant
UNKNOWN = -1


def tri_not(value):
    """Negation in Kleene three-valued logic."""
    if value == TRUE:
        return FALSE
    if value == FALSE:
        return TRUE
    return UNKNOWN


def tri_and(left, right):
    """Conjunction in Kleene three-valued logic."""
    if left == FALSE or right == FALSE:
        return FALSE
    if left == TRUE and right == TRUE:
        return TRUE
    return UNKNOWN


def tri_or(left, right):
    """Disjunction in Kleene three-valued logic."""
    if left == TRUE or right == TRUE:
        return TRUE
    if left == FALSE and right == FALSE:
        return FALSE
    return UNKNOWN


# === ERRORS =================================================================

class CCError(Exception):
    """Base class for conditional-compilation analysis errors."""


class CCParseError(CCError):
    """Raised when a conditional-compilation expression cannot be parsed."""


# === BUILT-IN CONSTANTS =====================================================

# VBA conditional-compilation constants defined by the host application.
# They are only treated as known when the caller explicitly provides a value:
# by default they remain unknown so that all host environments are considered.
# Reference: MS-VBAL "Conditional Compilation Constants".
BUILTIN_CONSTANTS = frozenset((
    'VBA7', 'VBA6', 'Win64', 'Win32', 'Win16', 'Mac', 'Linux',
))

#: VBA expression words that must never be treated as unknown constants
EXPRESSION_WORDS = frozenset((
    'AND', 'OR', 'NOT', 'MOD', 'TRUE', 'FALSE', 'NULL',
))


def _normalize_env(env):
    """
    Normalize a user-supplied environment mapping.

    Keys are upper-cased constant names. Values are coerced to Python
    int/bool/str so they can feed the expression evaluator.
    """
    normalized = {}
    if not env:
        return normalized
    for name, value in env.items():
        if isinstance(value, str):
            text = value.strip()
            if text.lower() in ('true', '-1'):
                coerced = TRUE
            elif text.lower() in ('false', '0'):
                coerced = FALSE
            else:
                try:
                    coerced = int(text, 0)
                except ValueError:
                    coerced = text
        elif isinstance(value, bool):
            coerced = TRUE if value else FALSE
        else:
            coerced = value
        normalized[str(name).strip().upper()] = coerced
    return normalized


# === CONDITIONAL EXPRESSION AST =============================================
#
# A small AST + recursive-descent parser for the expressions accepted by
# VBA ``#If`` / ``#Const`` directives. It only supports the documented
# conditional-compilation grammar (literals, named constants, arithmetic,
# comparison and the logical operators And/Or/Not), which is enough to model
# real-world VBA7/Win64 guards without ever evaluating the macro itself.

class Node(object):
    """Base class for expression AST nodes."""


class Literal(Node):
    """A numeric or string literal."""
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return 'Literal(%r)' % (self.value,)


class Symbol(Node):
    """A named conditional-compilation constant."""
    def __init__(self, name):
        self.name = name.upper()

    def __repr__(self):
        return 'Symbol(%s)' % (self.name,)


class UnaryOp(Node):
    """A unary operator (``-`` or ``Not``)."""
    def __init__(self, op, operand):
        self.op = op.upper()
        self.operand = operand


class BinOp(Node):
    """A binary operator (arithmetic, comparison or logical)."""
    def __init__(self, op, left, right):
        self.op = op.upper()
        self.left = left
        self.right = right


class ExpressionParser(object):
    """
    Tokenizer and recursive-descent parser for VBA conditional expressions.

    Grammar (operator precedence, lowest to highest)::

        or_expr   := and_expr (Or and_expr)*
        and_expr  := not_expr (And not_expr)*
        not_expr  := Not not_expr | comparison
        comparison:= addition (('=' | '<>' | '<' | '>' | '<=' | '>=') addition)?
        addition  := term (('+' | '-') term)*
        term      := factor (('*' | '\\' | '/' | 'Mod') factor)*
        factor    := ('-' factor) | atom
        atom      := NUMBER | STRING | NAME | '(' or_expr ')'
    """

    _TOKEN_RE = re.compile(
        r"""\s*(?P<number>\d+(?:\.\d+)?|0x[0-9a-fA-F]+)
            |\s*(?P<string>"(?:[^"]|"")*")
            |\s*(?P<op><=|>=|<>|[()=+\-*/\\<>])
            |\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)
            |\s*(?P<ws>\s+)""",
        re.VERBOSE)

    def __init__(self, text):
        self.text = text
        self.tokens = self._tokenize(text)
        self.pos = 0

    def _tokenize(self, text):
        tokens = []
        index = 0
        length = len(text)
        while index < length:
            match = self._TOKEN_RE.match(text, index)
            if not match:
                raise CCParseError(
                    'Unexpected character %r in expression %r'
                    % (text[index], text))
            index = match.end()
            kind = match.lastgroup
            if kind == 'ws':
                continue
            value = match.group()
            tokens.append((kind, value.strip()))
        return tokens

    def _peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return (None, None)

    def _take(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self):
        node = self.parse_or()
        if self.pos != len(self.tokens):
            raise CCParseError(
                'Trailing tokens in expression %r' % (self.text,))
        return node

    def parse_or(self):
        node = self.parse_and()
        while self._peek()[1] and self._peek()[1].lower() == 'or':
            self._take()
            node = BinOp('Or', node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self._peek()[1] and self._peek()[1].lower() == 'and':
            self._take()
            node = BinOp('And', node, self.parse_not())
        return node

    def parse_not(self):
        token = self._peek()
        if token[1] and token[1].lower() == 'not':
            self._take()
            return UnaryOp('Not', self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_addition()
        token = self._peek()
        if token[0] == 'op' and token[1] in ('=', '<>', '<', '>', '<=', '>='):
            self._take()
            right = self.parse_addition()
            return BinOp(token[1], left, right)
        return left

    def parse_addition(self):
        node = self.parse_term()
        while self._peek()[0] == 'op' and self._peek()[1] in ('+', '-'):
            op = self._take()[1]
            node = BinOp(op, node, self.parse_term())
        return node

    def parse_term(self):
        node = self.parse_factor()
        while True:
            token = self._peek()
            if token[0] == 'op' and token[1] in ('*', '/', chr(92)):
                op = self._take()[1]
                node = BinOp(op, node, self.parse_factor())
            elif token[1] and token[1].lower() == 'mod':
                self._take()
                node = BinOp('Mod', node, self.parse_factor())
            else:
                break
        return node

    def parse_factor(self):
        token = self._peek()
        if token == ('op', '-'):
            self._take()
            return UnaryOp('-', self.parse_factor())
        if token == ('op', '+'):
            self._take()
            return self.parse_factor()
        return self.parse_atom()

    def parse_atom(self):
        kind, value = self._take()
        if kind == 'number':
            if value.lower().startswith('0x'):
                return Literal(int(value, 16))
            if '.' in value:
                return Literal(float(value))
            return Literal(int(value))
        if kind == 'string':
            return Literal(value[1:-1].replace('""', '"'))
        if kind == 'name':
            if value.lower() == 'true':
                return Literal(TRUE)
            if value.lower() == 'false':
                return Literal(FALSE)
            if value.lower() == 'null':
                raise CCParseError('Null is not supported in %r' % self.text)
            return Symbol(value)
        if kind == 'op' and value == '(':
            node = self.parse_or()
            closing = self._take()
            if closing != ('op', ')'):
                raise CCParseError(
                    'Missing closing parenthesis in %r' % self.text)
            return node
        raise CCParseError('Unexpected token %r in %r' % (value, self.text))


def parse_expression(text):
    """Parse a conditional-compilation expression string into an AST."""
    if text is None or not str(text).strip():
        raise CCParseError('Empty conditional expression')
    return ExpressionParser(str(text)).parse()


# === EXPRESSION EVALUATION ==================================================

class UnknownAtom(Node):
    """
    Internal node for a comparison/arithmetic expression whose truth value
    cannot be computed because one of its symbols is unknown. It is registered
    once in an :class:`EvalContext` and then enumerated as a boolean variable.
    """
    def __init__(self, key, text):
        self.key = key
        self.text = text

    def __repr__(self):
        return 'UnknownAtom(%s)' % (self.text,)


class EvalContext(object):
    """
    Holds the constant values used while evaluating condition ASTs.

    Resolution order for a symbol name:

    1. explicit environment values supplied by the caller;
    2. module-level ``#Const`` expressions (evaluated recursively);
    3. an :class:`UnknownAtom`, which keeps the condition undecided instead
       of guessing a value.
    """

    def __init__(self, env=None, consts=None):
        #: user-supplied / built-in constant values, upper-cased names
        self.env = env or {}
        #: module #Const name -> expression AST
        self.consts = consts or {}
        #: UnknownAtom key -> UnknownAtom instance
        self.atoms = {}
        #: names currently being resolved (cycle guard for #Const chains)
        self._resolving = set()

    def unknown_atom(self, node, text):
        # Deduplicate on the rendered expression rather than the node id so
        # that the same symbol / sub-expression used in several #If blocks is
        # modelled as a single boolean variable.
        key = text
        atom = self.atoms.get(key)
        if atom is None:
            atom = UnknownAtom(key, text)
            self.atoms[key] = atom
        return atom

    def resolve_symbol(self, node):
        name = node.name
        if name in self.env:
            return self.env[name]
        if name in self.consts and name not in self._resolving:
            self._resolving.add(name)
            try:
                return self.evaluate(self.consts[name])
            finally:
                self._resolving.discard(name)
        return self.unknown_atom(node, name)

    def evaluate(self, node):
        """
        Evaluate an AST node.

        Returns a concrete Python value, or an :class:`UnknownAtom` when the
        value depends on an unresolved constant.
        """
        if isinstance(node, Literal):
            return node.value
        if isinstance(node, UnknownAtom):
            return node
        if isinstance(node, Symbol):
            return self.resolve_symbol(node)
        if isinstance(node, UnaryOp):
            value = self.evaluate(node.operand)
            if isinstance(value, UnknownAtom):
                if node.op == 'NOT':
                    return value
                return value
            if node.op == 'NOT':
                # VBA uses -1 for True; Not flips every bit
                return FALSE if value else TRUE
            return -value
        if isinstance(node, BinOp):
            return self._eval_binop(node)
        raise CCError('Cannot evaluate node %r' % (node,))

    def _eval_binop(self, node):
        op = node.op
        if op == 'AND':
            return self._eval_logical(node, tri_and)
        if op == 'OR':
            return self._eval_logical(node, tri_or)
        left = self.evaluate(node.left)
        right = self.evaluate(node.right)
        if isinstance(left, UnknownAtom) or isinstance(right, UnknownAtom):
            return self.unknown_atom(node, self._render(node))
        try:
            if op == '+':
                return left + right
            if op == '-':
                return left - right
            if op == '*':
                return left * right
            if op == '/':
                return left / right
            if op == '\\':
                return int(left) // int(right)
            if op == 'MOD':
                return int(left) % int(right)
            if op == '=':
                return TRUE if left == right else FALSE
            if op == '<>':
                return TRUE if left != right else FALSE
            if op == '<':
                return TRUE if left < right else FALSE
            if op == '>':
                return TRUE if left > right else FALSE
            if op == '<=':
                return TRUE if left <= right else FALSE
            if op == '>=':
                return TRUE if left >= right else FALSE
        except (TypeError, ValueError, ZeroDivisionError) as exc:
            raise CCParseError('Cannot evaluate %s %s %s (%s)'
                               % (left, op, right, exc))
        raise CCParseError('Unsupported operator %r' % op)

    def _eval_logical(self, node, combinator):
        left = self.evaluate(node.left)
        right = self.evaluate(node.right)
        left_tri = self._as_tri(left)
        right_tri = self._as_tri(right)
        result = combinator(left_tri, right_tri)
        if result != UNKNOWN:
            return result
        if isinstance(left, UnknownAtom):
            return left
        if isinstance(right, UnknownAtom):
            return right
        return self.unknown_atom(node, self._render(node))

    @staticmethod
    def _as_tri(value):
        if isinstance(value, UnknownAtom):
            return UNKNOWN
        return TRUE if value else FALSE

    @staticmethod
    def _render(node):
        # lightweight, best-effort rendering for scenario labels
        if isinstance(node, Symbol):
            return node.name
        if isinstance(node, BinOp):
            return '%s %s %s' % (EvalContext._render(node.left),
                                 node.op, EvalContext._render(node.right))
        if isinstance(node, UnaryOp):
            return '%s %s' % (node.op, EvalContext._render(node.operand))
        if isinstance(node, Literal):
            return str(node.value)
        return '?'


def evaluate_condition(node, context):
    """
    Evaluate a condition AST to a tri-state boolean.

    :return: TRUE, FALSE or UNKNOWN
    """
    value = context.evaluate(node)
    if isinstance(value, UnknownAtom):
        return UNKNOWN, value
    return (TRUE if value else FALSE), None


# === REGION TREE PARSING ====================================================

# A conditional-compilation directive, allowing optional leading whitespace
# and an optional line number (some modules are exported with them).
RE_DIRECTIVE = re.compile(
    r'^\s*(?:\d+\s+)?#\s*(?P<kw>If|ElseIf|Else|End\s+If|Const)\b'
    r'(?P<rest>.*)$',
    re.IGNORECASE)

# #Const NAME = expression
RE_CONST = re.compile(
    r'^\s*(?:\d+\s+)?#\s*Const\s+'
    r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>.+?)\s*$',
    re.IGNORECASE)

# Sub / Function / Property procedure header
RE_PROC = re.compile(
    r'^\s*(?:(?P<visibility>Public|Private|Friend|Global)\s+)?'
    r'(?:Static\s+)?(?P<kind>Sub|Function|Property\s+(?:Get|Let|Set))\s+'
    r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE)

# End Sub / End Function / End Property
RE_END_PROC = re.compile(
    r'^\s*(?:\d+\s+)?End\s+(?:Sub|Function|Property)\b',
    re.IGNORECASE)

# A bare procedure-name call, e.g. "RunPayload" or "Call RunPayload"
RE_CALL = re.compile(r'\b(?:Call\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|$)')

#: words that look like calls but are VBA statements, not user procedures
CALL_STOPWORDS = frozenset((
    'IF', 'WHILE', 'FOR', 'WITH', 'SELECT', 'DO', 'LOOP', 'NEXT', 'WEND',
    'CALL', 'SUB', 'FUNCTION', 'DIM', 'REDIM', 'SET', 'LET', 'GET', 'END',
    'EXIT', 'GOTO', 'ON', 'ERROR', 'RESUME', 'RAISEEVENT', 'REM', 'PRINT',
    'OPEN', 'CLOSE', 'WRITE', 'READ', 'PUT', 'KILL', 'MKDIR', 'RMDIR',
    'CHDIR', 'MKDIR', 'DECLARE', 'OPTION', 'MODULE', 'CLASS', 'EVENT',
    'IMPLEMENTS', 'ENUM', 'TYPE', 'CONST', 'BYVAL', 'BYREF', 'OPTIONAL',
    'PARAMARRAY', 'STOP', 'RETURN', 'YIELD', 'USING', 'NAMESPACE',
))


class Branch(object):
    """One selectable branch of an ``#If`` frame."""

    def __init__(self, kind, condition_ast=None, condition_text=None,
                 line_no=None):
        #: 'if', 'elseif', 'else' or 'broken'
        self.kind = kind
        #: condition AST (None for an Else / broken branch)
        self.condition_ast = condition_ast
        #: raw condition text, kept for reports and unknown-atom labels
        self.condition_text = condition_text
        #: source line of the directive that opens the branch
        self.line_no = line_no
        #: True when the condition expression could not be parsed
        self.broken = condition_ast is None and kind in ('if', 'elseif')


class Frame(object):
    """An ``#If ... #End If`` region and its ordered branches."""

    def __init__(self, open_line):
        self.open_line = open_line
        self.branches = []
        self.closed = False
        #: True when nesting is malformed around this frame
        self.broken = False


class LineRecord(object):
    """A source statement line bound to its conditional-compilation path."""

    def __init__(self, line_no, text, path, uncertain=False,
                 uncertain_reasons=None):
        #: 1-based line number in the raw extracted module text
        self.line_no = line_no
        #: raw source text (without line ending)
        self.text = text
        #: tuple of (frame, branch) selections enclosing this line
        self.path = tuple(path)
        #: True when a broken directive makes reachability undecidable here
        self.uncertain = uncertain
        self.uncertain_reasons = list(uncertain_reasons or [])

    @property
    def is_code(self):
        return not RE_DIRECTIVE.match(self.text)


class ParsedModule(object):
    """Result of parsing one VBA module."""

    def __init__(self, module_name):
        self.module_name = module_name
        #: ordered list of LineRecord for every physical line
        self.lines = []
        #: #Const name -> (expression AST or None if broken, raw text, line)
        self.consts = {}
        #: all frames, outer first
        self.frames = []
        #: list of (line_no, message) for malformed directives
        self.damage = []

    def code_lines(self):
        """Yield LineRecord entries that are actual statements."""
        for record in self.lines:
            if record.is_code:
                yield record


def parse_module(vba_code, module_name='<module>'):
    """
    Parse one VBA module into a :class:`ParsedModule`.

    The function never executes the macro: it only walks the physical lines
    to collect ``#Const`` declarations and the ``#If`` frame tree. Every
    statement line is bound to the tuple of (frame, branch) selections that
    encloses it. Malformed directives are recorded in ``damage`` and only the
    affected region is flagged uncertain; parsing always returns a result.

    :param str vba_code: raw VBA source of one module
    :param str module_name: name used in reports
    :rtype: ParsedModule
    """
    parsed = ParsedModule(module_name)
    # stack of Frame objects currently open
    frame_stack = []
    # stack aligned with frame_stack: the current Branch inside each frame
    branch_stack = []

    def current_path():
        return tuple(zip(frame_stack, branch_stack))

    def open_uncertainty():
        """Reasons inherited by every line inside the open frames."""
        reasons = []
        for frame, branch in current_path():
            if frame.broken:
                reasons.append('Malformed #If region opened at line %d'
                               % frame.open_line)
            elif branch is not None and branch.broken:
                reasons.append('Unparsable condition at line %d'
                               % branch.line_no)
        return reasons

    for line_no, raw_line in enumerate(
            str(vba_code).splitlines(), start=1):
        directive = RE_DIRECTIVE.match(raw_line)
        if directive is None:
            parsed.lines.append(LineRecord(
                line_no, raw_line, current_path(),
                uncertain=bool(open_uncertainty()),
                uncertain_reasons=open_uncertainty()))
            continue

        keyword = re.sub(r'\s+', ' ', directive.group('kw')).lower()
        rest = directive.group('rest')
        rest = re.sub(r'(?i)\s+Then\s*$', '', rest).strip()
        _handle_directive(parsed, frame_stack, branch_stack, line_no,
                          raw_line, keyword, rest, current_path,
                          open_uncertainty)

    # Unclosed frames: mark them broken and flag the remaining records.
    for frame in frame_stack:
        frame.broken = True
        parsed.damage.append(
            (frame.open_line, '#If block is never closed by #End If'))
    if frame_stack:
        for record in parsed.lines:
            for frame, _branch in record.path:
                if frame.broken and not record.uncertain:
                    record.uncertain = True
                    record.uncertain_reasons.append(
                        'Unclosed #If region opened at line %d'
                        % frame.open_line)
    return parsed


def _handle_directive(parsed, frame_stack, branch_stack, line_no,
                      raw_line, keyword, rest, current_path,
                      open_uncertainty):
    """Process one conditional-compilation directive line."""
    if keyword == 'if':
        frame = Frame(line_no)
        parsed.frames.append(frame)
        ast = _safe_parse_condition(parsed, line_no, rest)
        branch = Branch('if', ast, rest.strip(), line_no)
        frame.branches.append(branch)
        frame_stack.append(frame)
        branch_stack.append(branch)
        if ast is None:
            frame.broken = True
        parsed.lines.append(LineRecord(
            line_no, raw_line, current_path(),
            uncertain=bool(open_uncertainty()),
            uncertain_reasons=open_uncertainty()))
        return

    if keyword == 'elseif':
        if not frame_stack:
            parsed.damage.append(
                (line_no, '#ElseIf without a matching #If'))
            parsed.lines.append(LineRecord(
                line_no, raw_line, current_path(), uncertain=True,
                uncertain_reasons=['#ElseIf without a matching #If']))
            return
        frame = frame_stack[-1]
        ast = _safe_parse_condition(parsed, line_no, rest)
        branch = Branch('elseif', ast, rest.strip(), line_no)
        frame.branches.append(branch)
        branch_stack[-1] = branch
        if ast is None:
            frame.broken = True
        parsed.lines.append(LineRecord(
            line_no, raw_line, current_path(),
            uncertain=bool(open_uncertainty()),
            uncertain_reasons=open_uncertainty()))
        return

    if keyword == 'else':
        if not frame_stack:
            parsed.damage.append((line_no, '#Else without a matching #If'))
            parsed.lines.append(LineRecord(
                line_no, raw_line, current_path(), uncertain=True,
                uncertain_reasons=['#Else without a matching #If']))
            return
        frame = frame_stack[-1]
        branch = Branch('else', None, None, line_no)
        frame.branches.append(branch)
        branch_stack[-1] = branch
        parsed.lines.append(LineRecord(
            line_no, raw_line, current_path(),
            uncertain=bool(open_uncertainty()),
            uncertain_reasons=open_uncertainty()))
        return

    if keyword == 'end if':
        if not frame_stack:
            parsed.damage.append((line_no, '#End If without a matching #If'))
            parsed.lines.append(LineRecord(
                line_no, raw_line, current_path(), uncertain=True,
                uncertain_reasons=['#End If without a matching #If']))
            return
        frame = frame_stack.pop()
        branch_stack.pop()
        frame.closed = True
        parsed.lines.append(LineRecord(
            line_no, raw_line, current_path(),
            uncertain=bool(open_uncertainty()),
            uncertain_reasons=open_uncertainty()))
        return

    if keyword == 'const':
        _handle_const(parsed, line_no, raw_line, current_path,
                      open_uncertainty)
        return

    # Unknown directive: keep the line but do not let it break the module.
    parsed.damage.append((line_no, 'Unknown conditional directive %r' % raw_line))
    parsed.lines.append(LineRecord(
        line_no, raw_line, current_path(), uncertain=True,
        uncertain_reasons=open_uncertainty() + ['Unknown directive']))


def _safe_parse_condition(parsed, line_no, rest):
    """Parse a condition expression, recording damage instead of raising."""
    try:
        return parse_expression(rest)
    except CCParseError as exc:
        parsed.damage.append((line_no, str(exc)))
        return None


def _handle_const(parsed, line_no, raw_line, current_path,
                  open_uncertainty):
    """Store a #Const declaration; a broken RHS only damages that constant."""
    match = RE_CONST.match(raw_line)
    if match is None:
        parsed.damage.append((line_no, 'Malformed #Const declaration'))
        parsed.lines.append(LineRecord(
            line_no, raw_line, current_path(), uncertain=True,
            uncertain_reasons=open_uncertainty() +
            ['Malformed #Const declaration']))
        return
    name = match.group('name').upper()
    expr_text = match.group('expr').strip()
    try:
        ast = parse_expression(expr_text)
    except CCParseError as exc:
        parsed.damage.append((line_no, str(exc)))
        ast = None
    parsed.consts[name] = (ast, expr_text, line_no)
    parsed.lines.append(LineRecord(
        line_no, raw_line, current_path(),
        uncertain=bool(open_uncertainty()),
        uncertain_reasons=open_uncertainty()))


# === ANALYSIS MODEL =========================================================

class Procedure(object):
    """A VBA Sub/Function/Property extracted without executing the macro."""

    def __init__(self, name, kind, start_line, end_line=None):
        #: procedure name as written in the source
        self.name = name
        #: upper-cased name used for call resolution
        self.key = name.upper()
        #: 'Sub', 'Function' or 'Property Get/Let/Set'
        self.kind = kind
        #: first physical line of the header (1-based)
        self.start_line = start_line
        #: physical line of the matching End statement, if found
        self.end_line = end_line
        #: list of LineRecord statements making up the body
        self.body = []


class KeywordHit(object):
    """An auto-exec or suspicious keyword located on a specific line."""

    def __init__(self, keyword, description, line_no, text, category,
                 record):
        self.keyword = keyword
        self.description = description
        self.line_no = line_no
        self.text = text
        #: 'AutoExec' or 'Suspicious'
        self.category = category
        #: back-reference to the LineRecord carrying the branch path
        self.record = record


class CallEdge(object):
    """A static call from one procedure line to another procedure name."""

    def __init__(self, caller, callee_key, callee_name, line_no, record):
        self.caller = caller
        self.callee_key = callee_key
        self.callee_name = callee_name
        self.line_no = line_no
        self.record = record


class Chain(object):
    """
    A condition-compatible path from an auto-executable entry point to one
    suspicious call. Every hop shares the same scenario, so two mutually
    exclusive branches can never appear in the same chain.
    """

    def __init__(self, module_name, entry, target, path, scenario):
        self.module_name = module_name
        #: entry KeywordHit (an AutoExec keyword)
        self.entry = entry
        #: terminal suspicious KeywordHit
        self.target = target
        #: ordered list of (procedure name, call line) hops, entry first
        self.path = path
        self.scenario = scenario

    def to_dict(self):
        return {
            'module': self.module_name,
            'entry_keyword': self.entry.keyword,
            'entry_line': self.entry.line_no,
            'entry_procedure': self.path[0][0],
            'suspicious_keyword': self.target.keyword,
            'suspicious_description': self.target.description,
            'suspicious_line': self.target.line_no,
            'call_path': [
                {'procedure': proc, 'line': line_no}
                for proc, line_no in self.path
            ],
            'scenario_id': self.scenario.scenario_id,
        }


class Scenario(object):
    """One internally consistent assignment of the conditional constants."""

    def __init__(self, scenario_id, assignment, guard_values,
                 is_unknown_environment=False):
        #: stable 1-based index inside the report
        self.scenario_id = scenario_id
        #: dict ATOM-TEXT -> TRUE/FALSE for every unknown boolean atom
        self.assignment = assignment
        #: dict id(frame) -> index of the selected branch in this scenario
        self.guard_values = guard_values
        #: True when the enumeration was capped and not exhaustive
        self.is_unknown_environment = is_unknown_environment
        #: LineRecord statements reachable in this scenario
        self.active_lines = []
        #: KeywordHit reachable in this scenario
        self.keyword_hits = []
        #: Chain objects reachable in this scenario
        self.chains = []

    @property
    def conditions(self):
        """Human-readable list of 'CONST = value' constraints."""
        return ['%s = %s' % (name, 'True' if value == TRUE else 'False')
                for name, value in sorted(self.assignment.items())]


class ModuleReport(object):
    """All scenarios and structural findings for one analyzed module."""

    def __init__(self, module_name):
        self.module_name = module_name
        #: ParsedModule used as the analysis basis
        self.parsed = None
        #: list of Procedure objects (independent of scenarios)
        self.procedures = []
        #: list of (line_no, message) syntax-damage records
        self.damage = []
        #: list of Scenario objects
        self.scenarios = []
        #: names of constants supplied explicitly by the caller
        self.provided_constants = []
        #: names left unspecified and therefore enumerated
        self.unknown_constants = []
        #: True when enumeration had to be capped
        self.enumeration_capped = False

    @property
    def chains(self):
        # All chains across every scenario of this module.
        result = []
        for scenario in self.scenarios:
            result.extend(scenario.chains)
        return result

    def to_dict(self):
        # JSON-serializable view of this module report.
        return report_to_dict(self)


# === KEYWORD TABLES =========================================================

# Lazy access to olevba keyword tables: imported on demand so that importing
# condcomp stays cheap and does not create an import cycle at module load.
_keyword_tables = None


def _get_keyword_tables():
    """Return the olevba keyword tables as a tuple, importing olevba once."""
    global _keyword_tables
    if _keyword_tables is None:
        from oletools import olevba
        _keyword_tables = (
            olevba.AUTOEXEC_KEYWORDS,
            olevba.AUTOEXEC_KEYWORDS_REGEX,
            olevba.SUSPICIOUS_KEYWORDS,
            olevba.SUSPICIOUS_KEYWORDS_REGEX,
        )
    return _keyword_tables


# === PROCEDURE EXTRACTION ===================================================

def extract_procedures(parsed):
    """
    Extract Sub/Function/Property procedures from the parsed module.

    Each procedure keeps the LineRecord statements of its body, so later
    scenario filtering knows the branch path of every statement. A missing
    End statement simply closes the procedure at EOF instead of failing.

    :param ParsedModule parsed: result of :func:`parse_module`
    :return: list of Procedure objects
    """
    procedures = []
    current = None
    for record in parsed.lines:
        if not record.is_code:
            continue
        header = RE_PROC.match(record.text)
        if header is not None and current is None:
            current = Procedure(
                name=header.group('name'),
                kind=re.sub(r'\s+', ' ', header.group('kind')).title(),
                start_line=record.line_no)
            current.body.append(record)
            continue
        if current is not None:
            current.body.append(record)
            if RE_END_PROC.match(record.text):
                current.end_line = record.line_no
                procedures.append(current)
                current = None
    if current is not None:
        current.end_line = parsed.lines[-1].line_no if parsed.lines \
            else current.start_line
        procedures.append(current)
    return procedures


# === LINE-LEVEL KEYWORD DETECTION ===========================================

def detect_line_keywords(record):
    """
    Detect auto-exec and suspicious keywords on a single statement line.

    The olevba keyword tables are reused unchanged, preserving the classic
    keyword interface. Each hit keeps the original line and its branch path.

    :param LineRecord record: one statement line
    :return: list of KeywordHit
    """
    autoexec_kw, autoexec_re, suspicious_kw, suspicious_re = \
        _get_keyword_tables()
    hits = []
    text = record.text
    for description, keywords in autoexec_kw.items():
        for keyword in keywords:
            match = re.search(r'(?i)\b' + re.escape(keyword) + r'\b', text)
            if match:
                hits.append(KeywordHit(match.group(), description,
                                       record.line_no, text, 'AutoExec',
                                       record))
    for description, keywords in autoexec_re.items():
        for keyword in keywords:
            match = re.search(r'(?i)\b' + keyword + r'\b', text)
            if match:
                hits.append(KeywordHit(match.group(), description,
                                       record.line_no, text, 'AutoExec',
                                       record))
    for description, keywords in suspicious_kw.items():
        for keyword in keywords:
            match = re.search(r'(?i)\b' + re.escape(keyword) + r'\b', text)
            if match:
                hits.append(KeywordHit(match.group(), description,
                                       record.line_no, text, 'Suspicious',
                                       record))
    for description, keywords in suspicious_re.items():
        for keyword in keywords:
            match = re.search(r'(?i)\b' + keyword + r'\b', text)
            if match:
                hits.append(KeywordHit(match.group(), description,
                                       record.line_no, text, 'Suspicious',
                                       record))
    return hits
    deduped = []
    seen = set()
    for hit in hits:
        key = (hit.category, hit.keyword.lower(), hit.line_no)
        if key not in seen:
            seen.add(key)
            deduped.append(hit)
    hits = deduped


def detect_calls(procedure, known_keys):
    """
    Statically collect calls made by one procedure to other known procedures.

    Only identifiers resolving to a real procedure in the module are kept, so
    VBA statements filtered through CALL_STOPWORDS never create false edges.

    :param Procedure procedure: caller procedure
    :param set known_keys: upper-cased names of all module procedures
    :return: list of CallEdge
    """
    edges = []
    for record in procedure.body:
        if not record.is_code:
            continue
        for match in RE_CALL.finditer(record.text):
            callee = match.group(1)
            key = callee.upper()
            if key in CALL_STOPWORDS or key not in known_keys:
                continue
            edges.append(CallEdge(procedure, key, callee, record.line_no,
                                  record))
    return edges


# === SCENARIO ENUMERATION AND CHAIN BUILDING ================================

#: maximum number of unknown boolean atoms enumerated before capping.
#: 12 atoms -> at most 4096 assignments, which stays well within the 10s
#: budget while covering every realistic VBA7/Win64 conditional module.
MAX_UNKNOWN_ATOMS = 12


def _evaluate_branch_choice(frame, context):
    """
    Decide which branch of a frame is selected.

    Conditions are evaluated in order with Kleene three-valued logic. The
    first TRUE condition wins; an UNKNOWN condition means the choice is not
    fixed and every branch it can reach is returned as an option.

    :return: tuple ``(options, uncertain)`` where ``options`` is a list of
        branch indices that may be selected and ``uncertain`` is True when a
        broken/unparsable condition prevents a definite answer.
    """
    options = []
    uncertain = False
    for index, branch in enumerate(frame.branches):
        if branch.kind == 'else':
            options.append(index)
            continue
        if branch.condition_ast is None:
            # broken condition: this branch stays a possibility and the
            # frame is flagged uncertain, but analysis does not stop.
            uncertain = True
            options.append(index)
            continue
        tri, _atom = evaluate_condition(branch.condition_ast, context)
        if tri == TRUE:
            return [index], uncertain
        if tri == UNKNOWN:
            options.append(index)
    if not options:
        # All conditions were definitely FALSE and there was no Else:
        # no statement of the frame is reachable.
        return [], uncertain
    return options, uncertain


def _base_context(parsed, env):
    """Build an EvalContext from the env and the module #Const declarations."""
    consts = {}
    for name, (ast, _text, _line_no) in parsed.consts.items():
        if ast is not None:
            consts[name] = ast
    return EvalContext(env=env, consts=consts)



def _iter_assignments(atom_texts):
    """Enumerate every True/False assignment of unknown boolean atoms."""
    count = len(atom_texts)
    if count == 0:
        yield {}
        return
    for mask in range(1 << count):
        assignment = {}
        for index, text in enumerate(atom_texts):
            assignment[text] = TRUE if (mask >> index) & 1 else FALSE
        yield assignment

def _frame_choice(frame, context):
    """Evaluate one frame against a concrete assignment context."""
    options, uncertain = _evaluate_branch_choice(frame, context)
    if not options:
        return None, uncertain
    return options[0], uncertain

def _line_active(record, guard_values):
    """Return True when the record path matches the guard selections."""
    for frame, branch in record.path:
        selected = guard_values.get(id(frame))
        if selected is None:
            return False
        if selected != frame.branches.index(branch):
            return False
    return True


def _build_context(parsed, env, symbol_values):
    # Build an EvalContext with unknown symbols pinned to concrete values.
    merged_env = dict(env)
    merged_env.update(symbol_values)
    return _base_context(parsed, merged_env)

def _collect_unknown_symbols(parsed, env):
    """Return the sorted names of constants referenced but never supplied."""
    context = _base_context(parsed, env)
    for frame in parsed.frames:
        for branch in frame.branches:
            if branch.condition_ast is not None:
                evaluate_condition(branch.condition_ast, context)
    names = set()
    for atom_text in context.atoms.keys():
        for name in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", atom_text):
            upper = name.upper()
            if (upper not in env and upper not in parsed.consts
                    and upper not in EXPRESSION_WORDS):
                names.add(upper)
    return sorted(names)

def build_scenarios(parsed, env):
    """Enumerate every internally consistent conditional scenario.

    Unknown constants are assigned all True/False combinations (capped by
    MAX_UNKNOWN_ATOMS). Assignments that select the same frame branches are
    merged into one scenario carrying their combined constraints."
    """
    unknown_symbols = _collect_unknown_symbols(parsed, env)
    capped = len(unknown_symbols) > MAX_UNKNOWN_ATOMS
    if capped:
        unknown_symbols = unknown_symbols[:MAX_UNKNOWN_ATOMS]
    seen = {}
    order = []
    for assignment in _iter_assignments(unknown_symbols):
        context = _build_context(parsed, env, assignment)
        guard_values = {}
        uncertain = False
        for frame in parsed.frames:
            choice, frame_uncertain = _frame_choice(frame, context)
            guard_values[id(frame)] = choice
            uncertain = uncertain or frame_uncertain or frame.broken
        signature = tuple(guard_values[id(f)] for f in parsed.frames)
        if signature not in seen:
            scenario = Scenario(
                scenario_id=len(order) + 1,
                assignment=dict(assignment),
                guard_values=guard_values,
                is_unknown_environment=bool(unknown_symbols) or capped)
            scenario.uncertain = uncertain
            seen[signature] = scenario
            order.append(scenario)
        else:
            pass
    for index, scenario in enumerate(order, start=1):
        scenario.scenario_id = index
        scenario.enumeration_capped = capped
        scenario.unknown_symbols = list(unknown_symbols)
        scenario.provided_constants = sorted(env.keys())
    return order, capped, unknown_symbols

def _procedure_of(line_no, procedures):
    """Return the procedure containing a physical line number, or None.
    """
    for procedure in procedures:
        if procedure.start_line <= line_no <= (procedure.end_line or line_no):
            return procedure
    return None


def build_chains(module_name, scenario, procedures, call_edges, hits):
    """Build condition-compatible entry-to-suspicious chains for a scenario.

    Only active lines participate, so a chain can never join two mutually
    exclusive branches. The call graph is walked from every active auto-exec
    entry; suspicious calls reached through it are reported with the hops.
    """
    active_numbers = set()
    for record in scenario.active_lines:
        active_numbers.add(record.line_no)
    active_hits = [hit for hit in hits if hit.line_no in active_numbers]
    entries = [hit for hit in active_hits if hit.category == "AutoExec"]
    suspicious = [hit for hit in active_hits
                  if hit.category == "Suspicious"]
    edges_by_caller = {}
    for edge in call_edges:
        if edge.line_no in active_numbers:
            edges_by_caller.setdefault(edge.caller.key, []).append(edge)
    chains = []
    seen_chains = set()
    for entry in entries:
        entry_proc = _procedure_of(entry.line_no, procedures)
        entry_proc_key = entry_proc.key if entry_proc else None
        reachable = {entry_proc_key: [(entry_proc.name if entry_proc
                                        else "<module>", entry.line_no)]}
        queue = [entry_proc] if entry_proc else []
        while queue:
            current = queue.pop(0)
            path_so_far = reachable[current.key]
            for edge in edges_by_caller.get(current.key, []):
                target = _procedure_of_edge(edge, procedures)
                if target is None or target.key in reachable:
                    continue
                reachable[target.key] = path_so_far + [
                    (edge.callee_name, edge.line_no)]
                queue.append(target)
        for hit in suspicious:
            hit_proc = _procedure_of(hit.line_no, procedures)
            hit_key = hit_proc.key if hit_proc else None
            if hit_key in reachable:
                target_name = hit_proc.name if hit_proc else "<module>"
                path = reachable[hit_key] + [(target_name, hit.line_no)]
                chain_key = (entry.line_no, hit.line_no,
                             tuple((name, ln) for name, ln in path))
                if chain_key not in seen_chains:
                    seen_chains.add(chain_key)
                    chains.append(Chain(module_name, entry, hit, path,
                                     scenario))
    scenario.chains = chains
    scenario.keyword_hits = active_hits
    return chains

def _procedure_of_edge(edge, procedures):
    """Resolve a call edge to its target Procedure when it exists.
    """
    for procedure in procedures:
        if procedure.key == edge.callee_key:
            return procedure
    return None

def analyze_module(vba_code, module_name='<module>', env=None):
    # Static conditional-compilation analysis of one VBA module.
    normalized_env = _normalize_env(env)
    parsed = parse_module(vba_code, module_name)
    procedures = extract_procedures(parsed)
    known_keys = set(proc.key for proc in procedures)
    call_edges = []
    for procedure in procedures:
        call_edges.extend(detect_calls(procedure, known_keys))
    hits = []
    for record in parsed.code_lines():
        hits.extend(detect_line_keywords(record))
    scenarios, capped, unknown_symbols = build_scenarios(
        parsed, normalized_env)
    for scenario in scenarios:
        scenario.active_lines = [
            record for record in parsed.code_lines()
            if _line_active(record, scenario.guard_values)]
        build_chains(module_name, scenario, procedures, call_edges, hits)
    report = ModuleReport(module_name)
    report.parsed = parsed
    report.procedures = procedures
    report.damage = list(parsed.damage)
    report.scenarios = scenarios
    report.provided_constants = sorted(normalized_env.keys())
    report.unknown_constants = unknown_symbols
    report.enumeration_capped = capped
    report.call_edges = call_edges
    report.keyword_hits = hits
    return report

class ConditionalReport(object):
    # Aggregated conditional-compilation report across all VBA modules.
    def __init__(self):
        self.module_reports = []
        self.env = {}

    @property
    def scenarios(self):
        result = []
        for report in self.module_reports:
            result.extend(report.scenarios)
        return result

    @property
    def chains(self):
        result = []
        for report in self.module_reports:
            for scenario in report.scenarios:
                result.extend(scenario.chains)
        return result

    def to_dict(self):
        return {
            'env': self.env,
            'modules': [report_to_dict(report)
                        for report in self.module_reports],
        }


def analyze_vba_modules(modules, env=None):
    # Analyze an iterable of (module_name, vba_code) tuples.
    normalized_env = _normalize_env(env)
    report = ConditionalReport()
    report.env = normalized_env
    for module_name, vba_code in modules:
        report.module_reports.append(
            analyze_module(vba_code, module_name, normalized_env))
    return report

def _fmt_value(value):
    if value == TRUE:
        return 'True'
    if value == FALSE:
        return 'False'
    return str(value)


def scenario_conditions(scenario):
    # Human-readable constraints for one scenario.
    if not scenario.assignment:
        return ['(all conditional constants fully specified)']
    return ['%s = %s' % (name, _fmt_value(value))
            for name, value in sorted(scenario.assignment.items())]


def report_to_dict(report):
    # JSON-serializable view of one ModuleReport.
    return {
        'module': report.module_name,
        'provided_constants': report.provided_constants,
        'unknown_constants': report.unknown_constants,
        'enumeration_capped': report.enumeration_capped,
        'damage': [{'line': line, 'message': message}
                   for line, message in report.damage],
        'procedures': [{'name': proc.name, 'kind': proc.kind,
                       'start_line': proc.start_line,
                       'end_line': proc.end_line}
                      for proc in report.procedures],
        'scenarios': [scenario_to_dict(scenario, report.module_name)
                      for scenario in report.scenarios],
    }

def scenario_to_dict(scenario, module_name):
    # JSON-serializable view of one scenario and its chains.
    return {
        'scenario_id': scenario.scenario_id,
        'conditions': scenario_conditions(scenario),
        'uncertain': getattr(scenario, 'uncertain', False),
        'active_lines': [record.line_no for record in scenario.active_lines],
        'keywords': [{'category': hit.category, 'keyword': hit.keyword,
                     'description': hit.description, 'line': hit.line_no}
                    for hit in scenario.keyword_hits],
        'chains': [chain.to_dict() for chain in scenario.chains],
    }

def render_text_report(report):
    # Render a ConditionalReport as a human-readable string.
    lines = []
    if report.env:
        lines.append('Provided environment: ' + ', '.join(
            '%s=%s' % (name, _fmt_value(value))
            for name, value in sorted(report.env.items())))
    else:
        lines.append('Provided environment: (none - unknown constants are enumerated)')
    for module in report.module_reports:
        lines.append('')
        lines.append('Module: %s' % module.module_name)
        if module.damage:
            lines.append('  Uncertain regions (syntax damage):')
            for line_no, message in module.damage:
                lines.append('    line %d: %s' % (line_no, message))
        if module.enumeration_capped:
            lines.append('  WARNING: too many unknown constants; enumeration was capped')
        for scenario in module.scenarios:
            lines.append('  Scenario %d:' % scenario.scenario_id)
            for condition in scenario_conditions(scenario):
                lines.append('    condition: %s' % condition)
            if getattr(scenario, 'uncertain', False):
                lines.append('    status: UNCERTAIN (a condition could not be parsed)')
            if not scenario.chains:
                lines.append('    reachable attack chains: none')
            else:
                lines.append('    reachable attack chains:')
                for chain in scenario.chains:
                    hops = ' -> '.join('%s@L%d' % (name, ln)
                                       for name, ln in chain.path)
                    lines.append('      - %s' % hops)
                    lines.append('          entry: %s (line %d)' % (
                        chain.entry.keyword, chain.entry.line_no))
                    lines.append('          call:  %s (line %d) - %s' % (
                        chain.target.keyword, chain.target.line_no,
                        chain.target.description))
    return '\n'.join(lines)
