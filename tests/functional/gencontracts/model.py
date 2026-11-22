"""Program IR and the independent security-contract oracle.

The oracle derives expected findings purely from this contract state,
never from Bandit's rule code.  The contract vocabulary mirrors the
documented behaviour of the two team rules under test:

* B602 (subprocess with shell=True): fires when a subprocess spawn
  passes ``shell=True``; severity is LOW when the command is a plain
  string literal at the call site, HIGH when any computation (a name
  or a data-moving call) stands between the literal and the sink.
* B106 (hardcoded password keyword): fires when a call passes a
  password-like keyword a plain string literal at the call site.
"""

from dataclasses import dataclass

RULE_SUBPROCESS_SHELL = "B602"
RULE_HARDCODED_PASSWORD_KWARG = "B106"

LOW = "LOW"
HIGH = "HIGH"

PASSWORD_LIKE_KEYWORDS = ("password", "passwd", "pwd", "secret", "token")
NEUTRAL_KEYWORDS = ("username", "host", "port", "timeout", "region")

MOVE_STR = "str"
MOVE_COPY = "copy.copy"
MOVE_DICT_GET = "dict.get"
MOVE_TUPLE = "tuple"
MOVE_OPS = (MOVE_STR, MOVE_COPY, MOVE_DICT_GET, MOVE_TUPLE)


# ---------------------------------------------------------------------------
# expressions
@dataclass(frozen=True)
class Lit:
    text: str


@dataclass(frozen=True)
class Var:
    name: str


@dataclass(frozen=True)
class Move:
    op: str
    arg: object  # expr


# ---------------------------------------------------------------------------
# statements (each carries a stable contract id)
@dataclass(frozen=True)
class Bind:
    cid: str
    name: str
    expr: object  # expr


@dataclass(frozen=True)
class ShellSink:
    cid: str
    cmd: object  # expr
    shell: bool


@dataclass(frozen=True)
class ConnectSink:
    cid: str
    keyword: str
    value: object  # expr


@dataclass(frozen=True)
class Scope:
    name: str  # "" is the module scope
    body: tuple  # tuple of statements


@dataclass(frozen=True)
class Program:
    case_id: str
    scopes: tuple  # tuple of Scope, module scope first


# ---------------------------------------------------------------------------
# IR queries
def expr_vars(expr):
    if isinstance(expr, Var):
        return {expr.name}
    if isinstance(expr, Move):
        return expr_vars(expr.arg)
    return set()


def expr_uses_move(expr, op):
    if isinstance(expr, Move):
        return expr.op == op or expr_uses_move(expr.arg, op)
    return False


def stmt_defs(stmt):
    if isinstance(stmt, Bind):
        return {stmt.name}
    return set()


def stmt_uses(stmt):
    if isinstance(stmt, Bind):
        return expr_vars(stmt.expr)
    if isinstance(stmt, ShellSink):
        return expr_vars(stmt.cmd)
    if isinstance(stmt, ConnectSink):
        return expr_vars(stmt.value)
    return set()


def iter_statements(program):
    for scope in program.scopes:
        for stmt in scope.body:
            yield scope, stmt


def statement_count(program):
    return sum(len(scope.body) for scope in program.scopes)


# ---------------------------------------------------------------------------
# the independent contract oracle
@dataclass(frozen=True)
class Expectation:
    cid: str
    rule_id: str
    severity: str


def contract_expectations(program):
    """Expected findings, computed from the contract state alone."""
    expectations = {}
    for _, stmt in iter_statements(program):
        if isinstance(stmt, ShellSink):
            if not stmt.shell:
                continue
            severity = LOW if isinstance(stmt.cmd, Lit) else HIGH
            expectations[stmt.cid] = Expectation(
                stmt.cid, RULE_SUBPROCESS_SHELL, severity
            )
        elif isinstance(stmt, ConnectSink):
            if (
                stmt.keyword in PASSWORD_LIKE_KEYWORDS
                and isinstance(stmt.value, Lit)
            ):
                expectations[stmt.cid] = Expectation(
                    stmt.cid, RULE_HARDCODED_PASSWORD_KWARG, LOW
                )
    return expectations
