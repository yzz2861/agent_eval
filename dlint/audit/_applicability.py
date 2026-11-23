#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import re

from .. import linters
from . import _syntax


# A linter is only "in effect" on a target environment when its
# implementation can actually fire there. Most linters are plain AST
# visitors that work on every supported interpreter; a handful carry
# explicit sys.version_info gates, or rely on node types that only exist
# on one interpreter family.

# Rules whose visit logic short-circuits on Python 3.
PYTHON_2_ONLY_CODES = frozenset([
    # visit_Exec only exists for Python 2 exec statements; exec() calls are
    # still covered on every version through the BadBuiltinUse base class.
    linters.BadExecUseLinter._code,
    # visit_Call short-circuits unless sys.version_info < (3, 0).
    linters.BadInputUseLinter._code,
])

# visit_FunctionDef returns early on sys.version_info >= (3, 3), so this
# rule can only produce findings on Python 2 interpreters.
PYTHON_2_ONLY_CODES = PYTHON_2_ONLY_CODES | frozenset([
    linters.YieldReturnStatementLinter._code,
])

_EXEC_STATEMENT_RE = re.compile(r'^[ \t]*exec[ \t]+(?!=)')


def _code_to_linter():
    return dict(
        (linter_class._code, linter_class)
        for linter_class in linters.ALL
    )


_CODE_TO_LINTER = _code_to_linter()


def linter_for_code(code, linter_classes=None):
    """Return the linter class registered for ``code``, or ``None``."""
    if linter_classes is None:
        return _CODE_TO_LINTER.get(code)

    for linter_class in linter_classes:
        if linter_class._code == code:
            return linter_class

    return None


def linter_applies(linter_class, version, source=None):
    """Return whether ``linter_class`` can fire on the target environment.

    The check mirrors the runtime gates baked into the linter implementations
    rather than the interpreter currently executing the audit. That is what
    lets one report generated on one Python version be scoped against a
    maintenance group running a different one.

    When ``source`` is supplied, statement-only rules stay applicable if the
    fragment actually contains the Python 2 statement they cover; an
    ``exec()`` call fragment remains eligible for DUO105 on Python 3 through
    the shared builtin visitor.
    """
    code = linter_class._code
    target = _syntax.normalize_version(version)

    if code not in PYTHON_2_ONLY_CODES:
        return True

    if target[0] >= 3 and source is None:
        return False

    if target[0] < 3:
        return True

    # Python 3 target with source in hand: decide per fragment. DUO105
    # stays applicable for exec() calls via the BadBuiltinUse base class;
    # only a bare Python 2 exec statement is uncovered on Python 3.
    if code == linters.BadExecUseLinter._code:
        has_exec_statement = any(
            _EXEC_STATEMENT_RE.match(line)
            for line in source.splitlines()
        )
        if has_exec_statement:
            return False
        return True

    if code == linters.BadInputUseLinter._code:
        return False

    if code == linters.YieldReturnStatementLinter._code:
        return False

    return False


