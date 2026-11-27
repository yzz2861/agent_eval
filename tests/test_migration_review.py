"""Offline migration review for an interpreter upgrade.

The historical acceptance check only verified that restricted source still
compiles.  A security review additionally has to prove that the guards used
to enforce the restriction policy are still selected on the *normal* code
paths.  The checks in this module therefore run fully offline against fixed
synthetic rules and assert four independent aspects:

* the compile warnings emitted by the transformer,
* the guard functions selected for attribute, item, iteration and write use,
* the source locations attached to the generated guard calls,
* the ordinary output that an approved program is allowed to produce.

Diagnostics for syntax that is still unsupported are recorded as well, while
constructs that were previously supported keep their approved capability
boundary.

The guards are deliberately tiny, in-memory *counting* fakes: every
invocation is recorded so the behaviour can be reviewed without any network
or file system access.
"""

import ast
import collections

from RestrictedPython import compile_restricted_exec
from RestrictedPython.Guards import safe_builtins
from RestrictedPython.PrintCollector import PrintCollector
from RestrictedPython.transformer import RestrictingNodeTransformer


FILENAME = '<migration-review>'
GUARD_NAMES = ('_getattr_', '_getitem_', '_getiter_', '_write_')


class CountingGuards:
    """Record every guard invocation while keeping the program runnable."""

    def __init__(self):
        self.events = collections.Counter()

    def getattr(self, object, name):
        self.events['_getattr_'] += 1
        return getattr(object, name)

    def getitem(self, object, index):
        self.events['_getitem_'] += 1
        return object[index]

    def getiter(self, object):
        self.events['_getiter_'] += 1
        return iter(object)

    def write(self, object):
        self.events['_write_'] += 1
        return object


class CountingPrintCollector(PrintCollector):
    """PrintCollector which additionally counts its instantiations."""

    instances = 0

    def __init__(self, _getattr_=None):
        CountingPrintCollector.instances += 1
        super().__init__(_getattr_)


class Record:
    """Plain data holder used by the offline synthetic samples."""

    def __init__(self, label, amount):
        self.label = label
        self.amount = amount


RECORDS = [Record('alpha', 1), Record('beta', 2), Record('gamma', 3)]


def compile_review(source):
    """Compile fixed synthetic source with a stable review filename."""
    return compile_restricted_exec(source, filename=FILENAME)


def transformed_tree(source):
    """Return the transformed AST together with the policy bookkeeping."""
    errors = []
    warnings = []
    used_names = {}
    tree = ast.parse(source, FILENAME)
    RestrictingNodeTransformer(errors, warnings, used_names).visit(tree)
    return tree, errors, warnings, used_names


def guard_calls(tree):
    """Yield ``(guard_name, node)`` pairs found in a transformed tree."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(
                node.func, ast.Name) and node.func.id in GUARD_NAMES:
            yield node.func.id, node


def guard_call_positions(tree):
    """Map guard names to the sorted source positions of their call nodes."""
    positions = {name: [] for name in GUARD_NAMES}
    for name, node in guard_calls(tree):
        positions[name].append((
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ))
    for name in GUARD_NAMES:
        positions[name].sort()
    return positions


def make_globals(guards, **extra):
    """Build the minimal offline globals needed to execute a sample."""
    glb = {
        '__builtins__': safe_builtins.copy(),
        '_getattr_': guards.getattr,
        '_getitem_': guards.getitem,
        '_getiter_': guards.getiter,
        '_write_': guards.write,
        '_print_': CountingPrintCollector,
    }
    glb.update(extra)
    return glb


# Common samples: a branch with sequential reads and a function return.
BRANCH_SAMPLE = '''
def pick(records, take_first):
    if take_first:
        chosen = records[0]
    else:
        chosen = records[1]
    return chosen.label

answer = pick(records, take_first=True)
second = pick(records, take_first=False)
'''

SEQUENCE_SAMPLE = '''
def accumulate(records):
    total = 0
    for entry in records:
        total = total + entry.amount
    return total

result = accumulate(records)
'''

WRITE_SAMPLE = '''
def update(records):
    records[0].amount = records[0].amount + 1
    return records

updated = update(records)
'''

PRINT_SAMPLE = '''
def render(records):
    print("records:")
    for entry in records:
        print(entry.label)
    return printed

rendered = render(records)
'''

PRINT_WITHOUT_READ_SAMPLE = '''
def render(records):
    print("records:")
    return records
'''

PRINT_WITHOUT_PRINT_SAMPLE = '''
def render(records):
    captured = printed
    return captured
'''


def test_migration_review__branch_sample_compiles_without_diagnostics():
    result = compile_review(BRANCH_SAMPLE)
    assert result.errors == ()
    assert result.warnings == []
    assert result.code is not None
    assert result.code.co_filename == FILENAME
    assert result.used_names == {
        'records': True, 'take_first': True, 'chosen': True,
        'pick': True}


def test_migration_review__branch_sample_selects_expected_guards():
    tree, errors, warnings, _ = transformed_tree(BRANCH_SAMPLE)
    assert errors == []
    assert warnings == []
    counts = collections.Counter(name for name, _ in guard_calls(tree))
    # Each branch reads one item; the shared return statement reads the
    # `label` attribute through `_getattr_`.
    assert counts == {'_getitem_': 2, '_getattr_': 1}
    positions = guard_call_positions(tree)
    assert positions['_getitem_'] == [
        (4, 17, 4, 27),
        (6, 17, 6, 27),
    ]
    assert positions['_getattr_'] == [(7, 11, 7, 23)]
    assert positions['_getiter_'] == []
    assert positions['_write_'] == []


def test_migration_review__branch_sample_allows_ordinary_output():
    guards = CountingGuards()
    result = compile_review(BRANCH_SAMPLE)
    glb = make_globals(guards, records=RECORDS)
    exec(result.code, glb)
    assert glb['answer'] == 'alpha'
    assert glb['second'] == 'beta'
    # `pick` is invoked twice: one guarded item read and one guarded
    # attribute read on every invocation.
    assert guards.events == collections.Counter({
        '_getitem_': 2, '_getattr_': 2})


def test_migration_review__sequence_sample_compiles_without_diagnostics():
    result = compile_review(SEQUENCE_SAMPLE)
    assert result.errors == ()
    assert result.warnings == []
    assert result.code is not None
    assert result.code.co_filename == FILENAME
    assert result.used_names == {
        'records': True, 'total': True, 'entry': True,
        'accumulate': True}


def test_migration_review__sequence_sample_selects_iteration_guards():
    tree, errors, warnings, _ = transformed_tree(SEQUENCE_SAMPLE)
    assert errors == []
    assert warnings == []
    counts = collections.Counter(name for name, _ in guard_calls(tree))
    assert counts == {'_getiter_': 1, '_getattr_': 1}
    positions = guard_call_positions(tree)
    # The `_getiter_` call replaces the `for` iterable in place.
    assert positions['_getiter_'] == [(4, 17, 4, 24)]
    assert positions['_getattr_'] == [(5, 24, 5, 36)]
    assert positions['_getitem_'] == []
    assert positions['_write_'] == []


def test_migration_review__sequence_sample_allows_ordinary_output():
    guards = CountingGuards()
    result = compile_review(SEQUENCE_SAMPLE)
    glb = make_globals(guards, records=RECORDS)
    exec(result.code, glb)
    assert glb['result'] == 6
    # One guarded iteration plus one attribute read per record.
    assert guards.events == collections.Counter({
        '_getiter_': 1, '_getattr_': 3})


def test_migration_review__write_sample_selects_write_and_read_guards():
    tree, errors, warnings, _ = transformed_tree(WRITE_SAMPLE)
    assert errors == []
    assert warnings == []
    counts = collections.Counter(name for name, _ in guard_calls(tree))
    assert counts == {'_write_': 1, '_getitem_': 2, '_getattr_': 1}
    positions = guard_call_positions(tree)
    # `_write_` wraps the assignment target; reads still use their own
    # item and attribute guards.
    assert positions['_write_'] == [(3, 4, 3, 14)]
    assert positions['_getitem_'] == [
        (3, 4, 3, 14),
        (3, 24, 3, 34),
    ]
    assert positions['_getattr_'] == [(3, 24, 3, 41)]
    assert positions['_getiter_'] == []


def test_migration_review__write_sample_allows_mutation_through_guards():
    guards = CountingGuards()
    result = compile_review(WRITE_SAMPLE)
    glb = make_globals(guards, records=RECORDS)
    exec(result.code, glb)
    assert glb['updated'][0].amount == 2
    assert RECORDS[0].amount == 2
    assert guards.events == collections.Counter({
        '_write_': 1, '_getitem_': 2, '_getattr_': 1})


def test_migration_review__print_sample_is_silent_when_balanced():
    result = compile_review(PRINT_SAMPLE)
    assert result.errors == ()
    assert result.warnings == []
    assert result.code is not None


def test_migration_review__print_sample_collects_allowed_output():
    CountingPrintCollector.instances = 0
    guards = CountingGuards()
    result = compile_review(PRINT_SAMPLE)
    glb = make_globals(guards, records=RECORDS)
    exec(result.code, glb)
    assert glb['rendered'] == 'records:\nalpha\nbeta\ngamma\n'
    assert CountingPrintCollector.instances == 1
    # Iteration is guarded and every label read goes through `_getattr_`.
    assert guards.events == collections.Counter({
        '_getiter_': 1, '_getattr_': 3})


def test_migration_review__print_without_read_warns_with_line():
    result = compile_review(PRINT_WITHOUT_READ_SAMPLE)
    assert result.errors == ()
    assert result.warnings == [
        'Line 2: Prints, but never reads \'printed\' variable.']
    assert result.code is not None


def test_migration_review__read_without_print_warns_with_line():
    result = compile_review(PRINT_WITHOUT_PRINT_SAMPLE)
    assert result.errors == ()
    assert result.warnings == [
        'Line 2: Doesn\'t print, but reads \'printed\' variable.']
    assert result.code is not None


UNSUPPORTED_SYNTAX = [
    ('async def f():\n    pass\n',
     'Line 1: AsyncFunctionDef statements are not allowed.'),
    ('x = eval("1 + 1")\n',
     'Line 1: Eval calls are not allowed.'),
    ('x = _secret\n',
     'Line 1: "_secret" is an invalid variable name because it starts '
     'with "_"'),
    ('x = obj._secret\n',
     'Line 1: "_secret" is an invalid attribute name because it starts '
     'with "_".'),
    ('from os import *\n',
     'Line 1: "*" imports are not allowed.'),
    ('breakpoint()\n',
     'Line 1: "breakpoint" is a reserved name.'),
]


def test_migration_review__unsupported_syntax_keeps_recorded_diagnostics():
    for source, diagnostic in UNSUPPORTED_SYNTAX:
        result = compile_review(source)
        assert result.code is None, source
        assert result.errors == (diagnostic,), source
        assert result.warnings == [], source


def test_migration_review__unsupported_syntax_invokes_no_guards():
    for source, _ in UNSUPPORTED_SYNTAX:
        result = compile_review(source)
        guards = CountingGuards()
        try:
            exec(result.code, make_globals(guards))
        except TypeError:
            pass
        else:
            raise AssertionError(
                f'unsupported sample unexpectedly executed: {source!r}')
        assert guards.events == collections.Counter()


def test_migration_review__plain_syntax_error_is_recorded_without_guards():
    result = compile_review('def broken(:\n')
    assert result.code is None
    assert result.warnings == []
    assert result.errors == (
        "Line 1: SyntaxError: invalid syntax at statement:"
        " 'def broken(:'",)
