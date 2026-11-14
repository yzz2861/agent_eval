import contextlib

from RestrictedPython import compile_restricted_exec
from RestrictedPython.Guards import guarded_unpack_sequence
from RestrictedPython.transformer import CAPABILITY_WITH_STATEMENTS
from RestrictedPython.transformer import RestrictingNodeTransformer


class WithStatementsPolicy(RestrictingNodeTransformer):
    """Policy which explicitly enables the ``with`` capability."""

    policy_name = 'WithStatementsPolicy'
    enabled_capabilities = frozenset({CAPABILITY_WITH_STATEMENTS})


def _restricted_exec_with_policy(source, glb=None):
    result = compile_restricted_exec(source, policy=WithStatementsPolicy)
    assert result.errors == (), result.errors
    assert result.code is not None
    if glb is None:
        glb = {}
    exec(result.code, glb)
    return glb


WITH_STMT_DEFAULT_DENIED = """
def call(ctx):
    with ctx() as value:
        return value
"""


def test_with_stmt_default_denied():
    """The default policy rejects ``with`` without an enabled capability."""
    result = compile_restricted_exec(WITH_STMT_DEFAULT_DENIED)
    assert result.code is None
    assert result.errors == (
        'Line 3, col 4: policy "RestrictingNodeTransformer" rejected node '
        'With: the capability for this node type is not enabled by the '
        'caller (required capability: "with_statements")',
    )


def test_with_stmt_allowed_with_capability():
    """Enabling the capability admits the ``with`` node."""
    result = compile_restricted_exec(
        WITH_STMT_DEFAULT_DENIED, policy=WithStatementsPolicy)
    assert result.errors == ()
    assert result.warnings == []
    assert result.code is not None


WITH_STMT_WITH_UNPACK_SEQUENCE = """
def call(ctx):
    with ctx() as (a, (c, b)):
        return a, c, b
"""


def test_with_stmt_unpack_sequence(mocker):
    @contextlib.contextmanager
    def ctx():
        yield (1, (2, 3))

    _getiter_ = mocker.stub()
    _getiter_.side_effect = lambda ob: ob

    glb = {
        '_getiter_': _getiter_,
        '_unpack_sequence_': guarded_unpack_sequence
    }

    _restricted_exec_with_policy(WITH_STMT_WITH_UNPACK_SEQUENCE, glb)

    ret = glb['call'](ctx)

    assert ret == (1, 2, 3)
    _getiter_.assert_has_calls([
        mocker.call((1, (2, 3))),
        mocker.call((2, 3))])


WITH_STMT_MULTI_CTX_WITH_UNPACK_SEQUENCE = """
def call(ctx1, ctx2):
    with ctx1() as (a, (b, c)), ctx2() as ((x, z), (s, h)):
        return a, b, c, x, z, s, h
"""


def test_with_stmt_multi_ctx_unpack_sequence(mocker):
    result = compile_restricted_exec(WITH_STMT_MULTI_CTX_WITH_UNPACK_SEQUENCE)
    # The default policy rejects ``with``; the capability has to be opted in.
    assert result.errors
    result = compile_restricted_exec(
        WITH_STMT_MULTI_CTX_WITH_UNPACK_SEQUENCE,
        policy=WithStatementsPolicy)
    assert result.errors == ()

    @contextlib.contextmanager
    def ctx1():
        yield (1, (2, 3))

    @contextlib.contextmanager
    def ctx2():
        yield (4, 5), (6, 7)

    _getiter_ = mocker.stub()
    _getiter_.side_effect = lambda ob: ob

    glb = {
        '_getiter_': _getiter_,
        '_unpack_sequence_': guarded_unpack_sequence
    }

    exec(result.code, glb)

    ret = glb['call'](ctx1, ctx2)

    assert ret == (1, 2, 3, 4, 5, 6, 7)
    _getiter_.assert_has_calls([
        mocker.call((1, (2, 3))),
        mocker.call((2, 3)),
        mocker.call(((4, 5), (6, 7))),
        mocker.call((4, 5)),
        mocker.call((6, 7))
    ])


WITH_STMT_ATTRIBUTE_ACCESS = """
def simple(ctx):
    with ctx as x:
        x.z = x.y + 1

def assign_attr(ctx, x):
    with ctx as x.y:
        x.z = 1

def load_attr(w):
    with w.ctx as x:
        x.z = 1

"""


def test_with_stmt_attribute_access(mocker):
    _getattr_ = mocker.stub()
    _getattr_.side_effect = getattr

    _write_ = mocker.stub()
    _write_.side_effect = lambda ob: ob

    glb = {'_getattr_': _getattr_, '_write_': _write_}
    _restricted_exec_with_policy(WITH_STMT_ATTRIBUTE_ACCESS, glb)

    # Test simple
    ctx = mocker.MagicMock(y=1)
    ctx.__enter__.return_value = ctx

    glb['simple'](ctx)

    assert ctx.z == 2
    _write_.assert_called_once_with(ctx)
    _getattr_.assert_called_once_with(ctx, 'y')

    _write_.reset_mock()
    _getattr_.reset_mock()

    # Test assign_attr
    x = mocker.Mock()
    glb['assign_attr'](ctx, x)

    assert x.z == 1
    assert x.y == ctx
    _write_.assert_has_calls([
        mocker.call(x),
        mocker.call(x)
    ])

    _write_.reset_mock()

    # Test load_attr
    ctx = mocker.MagicMock()
    ctx.__enter__.return_value = ctx

    w = mocker.Mock(ctx=ctx)

    glb['load_attr'](w)

    assert w.ctx.z == 1
    _getattr_.assert_called_once_with(w, 'ctx')
    _write_.assert_called_once_with(w.ctx)


WITH_STMT_SUBSCRIPT = """
def single_key(ctx, x):
    with ctx as x['key']:
        pass


def slice_key(ctx, x):
    with ctx as x[2:3]:
        pass
"""


def test_with_stmt_subscript(mocker):
    _write_ = mocker.stub()
    _write_.side_effect = lambda ob: ob

    glb = {'_write_': _write_}
    _restricted_exec_with_policy(WITH_STMT_SUBSCRIPT, glb)

    # Test single_key
    ctx = mocker.MagicMock()
    ctx.__enter__.return_value = ctx
    x = {}

    glb['single_key'](ctx, x)

    assert x['key'] == ctx
    _write_.assert_called_once_with(x)
    _write_.reset_mock()

    # Test slice_key
    ctx = mocker.MagicMock()
    ctx.__enter__.return_value = (1, 2)

    x = [0, 0, 0, 0, 0, 0]
    glb['slice_key'](ctx, x)

    assert x == [0, 0, 1, 2, 0, 0, 0]
    _write_.assert_called_once_with(x)
