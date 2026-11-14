import pytest

from RestrictedPython.AttributePolicy import CALL
from RestrictedPython.AttributePolicy import ERR_CALL_DENIED
from RestrictedPython.AttributePolicy import ERR_ITERATE_DENIED
from RestrictedPython.AttributePolicy import ERR_READ_DENIED
from RestrictedPython.AttributePolicy import ERR_WRITE_DENIED
from RestrictedPython.AttributePolicy import READ
from RestrictedPython.AttributePolicy import WRITE
from RestrictedPython.AttributePolicy import AttributePolicy
from RestrictedPython.AttributePolicy import AttributePolicyError
from tests.helper import restricted_eval
from tests.helper import restricted_exec


class Business:
    """A legitimate business object a tenant may want to expose."""

    # Declares (towards the stock write guard) that it handles its own
    # write security; the tenant policy is checked before this is reached.
    _guarded_writes = True

    def __init__(self):
        self.token = 'tok-1'
        self.items = [1, 2, 3]

    def get_token(self):
        return self.token


def default_policy(**kw):
    return AttributePolicy('tenant-a', **kw)


def policy_globals(policy, **extra):
    glb = policy.guards()
    glb.update(extra)
    return glb


def test_AttributePolicy__poc_dunder_chain_blocked():
    """It stops `().__class__.__base__.__subclasses__()` at the first step.

    Literal dunder attributes are already rejected at compile time; the
    runtime policy is the backstop for dynamically computed names, e.g.
    when the executor exposes a `getattr` builtin to the script.
    """
    policy = default_policy()
    glb = policy_globals(policy, getattr=policy.guard_getattr())
    with pytest.raises(AttributePolicyError) as excinfo:
        restricted_eval(
            "getattr(getattr(getattr((), '__cl' + 'ass__'),"
            " '__base__'), '__subclasses__')()",
            glb)
    err = excinfo.value
    assert err.code == ERR_READ_DENIED
    assert err.operation == READ
    assert err.attribute == '__class__'
    assert err.policy == 'tenant-a'

    # The same holds when the guard is used directly as `_getattr_`.
    get = policy.guard_getattr()
    with pytest.raises(AttributePolicyError) as excinfo:
        get((), '__class__')
    assert excinfo.value.code == ERR_READ_DENIED


def test_AttributePolicy__nested_chain_stops_at_first_violation():
    """A nested attribute chain fails at the first denied attribute."""
    policy = default_policy(extra_deny=['secret'])

    class Inner:
        secret = 'top'
        value = 1

    class Outer:
        pass

    outer = Outer()
    outer.inner = Inner()

    # The allowed prefix of the chain evaluates, the first denied
    # attribute terminates the chain -- deeper names are never touched.
    with pytest.raises(AttributePolicyError) as excinfo:
        restricted_eval(
            'outer.inner.secret.deeper.even_deeper',
            policy_globals(policy, outer=outer))
    assert excinfo.value.code == ERR_READ_DENIED
    assert excinfo.value.attribute == 'secret'

    # A dunder denial deeper in the chain also stops at the first dunder.
    glb = policy_globals(policy, outer=outer,
                         getattr=policy.guard_getattr())
    with pytest.raises(AttributePolicyError) as excinfo:
        restricted_eval("getattr(outer.inner, '__class__')", glb)
    assert excinfo.value.attribute == '__class__'

    # A fully allowed chain still evaluates.
    assert restricted_eval(
        'outer.inner.value',
        policy_globals(policy, outer=outer)) == 1


def test_AttributePolicy__whitelist_allows_business_object():
    """Explicit whitelist entries regain read/call/write/iterate access."""
    policy = default_policy(allow={
        READ: {Business: {'token', 'items', 'get_token'}},
        CALL: {Business: {'get_token'}},
        WRITE: {Business: {'token'}},
    })
    biz = Business()
    glb = policy_globals(policy, biz=biz)
    assert restricted_eval('biz.token', glb) == 'tok-1'
    assert restricted_eval('biz.get_token()', glb) == 'tok-1'
    assert restricted_eval('biz.items', glb) == [1, 2, 3]

    restricted_exec("biz.token = 'tok-2'", glb)
    assert biz.token == 'tok-2'

    # Dunder stays denied even for whitelisted business objects.
    with pytest.raises(AttributePolicyError) as excinfo:
        policy.guard_getattr()(biz, '__class__')
    assert excinfo.value.code == ERR_READ_DENIED

    with pytest.raises(AttributePolicyError) as excinfo:
        policy.guard_write()(biz).__class__ = Business
    assert excinfo.value.code == ERR_WRITE_DENIED


def test_AttributePolicy__write_guard_delegates_to_full_write_guard():
    """Policy writes reuse the stock write guard semantics."""
    policy = default_policy()
    glb = policy_globals(policy)
    restricted_exec("d = {}\nd['k'] = 42", glb)
    assert glb['d'] == {'k': 42}

    # Attribute-less objects keep the stock error behaviour.
    with pytest.raises(TypeError):
        restricted_exec('ob = object()\nob.x = 1',
                        policy_globals(policy, object=object))


def test_AttributePolicy__call_guard_blocks_dangerous_callable():
    """The _apply_ guard denies calling denied names even if obtained."""
    policy = default_policy()
    apply_ = policy.guard_apply()
    with pytest.raises(AttributePolicyError) as excinfo:
        apply_(object.__subclasses__)
    assert excinfo.value.code == ERR_CALL_DENIED
    assert excinfo.value.operation == CALL

    def normal(a, b=2):
        return a + b

    assert apply_(normal, 1, b=3) == 4


def test_AttributePolicy__iterate_guard_blocks_generator_internals():
    """Frames, code objects and generators must not be iterated."""
    policy = default_policy()
    getiter = policy.guard_getiter()

    def gen():
        yield 1

    with pytest.raises(AttributePolicyError) as excinfo:
        getiter(gen())
    assert excinfo.value.code == ERR_ITERATE_DENIED

    assert list(getiter([1, 2, 3])) == [1, 2, 3]

    # Also through a restricted for loop.
    glb = policy_globals(policy, gen=gen)
    with pytest.raises(AttributePolicyError) as excinfo:
        restricted_exec('for x in gen():\n    pass', glb)
    assert excinfo.value.code == ERR_ITERATE_DENIED


def test_AttributePolicy__error_message_leaks_nothing():
    """No object repr or memory address is echoed back to the script."""

    class Sneaky:
        def __repr__(self):
            return 'SECRET-MARKER 0xdeadbeef'

    policy = default_policy()
    with pytest.raises(AttributePolicyError) as excinfo:
        policy.guard_getattr()(Sneaky(), '__class__')
    message = str(excinfo.value)
    assert 'SECRET-MARKER' not in message
    assert '0x' not in message
    assert 'Sneaky' in message
    assert ERR_READ_DENIED in message


def test_AttributePolicy__unknown_operation_rejected():
    policy = default_policy()
    with pytest.raises(ValueError):
        policy.check('delete', object(), 'x')
    with pytest.raises(ValueError):
        AttributePolicy('t', allow={'delete': {}})
