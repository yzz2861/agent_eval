"""Tests for jsonpickle's safe decoding mode.

Safe mode only restores builtin scalars/containers and explicitly
whitelisted classes, refuses py/reduce and py/function unless the
function is registered, never calls __init__ or __setstate__, and fails
with categorized errors that do not echo the complete payload.
"""

import pytest

import jsonpickle
from jsonpickle import errors

CALLS = {"init": 0, "setstate": 0, "function": 0}


@pytest.fixture(autouse=True)
def reset_calls():
    for key in CALLS:
        CALLS[key] = 0
    yield


class Widget:
    """A whitelisted project class whose constructor must never run"""

    def __init__(self, name=""):
        CALLS["init"] += 1
        self.name = name


class StatefulWidget(Widget):
    def __setstate__(self, state):
        CALLS["setstate"] += 1
        self.__dict__.update(state)


def pure_double(value):
    """A registered pure function"""
    CALLS["function"] += 1
    return value * 2


class NestedBox:
    """A class handled by a custom handler that nests jsonpickle content"""

    def __init__(self, inner=None):
        self.inner = inner


class NestedBoxHandler(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj, data):
        data["inner"] = self.context.flatten(obj.inner, reset=False)
        return data

    def restore(self, data):
        inner = self.context.restore(data["inner"], reset=False)
        return NestedBox(inner)


@pytest.fixture
def nested_handler():
    jsonpickle.handlers.register(NestedBox, NestedBoxHandler)
    yield
    jsonpickle.handlers.unregister(NestedBox)


def widget_payload():
    payload = jsonpickle.encode(Widget("hello"))
    # constructing the payload object legitimately ran __init__ once;
    # reset the counters so tests only observe decode-time behavior
    for key in CALLS:
        CALLS[key] = 0
    return payload


def test_safe_mode_allows_builtin_scalars_and_containers():
    payload = '{"a": [1, 2.5, {"b": null, "c": true}], "d": "text"}'
    assert jsonpickle.decode(payload, safe_mode=True) == {
        "a": [1, 2.5, {"b": None, "c": True}],
        "d": "text",
    }


def test_safe_mode_allows_whitelisted_class_without_calling_init():
    decoded = jsonpickle.decode(
        widget_payload(), safe_mode=True, allowed_classes=[Widget]
    )
    assert isinstance(decoded, Widget)
    assert decoded.name == "hello"
    assert CALLS["init"] == 0


def test_safe_mode_whitelist_accepts_dotted_strings_and_dicts():
    name = jsonpickle.util.importable_name(Widget)
    decoded = jsonpickle.decode(
        widget_payload(), safe_mode=True, allowed_classes=[name]
    )
    assert isinstance(decoded, Widget)
    decoded = jsonpickle.decode(
        widget_payload(), safe_mode=True, allowed_classes={name: Widget}
    )
    assert isinstance(decoded, Widget)
    assert CALLS["init"] == 0


def test_safe_mode_never_calls_setstate():
    name = jsonpickle.util.importable_name(StatefulWidget)
    payload = '{"py/object": "%s", "py/state": {"name": "stateful"}}' % name
    decoded = jsonpickle.decode(
        payload, safe_mode=True, allowed_classes=[StatefulWidget]
    )
    assert isinstance(decoded, StatefulWidget)
    assert decoded.name == "stateful"
    assert CALLS["init"] == 0
    assert CALLS["setstate"] == 0


def test_safe_mode_rejects_unknown_class():
    with pytest.raises(errors.DisallowedClassError):
        jsonpickle.decode(widget_payload(), safe_mode=True)
    assert CALLS["init"] == 0


def test_safe_mode_rejects_private_modules():
    payload = '{"py/object": "jsonpickle._secret.Thing", "x": 1}'
    with pytest.raises(errors.PrivateModuleError):
        jsonpickle.decode(payload, safe_mode=True, allowed_classes=[Widget])


def test_safe_mode_rejects_dangerous_builtin_functions():
    payload = '{"py/reduce": [{"py/function": "os.system"}, ["echo pwned"]]}'
    with pytest.raises(errors.DangerousFunctionError):
        jsonpickle.decode(payload, safe_mode=True, allowed_functions=[pure_double])
    payload = '{"py/function": "builtins.eval"}'
    with pytest.raises(errors.DangerousFunctionError):
        jsonpickle.decode(payload, safe_mode=True)


def test_safe_mode_reduce_and_function_are_off_by_default():
    name = jsonpickle.util.importable_name(pure_double)
    payload = '{"py/reduce": [{"py/function": "%s"}, [21]]}' % name
    with pytest.raises(errors.DisallowedFunctionError):
        jsonpickle.decode(payload, safe_mode=True)
    with pytest.raises(errors.DisallowedFunctionError):
        jsonpickle.decode('{"py/function": "%s"}' % name, safe_mode=True)
    assert CALLS["function"] == 0


def test_safe_mode_reduce_allows_registered_pure_functions():
    name = jsonpickle.util.importable_name(pure_double)
    payload = '{"py/reduce": [{"py/function": "%s"}, [21]]}' % name
    assert (
        jsonpickle.decode(payload, safe_mode=True, allowed_functions=[pure_double])
        == 42
    )
    assert CALLS["function"] == 1


def test_safe_mode_function_allows_registered_pure_functions():
    name = jsonpickle.util.importable_name(pure_double)
    decoded = jsonpickle.decode(
        '{"py/function": "%s"}' % name,
        safe_mode=True,
        allowed_functions=[name],
    )
    assert decoded is pure_double
    assert CALLS["function"] == 0


def test_safe_mode_reduce_never_calls_whitelisted_class_constructor():
    """A whitelisted class used as a reduce callable must not run __init__"""
    name = jsonpickle.util.importable_name(Widget)
    payload = '{"py/reduce": [{"py/object": "%s"}, ["x"]]}' % name
    with pytest.raises(errors.DisallowedFunctionError):
        jsonpickle.decode(payload, safe_mode=True, allowed_classes=[Widget])
    assert CALLS["init"] == 0


def test_safe_mode_rejects_recursive_references():
    with pytest.raises(errors.RecursiveReferenceError):
        jsonpickle.decode('{"py/id": 0}', safe_mode=True)
    with pytest.raises(errors.RecursiveReferenceError):
        jsonpickle.decode('[{"py/id": 0}]', safe_mode=True)
    with pytest.raises(errors.RecursiveReferenceError):
        jsonpickle.decode('{"a": {"py/id": 0}}', safe_mode=True)
    with pytest.raises(errors.RecursiveReferenceError):
        jsonpickle.decode('{"py/id": -1}', safe_mode=True)


def test_safe_mode_rejects_overly_deep_objects():
    payload = "[" * 500 + "1" + "]" * 500
    with pytest.raises(errors.MaxDepthExceededError):
        jsonpickle.decode(payload, safe_mode=True)
    # a custom limit is honored as well
    with pytest.raises(errors.MaxDepthExceededError):
        jsonpickle.decode("[[[[1]]]]", safe_mode=True, max_depth=3)
    # and reasonably nested payloads still decode
    assert jsonpickle.decode("[[[1]]]", safe_mode=True, max_depth=3) == [[[1]]]


def test_safe_mode_errors_do_not_echo_complete_payload():
    marker = "S3CR3T-" + "x" * 500
    payload = (
        '{"py/object": "unknown.evil.Class", "secret": "%s", "nested": ["%s"]}'
        % (marker, marker)
    )
    with pytest.raises(errors.DisallowedClassError) as excinfo:
        jsonpickle.decode(payload, safe_mode=True)
    message = str(excinfo.value)
    assert marker not in message
    assert len(message) < len(payload)


def test_safe_mode_whitelist_is_scoped_per_call():
    """A whitelist from one decode call must not pollute later messages"""
    payload = widget_payload()
    assert isinstance(
        jsonpickle.decode(payload, safe_mode=True, allowed_classes=[Widget]),
        Widget,
    )
    with pytest.raises(errors.DisallowedClassError):
        jsonpickle.decode(payload, safe_mode=True)
    # a fresh unpickler must not see the earlier whitelist either
    with pytest.raises(errors.DisallowedClassError):
        jsonpickle.decode(payload, safe_mode=True, allowed_classes=[])


def test_safe_mode_rejects_wildcards():
    with pytest.raises(ValueError):
        jsonpickle.decode("1", safe_mode=True, allowed_classes=["jsonpickle.*"])
    with pytest.raises(ValueError):
        jsonpickle.decode("1", safe_mode=True, allowed_functions=["os.*"])


def test_safe_mode_restores_shared_references():
    shared = [1, 2]
    payload = jsonpickle.encode({"x": shared, "y": shared})
    decoded = jsonpickle.decode(payload, safe_mode=True)
    assert decoded["x"] is decoded["y"]


def test_safe_mode_supports_custom_handlers(nested_handler):
    """Custom handlers, including nested ones, keep working in safe mode"""
    box = NestedBox(Widget("inner"))
    payload = jsonpickle.encode(box)
    # reset counters so only decode-time behavior is observed
    for key in CALLS:
        CALLS[key] = 0
    decoded = jsonpickle.decode(payload, safe_mode=True, allowed_classes=[Widget])
    assert isinstance(decoded, NestedBox)
    assert isinstance(decoded.inner, Widget)
    assert decoded.inner.name == "inner"
    assert CALLS["init"] == 0


def test_safe_mode_options_passthrough():
    """keys and other decode options keep working in safe mode"""
    payload = jsonpickle.encode({(1, 2): "tuple-key"}, keys=True)
    decoded = jsonpickle.decode(payload, safe_mode=True, keys=True)
    assert decoded == {(1, 2): "tuple-key"}
    decoded = jsonpickle.decode(payload, safe_mode=True, keys=False)
    assert list(decoded.values()) == ["tuple-key"]


def test_safe_mode_unpickler_context():
    """Safe mode can be driven through a pre-built Unpickler context"""
    unpickler = jsonpickle.unpickler.Unpickler(safe_mode=True, allowed_classes=[Widget])
    decoded = jsonpickle.decode(widget_payload(), context=unpickler)
    assert isinstance(decoded, Widget)
    assert CALLS["init"] == 0


def test_safe_mode_decode_options_override_context():
    unpickler = jsonpickle.unpickler.Unpickler()
    decoded = jsonpickle.decode(
        widget_payload(),
        context=unpickler,
        safe_mode=True,
        allowed_classes=[Widget],
    )
    assert isinstance(decoded, Widget)
    assert CALLS["init"] == 0
