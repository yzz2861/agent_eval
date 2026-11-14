# Copyright (C) 2013 Jason R. Coombs <jaraco@jaraco.com>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.

import datetime
import threading

import pytest

import jsonpickle
import jsonpickle.handlers


class CustomObject:
    "A class to be serialized by a custom handler"

    def __init__(self, name=None, creator=None):
        self.name = name
        self.creator = creator

    def __eq__(self, other):
        return self.name == other.name


class CustomA(CustomObject):
    pass


class CustomB(CustomA):
    pass


class ContextObject(CustomObject):
    pass


class NullHandler(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj, data):
        data["name"] = obj.name
        return data

    def restore(self, obj):
        return CustomObject(obj["name"], creator=type(self))


class DecoratedBase(CustomObject):
    pass


class DecoratedChild(DecoratedBase):
    pass


@jsonpickle.handlers.register(DecoratedBase, base=True)
class DecoratedHandler(NullHandler):
    pass


class SithHandler(jsonpickle.handlers.BaseHandler):
    """(evil) serialization handler that rewrites the entire object"""

    def flatten(self, obj, data):
        data["name"] = obj.name
        data["py/object"] = "sith.lord"
        return data


class ContextAwareHandler(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj, data, handler_context):
        data["name"] = f"{obj.name}-{handler_context['suffix']}"
        return data

    def restore(self, data, handler_context):
        return ContextObject(f"{data['name']}-{handler_context['suffix']}")


class HandlerTestCase:
    def setup_method(self):
        jsonpickle.handlers.register(CustomObject, NullHandler)

    def teardown_method(self):
        jsonpickle.handlers.unregister(CustomObject)

    def roundtrip(self, ob):
        encoded = jsonpickle.encode(ob)
        decoded = jsonpickle.decode(encoded)
        assert decoded == ob
        return decoded

    def test_custom_handler(self):
        """Ensure that the custom handler is indeed used"""
        expect = CustomObject("jarjar")
        encoded = jsonpickle.encode(expect)
        actual = jsonpickle.decode(encoded)
        assert expect.name == actual.name
        assert expect.creator is None
        assert actual.creator is NullHandler

    def test_references(self):
        """
        Ensure objects handled by a custom handler are properly dereferenced.
        """
        ob = CustomObject()
        # create a dictionary which contains several references to ob
        subject = {"a": ob, "b": ob, "c": ob}
        # ensure the subject can be roundtripped
        new_subject = self.roundtrip(subject)
        assert new_subject["a"] == new_subject["b"]
        assert new_subject["b"] == new_subject["c"]
        assert new_subject["a"] is new_subject["b"]
        assert new_subject["b"] is new_subject["c"]

    def test_invalid_class(self):
        with pytest.raises(TypeError):
            jsonpickle.handlers.register("foo", NullHandler)

    def test_base_handler(self):
        a = CustomA("a")
        assert a.creator is None
        assert jsonpickle.decode(jsonpickle.encode(a)).creator is None

        b = CustomB("b")
        assert b.creator is None
        assert jsonpickle.decode(jsonpickle.encode(b)).creator is None

        OtherHandler = type("OtherHandler", (NullHandler,), {})
        jsonpickle.handlers.register(CustomA, OtherHandler, base=True)
        assert self.roundtrip(a).creator is OtherHandler
        assert self.roundtrip(b).creator is OtherHandler

        SpecializedHandler = type("SpecializedHandler", (NullHandler,), {})
        jsonpickle.handlers.register(CustomB, SpecializedHandler)
        assert self.roundtrip(a).creator is OtherHandler
        assert self.roundtrip(b).creator is SpecializedHandler

    def test_decorated_register(self):
        db = DecoratedBase("db")
        dc = DecoratedChild("dc")
        assert self.roundtrip(db).creator is DecoratedHandler
        assert self.roundtrip(dc).creator is DecoratedHandler

    def test_custom_handler_can_rewrite_everything(self):
        """Test the low-level pickling structures"""
        jsonpickle.handlers.unregister(CustomObject)
        jsonpickle.handlers.register(CustomObject, SithHandler)
        obj = CustomObject("jarjar")  # secret sith lord jarjar
        pickler = jsonpickle.pickler.Pickler()
        data = pickler.flatten(obj)
        assert isinstance(data, dict)
        assert len(data) == 2
        assert data["name"] == "jarjar"
        assert data["py/object"] == "sith.lord"

    def test_custom_handler_with_context(self):
        jsonpickle.handlers.register(ContextObject, ContextAwareHandler)
        obj = ContextObject("hello")
        encoded_a = jsonpickle.encode(obj, handler_context={"suffix": "a"})
        encoded_b = jsonpickle.encode(obj, handler_context={"suffix": "b"})

        decoded_a = jsonpickle.decode(encoded_a, handler_context={"suffix": "x"})
        decoded_b = jsonpickle.decode(encoded_b, handler_context={"suffix": "y"})

        assert decoded_a.name == "hello-a-x"
        assert decoded_b.name == "hello-b-y"

    def test_custom_handler_without_context(self):
        obj = CustomObject("alpha")
        encoded = jsonpickle.encode(obj, handler_context={"suffix": "ignored"})
        decoded = jsonpickle.decode(encoded, handler_context={"suffix": "ignored"})

        assert decoded.name == "alpha"


def make_handler_class(name, namespace=None):
    """Create a fresh handler class (fresh identity) for deterministic tests"""
    return type(name, (jsonpickle.handlers.BaseHandler,), dict(namespace or {}))


def make_type(name):
    return type(name, (), {})


class DeterministicRegistryTestCase:
    """Review tests for the deterministic handler registry model"""

    def setup_method(self):
        self.registry = jsonpickle.handlers.Registry()

    def test_same_priority_conflict_raises(self):
        widget = make_type("ConflictWidget")
        handler_a = make_handler_class("ConflictHandlerA")
        handler_b = make_handler_class("ConflictHandlerB")
        self.registry.register(widget, handler_a)
        with pytest.raises(jsonpickle.handlers.HandlerConflictError):
            self.registry.register(widget, handler_b)

    def test_conflict_error_names_handlers_not_object_contents(self):
        widget = make_type("SecretWidget")
        handler_a = make_handler_class("NamedHandlerA")
        handler_b = make_handler_class("NamedHandlerB")
        self.registry.register(widget, handler_a)
        with pytest.raises(jsonpickle.handlers.HandlerConflictError) as excinfo:
            self.registry.register(widget, handler_b)
        message = str(excinfo.value)
        assert "NamedHandlerA" in message
        assert "NamedHandlerB" in message
        assert "SecretWidget" in message
        # never leak object contents, only type/handler names
        assert "object at 0x" not in message

    def test_failed_conflict_registration_leaves_registry_untouched(self):
        widget = make_type("AtomicWidget")
        handler_a = make_handler_class("AtomicHandlerA")
        handler_b = make_handler_class("AtomicHandlerB")
        self.registry.register(widget, handler_a, priority=3)
        before = self.registry.explain(widget)
        with pytest.raises(jsonpickle.handlers.HandlerConflictError):
            self.registry.register(widget, handler_b, priority=3)
        after = self.registry.explain(widget)
        assert self.registry.get(widget) is handler_a
        assert before.handler == after.handler
        assert before.priority == after.priority == 3

    def test_invalid_registration_is_atomic(self):
        widget = make_type("ValidatingWidget")
        handler_a = make_handler_class("ValidatingHandlerA")
        self.registry.register(widget, handler_a)
        with pytest.raises(ValueError):
            self.registry.register(widget, handler_a, direction="sideways")
        with pytest.raises(TypeError):
            self.registry.register(widget, handler_a, priority="high")
        with pytest.raises(TypeError):
            self.registry.register(widget, "not-callable")
        with pytest.raises(TypeError):
            self.registry.register("not-a-type", handler_a)
        assert self.registry.get(widget) is handler_a
        assert self.registry.explain(widget).match == "exact"

    def test_higher_priority_wins_regardless_of_registration_order(self):
        # simulates the same plugins loading in different orders on two machines
        widget = make_type("OrderedWidget")
        local_handler = make_handler_class("LocalTimezoneHandler")
        utc_handler = make_handler_class("UtcTimezoneHandler")

        first = jsonpickle.handlers.Registry()
        first.register(widget, local_handler, priority=1)
        first.register(widget, utc_handler, priority=2)

        second = jsonpickle.handlers.Registry()
        second.register(widget, utc_handler, priority=2)
        second.register(widget, local_handler, priority=1)

        assert first.get(widget) is utc_handler
        assert second.get(widget) is utc_handler
        assert first.explain(widget).handler == second.explain(widget).handler

    def test_same_priority_conflict_regardless_of_registration_order(self):
        widget = make_type("OrderlessWidget")
        handler_a = make_handler_class("OrderlessHandlerA")
        handler_b = make_handler_class("OrderlessHandlerB")

        first = jsonpickle.handlers.Registry()
        first.register(widget, handler_a)
        with pytest.raises(jsonpickle.handlers.HandlerConflictError):
            first.register(widget, handler_b)

        second = jsonpickle.handlers.Registry()
        second.register(widget, handler_b)
        with pytest.raises(jsonpickle.handlers.HandlerConflictError):
            second.register(widget, handler_a)

    def test_direction_specific_handlers_coexist(self):
        widget = make_type("DirectionalWidget")
        encode_handler = make_handler_class("EncodeOnlyHandler")
        decode_handler = make_handler_class("DecodeOnlyHandler")
        # same priority, but disjoint directions: not a conflict
        self.registry.register(widget, encode_handler, direction="encode")
        self.registry.register(widget, decode_handler, direction="decode")
        assert self.registry.get(widget, direction="encode") is encode_handler
        assert self.registry.get(widget, direction="decode") is decode_handler
        selection = self.registry.explain(widget, direction="encode")
        assert selection.handler.endswith("EncodeOnlyHandler")
        selection = self.registry.explain(widget, direction="decode")
        assert selection.handler.endswith("DecodeOnlyHandler")

    def test_exact_and_base_registrations_share_one_conflict_pool(self):
        widget = make_type("MixedPoolWidget")
        exact_handler = make_handler_class("ExactPoolHandler")
        base_handler = make_handler_class("BasePoolHandler")
        self.registry.register(widget, exact_handler)
        # a base=True registration for the same class competes in the same
        # selection pool, so the conflict is reported eagerly at registration
        with pytest.raises(jsonpickle.handlers.HandlerConflictError):
            self.registry.register(widget, base_handler, base=True)
        # different priorities resolve the conflict deterministically
        self.registry.register(widget, base_handler, base=True, priority=1)
        assert self.registry.get(widget) is base_handler

    def test_direction_specific_end_to_end(self):
        class DirectionalObject:
            pass

        class EncodeMarker(jsonpickle.handlers.BaseHandler):
            def flatten(self, obj, data):
                data["marker"] = "encoded"
                return data

        class DecodeMarker(jsonpickle.handlers.BaseHandler):
            def restore(self, data):
                obj = DirectionalObject()
                obj.marker = data["marker"] + "+decoded"
                return obj

        jsonpickle.handlers.register(
            DirectionalObject, EncodeMarker, direction="encode"
        )
        jsonpickle.handlers.register(
            DirectionalObject, DecodeMarker, direction="decode"
        )
        try:
            encoded = jsonpickle.encode(DirectionalObject())
            assert "encoded" in encoded
            decoded = jsonpickle.decode(encoded)
            assert decoded.marker == "encoded+decoded"
        finally:
            jsonpickle.handlers.unregister(DirectionalObject)

    def test_reregister_same_handler_is_idempotent(self):
        widget = make_type("IdempotentWidget")
        handler_cls = make_handler_class("IdempotentHandler")
        self.registry.register(widget, handler_cls)
        # re-registering the same handler (even a fresh instance) is an update
        self.registry.register(widget, handler_cls)
        self.registry.register(widget, handler_cls(None))
        assert self.registry.get(widget) is handler_cls or isinstance(
            self.registry.get(widget), handler_cls
        )

    def test_base_handler_conflict_detected_at_selection(self):
        base = make_type("ConflictBase")
        other_base = make_type("OtherConflictBase")
        child = type("ConflictChild", (base, other_base), {})
        handler_a = make_handler_class("BaseConflictHandlerA")
        handler_b = make_handler_class("BaseConflictHandlerB")
        self.registry.register(base, handler_a, base=True)
        self.registry.register(other_base, handler_b, base=True)
        with pytest.raises(jsonpickle.handlers.HandlerConflictError):
            self.registry.get(child)
        # deterministic resolution via priority
        self.registry.unregister(other_base)
        self.registry.register(other_base, handler_b, base=True, priority=1)
        assert self.registry.get(child) is handler_b

    def test_concurrent_registration_loses_nothing(self):
        registry = jsonpickle.handlers.Registry()
        count = 16
        types = [make_type(f"ConcurrentWidget{i}") for i in range(count)]
        handlers = [make_handler_class(f"ConcurrentHandler{i}") for i in range(count)]
        barrier = threading.Barrier(count)

        def worker(index):
            barrier.wait()
            registry.register(types[index], handlers[index], priority=index)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for i in range(count):
            assert registry.get(types[i]) is handlers[i]
            assert registry.explain(types[i]).priority == i

    def test_concurrent_conflicting_registration_is_deterministic(self):
        for attempt in range(10):
            registry = jsonpickle.handlers.Registry()
            widget = make_type(f"SharedWidget{attempt}")
            low = make_handler_class(f"LowPriorityHandler{attempt}")
            high = make_handler_class(f"HighPriorityHandler{attempt}")
            barrier = threading.Barrier(2)

            def register(handler, priority):
                barrier.wait()
                registry.register(widget, handler, priority=priority)

            threads = [
                threading.Thread(target=register, args=(low, 1)),
                threading.Thread(target=register, args=(high, 2)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            # the winner never depends on which thread registered first
            assert registry.get(widget) is high

    def test_audit_records_selections(self):
        widget = make_type("AuditedWidget")
        handler = make_handler_class("AuditedHandler")
        self.registry.register(widget, handler, priority=7, source="plugin-x")
        self.registry.clear_audit()
        assert self.registry.get(widget, direction="encode") is handler
        records = self.registry.audit()
        assert len(records) == 1
        record = records[0]
        assert record.match == "exact"
        assert record.handler.endswith("AuditedHandler")
        assert record.priority == 7
        assert record.source == "plugin-x"
        assert record.direction == "encode"
        assert "AuditedWidget" in record.key
        # explain() reports without recording
        assert self.registry.explain(widget).match == "exact"
        assert len(self.registry.audit()) == 1

    def test_audit_records_misses(self):
        widget = make_type("UnregisteredWidget")
        assert self.registry.get(widget) is None
        record = self.registry.audit()[-1]
        assert record.match == "none"
        assert record.handler is None

    def test_builtin_handlers_are_sourced_and_auditable(self):
        selection = jsonpickle.handlers.registry.explain(
            datetime.datetime, direction="encode"
        )
        assert selection.match == "exact"
        assert selection.handler.endswith("DatetimeHandler")
        assert selection.source == "builtin"

    def test_user_priority_overrides_builtin(self):
        class MyDateHandler(jsonpickle.handlers.BaseHandler):
            def flatten(self, obj, data):
                data["marker"] = "custom-date"
                return data

            def restore(self, data):
                return datetime.date(2000, 1, 1)

        jsonpickle.handlers.register(
            datetime.date, MyDateHandler, priority=10, source="user"
        )
        try:
            encoded = jsonpickle.encode(datetime.date(2024, 1, 1))
            assert "custom-date" in encoded
            selection = jsonpickle.handlers.registry.explain(
                datetime.date, direction="encode"
            )
            assert selection.handler.endswith("MyDateHandler")
            assert selection.priority == 10
        finally:
            jsonpickle.handlers.unregister(datetime.date)
            jsonpickle.handlers.register(
                datetime.date,
                jsonpickle.handlers.DatetimeHandler,
                source="builtin",
            )
        # builtin behaviour is restored
        restored = jsonpickle.decode(
            jsonpickle.encode(datetime.date(2024, 1, 1), unpicklable=False)
        )
        assert restored == "2024-01-01"
