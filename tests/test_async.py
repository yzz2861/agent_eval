"""Tests for the asynchronous load/validate API (`Schema.aload`,
`Schema.aloads`, `Schema.avalidate`).

No network is involved: the "remote" service is a local in-memory
``LocalAsyncService`` with controllable latency and failures.
"""

from __future__ import annotations

import asyncio
import json
import warnings

import pytest

from marshmallow import (
    Schema,
    ValidationError,
    fields,
    missing,
    post_load,
    pre_load,
    validate,
    validates,
    validates_schema,
)


class LocalAsyncService:
    """Stand-in for an asynchronous remote service.

    Tracks in-flight requests so tests can assert on concurrency.
    """

    def __init__(self, delay: float = 0):
        self.delay = delay
        self.in_flight = 0
        self.max_in_flight = 0
        self.calls = 0

    async def request(self, key, value):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        self.calls += 1
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if value in self.fail_values:
                raise ValidationError(f"{key} rejected remotely")
        finally:
            self.in_flight -= 1

    fail_values: set = set()


@pytest.fixture
def service():
    return LocalAsyncService(delay=0.01)


def run(coro):
    return asyncio.run(coro)


class TestAsyncFieldValidation:
    def test_async_field_validator(self, service):
        service.fail_values = {"bad"}

        async def remote(value):
            await service.request("name", value)

        class S(Schema):
            name = fields.Str(validate=remote)

        schema = S()
        assert run(schema.aload({"name": "ok"})) == {"name": "ok"}
        assert run(schema.avalidate({"name": "bad"})) == {
            "name": ["name rejected remotely"]
        }

    def test_async_validator_inside_and(self, service):
        service.fail_values = {"bad"}

        async def remote(value):
            await service.request("name", value)

        class S(Schema):
            name = fields.Str(validate=validate.And(validate.Length(min=2), remote))

        schema = S()
        assert run(schema.aload({"name": "ok"})) == {"name": "ok"}
        errors = run(schema.avalidate({"name": "bad"}))
        assert errors == {"name": ["name rejected remotely"]}
        errors = run(schema.avalidate({"name": "x"}))
        assert errors == {"name": ["Shorter than minimum length 2."]}

    def test_async_and_collects_all_errors(self, service):
        async def remote1(value):
            await asyncio.sleep(0)
            raise ValidationError("one")

        async def remote2(value):
            await asyncio.sleep(0)
            raise ValidationError("two")

        class S(Schema):
            name = fields.Str(validate=validate.And(remote1, remote2))

        errors = run(S().avalidate({"name": "x"}))
        assert errors == {"name": ["one", "two"]}

    def test_async_field_pre_and_post_load(self):
        class S(Schema):
            async def pre(value):  # noqa: N805
                await asyncio.sleep(0)
                return value.strip()

            async def post(value):  # noqa: N805
                await asyncio.sleep(0)
                return value.upper()

            name = fields.Str(pre_load=pre, post_load=post)

        assert run(S().aload({"name": "  bob  "})) == {"name": "BOB"}

    def test_sync_and_async_validators_mix_in_declaration_order(self):
        order = []

        def sync_v(value):
            order.append("sync")

        async def async_v(value):
            await asyncio.sleep(0)
            order.append("async")

        class S(Schema):
            name = fields.Str(validate=validate.And(sync_v, async_v))

        run(S().aload({"name": "x"}))
        assert order == ["sync", "async"]

    def test_validator_returning_value_ignored(self, service):
        # A validator that returns ``missing`` removes the key, even async.
        class S(Schema):
            @validates("name")
            async def check_name(self, value, **kwargs):
                await asyncio.sleep(0)
                if value == "drop":
                    return missing
                return None

            name = fields.Str()

        result = run(S().aload({"name": "drop"}))
        assert "name" not in result

    def test_custom_async_deserialize_field(self):
        class RemoteInt(fields.Int):
            async def _deserialize(self, value, attr, data, **kwargs):
                await asyncio.sleep(0)
                return super()._deserialize(value, attr, data, **kwargs)

        class S(Schema):
            n = RemoteInt()

        assert run(S().aload({"n": "5"})) == {"n": 5}

    def test_sync_load_rejects_custom_async_deserialize(self):
        class RemoteInt(fields.Int):
            async def _deserialize(self, value, attr, data, **kwargs):
                return int(value)

        class S(Schema):
            n = RemoteInt()

        with pytest.raises(RuntimeError, match="aload"):
            S().load({"n": "5"})


class TestAsyncSchemaHooks:
    def test_async_pre_and_post_load(self):
        class S(Schema):
            name = fields.Str()

            @pre_load
            async def pre(self, data, **kwargs):
                await asyncio.sleep(0)
                return {**data, "name": data["name"].strip()}

            @post_load
            async def post(self, data, **kwargs):
                await asyncio.sleep(0)
                return {"obj": data}

        assert run(S().aload({"name": "  bob  "})) == {"obj": {"name": "bob"}}

    def test_sync_hooks_mix_with_async_hooks(self):
        class S(Schema):
            class Meta:
                unknown = "include"

            name = fields.Str()

            @pre_load
            def pre_sync(self, data, **kwargs):
                data["seen_sync_pre"] = True
                return data

            @pre_load
            async def pre_async(self, data, **kwargs):
                await asyncio.sleep(0)
                data["seen_async_pre"] = True
                return data

            @post_load
            async def post_async(self, data, **kwargs):
                await asyncio.sleep(0)
                data["seen_async_post"] = True
                return data

            @post_load
            def post_sync(self, data, **kwargs):
                data["seen_sync_post"] = True
                return data

        result = run(S().aload({"name": "bob"}))
        assert result == {
            "name": "bob",
            "seen_sync_pre": True,
            "seen_async_pre": True,
            "seen_async_post": True,
            "seen_sync_post": True,
        }

    def test_async_validates_and_validates_schema(self):
        class S(Schema):
            name = fields.Str()
            age = fields.Int()

            @validates("name")
            async def check_name(self, value, **kwargs):
                await asyncio.sleep(0)
                if value == "bad":
                    raise ValidationError("bad name")

            @validates_schema
            async def cross(self, data, **kwargs):
                await asyncio.sleep(0)
                if data["name"] == "x" and data["age"] < 18:
                    raise ValidationError("too young for x", "age")

        schema = S()
        assert run(schema.aload({"name": "ok", "age": 20})) == {
            "name": "ok",
            "age": 20,
        }
        assert run(schema.avalidate({"name": "bad", "age": 20})) == {
            "name": ["bad name"]
        }
        assert run(schema.avalidate({"name": "x", "age": 10})) == {
            "age": ["too young for x"]
        }

    def test_sync_validates_works_on_async_path(self):
        class S(Schema):
            name = fields.Str()

            @validates("name")
            def check_name(self, value, **kwargs):
                if value == "bad":
                    raise ValidationError("bad name")

        assert run(S().avalidate({"name": "bad"})) == {"name": ["bad name"]}

    def test_async_pre_load_error_aborts_load(self):
        class S(Schema):
            name = fields.Str()

            @pre_load
            async def pre(self, data, **kwargs):
                await asyncio.sleep(0)
                raise ValidationError("pre failed")

            @post_load
            async def post(self, data, **kwargs):  # pragma: no cover
                raise AssertionError("post_load must not run")

        with pytest.raises(ValidationError) as exc:
            run(S().aload({"name": "x"}))
        assert exc.value.messages == {"_schema": ["pre failed"]}

    def test_async_many_hooks_collection_and_per_item(self):
        events = []

        class S(Schema):
            name = fields.Str()

            @pre_load(pass_collection=True)
            async def envelope(self, data, **kwargs):
                await asyncio.sleep(0)
                events.append("collection-pre")
                return data["items"]

            @pre_load
            async def per_item(self, item, **kwargs):
                await asyncio.sleep(0)
                events.append("item-pre")
                return item

            @post_load(pass_collection=True)
            async def wrap(self, data, **kwargs):
                events.append("collection-post")
                return {"items": data}

        result = run(S().aload({"items": [{"name": "a"}, {"name": "b"}]}, many=True))
        assert result == {"items": [{"name": "a"}, {"name": "b"}]}
        assert events[0] == "collection-pre"
        assert events.count("item-pre") == 2
        assert events[-1] == "collection-post"

    def test_post_load_not_run_when_field_errors(self):
        class S(Schema):
            name = fields.Str(required=True)

            @post_load
            async def post(self, data, **kwargs):  # pragma: no cover
                raise AssertionError("post_load must not run")

        with pytest.raises(ValidationError):
            run(S().aload({}))


class AddressSchema(Schema):
    city = fields.Str()
    zip_code = fields.Str()

    @validates("city")
    async def check_city(self, value, **kwargs):
        await asyncio.sleep(0)
        if value == "nowhere":
            raise ValidationError("unknown city")


class PersonSchema(Schema):
    name = fields.Str()
    address = fields.Nested(AddressSchema)
    tags = fields.List(fields.Str())


class TestAsyncNestingAndMany:
    def test_nested_async_load(self):
        result = run(
            PersonSchema().aload(
                {
                    "name": "bob",
                    "address": {"city": "here", "zip_code": "1"},
                    "tags": ["a", "b"],
                }
            )
        )
        assert result == {
            "name": "bob",
            "address": {"city": "here", "zip_code": "1"},
            "tags": ["a", "b"],
        }

    def test_nested_async_error_locations_match_sync(self):
        errors = run(
            PersonSchema().avalidate(
                {
                    "name": 1,
                    "address": {"city": "nowhere", "zip_code": 1},
                    "tags": "ok",
                }
            )
        )
        assert set(errors) == {"name", "address", "tags"}
        assert errors["address"] == {
            "city": ["unknown city"],
            "zip_code": ["Not a valid string."],
        }
        assert errors["tags"] == ["Not a valid list."]

    def test_nested_async_many(self):
        people = [
            {
                "name": "a",
                "address": {"city": "here", "zip_code": "1"},
                "tags": [],
            },
            {
                "name": "b",
                "address": {"city": "nowhere", "zip_code": "2"},
                "tags": [],
            },
        ]
        errors = run(PersonSchema().avalidate(people, many=True))
        assert errors == {1: {"address": {"city": ["unknown city"]}}}

    def test_nested_field_with_many(self):
        class S(Schema):
            addresses = fields.Nested(AddressSchema, many=True)

        errors = run(
            S().avalidate(
                {
                    "addresses": [
                        {"city": "here", "zip_code": "1"},
                        {"city": "nowhere", "zip_code": "2"},
                    ]
                }
            )
        )
        assert errors == {"addresses": {1: {"city": ["unknown city"]}}}

    def test_many_returns_ordered_results(self):
        class S(Schema):
            name = fields.Str()

            @validates("name")
            async def slow(self, value, **kwargs):
                await asyncio.sleep(0.01 if value == "a" else 0)

        result = run(S().aload([{"name": "a"}, {"name": "b"}], many=True))
        assert result == [{"name": "a"}, {"name": "b"}]

    def test_list_with_async_inner_validator(self):
        async def positive(value):
            await asyncio.sleep(0)
            if value <= 0:
                raise ValidationError("must be positive")

        class S(Schema):
            values = fields.List(fields.Int(validate=positive))

        schema = S()
        assert run(schema.aload({"values": [1, 2]})) == {"values": [1, 2]}
        assert run(schema.avalidate({"values": [1, -2, -3]})) == {
            "values": {1: ["must be positive"], 2: ["must be positive"]}
        }

    def test_dict_with_async_value_field(self):
        async def positive(value):
            await asyncio.sleep(0)
            if value <= 0:
                raise ValidationError("must be positive")

        class S(Schema):
            scores = fields.Dict(
                keys=fields.Str(), values=fields.Int(validate=positive)
            )

        errors = run(S().avalidate({"scores": {"a": 1, "b": -1}}))
        assert errors == {"scores": {"b": {"value": ["must be positive"]}}}

    def test_pluck_async(self):
        class S(Schema):
            city = fields.Pluck(AddressSchema, "city")

        assert run(S().aload({"city": "here"})) == {"city": {"city": "here"}}
        assert run(S().avalidate({"city": "nowhere"})) == {
            "city": {"city": ["unknown city"]}
        }

    def test_async_pass_collection_schema_validator(self):
        seen = []

        class S(Schema):
            name = fields.Str()

            @validates_schema(pass_collection=True)
            async def check_collection(self, data, **kwargs):
                await asyncio.sleep(0)
                seen.append(type(data))
                if len(data) != 2:
                    raise ValidationError("need exactly two")

        schema = S()
        assert run(schema.avalidate([{"name": "a"}, {"name": "b"}], many=True)) == {}
        errors = run(schema.avalidate([{"name": "a"}], many=True))
        assert errors == {"_schema": ["need exactly two"]}

    def test_nested_many_deeply(self):
        service = LocalAsyncService(delay=0)
        service.fail_values = {"bad"}

        async def remote(value):
            await service.request("city", value)

        class CitySchema(Schema):
            name = fields.Str(validate=remote)

        class CountrySchema(Schema):
            cities = fields.Nested(CitySchema, many=True)

        class WorldSchema(Schema):
            countries = fields.List(fields.Nested(CountrySchema))

        data = {
            "countries": [
                {"cities": [{"name": "a"}, {"name": "bad"}]},
                {"cities": [{"name": "c"}]},
            ]
        }
        errors = run(WorldSchema().avalidate(data))
        assert errors == {
            "countries": {0: {"cities": {1: {"name": ["city rejected remotely"]}}}}
        }


class TestConcurrency:
    def test_independent_fields_run_concurrently_with_bound(self):
        service = LocalAsyncService(delay=0.02)

        def make_validator(key):
            async def validator(value):
                await service.request(key, value)

            return validator

        class S(Schema):
            ASYNC_CONCURRENCY = 2
            a = fields.Str(validate=make_validator("a"))
            b = fields.Str(validate=make_validator("b"))
            c = fields.Str(validate=make_validator("c"))
            d = fields.Str(validate=make_validator("d"))

        schema = S()
        run(schema.aload({"a": "1", "b": "2", "c": "3", "d": "4"}))
        assert service.calls == 4
        assert service.max_in_flight == 2

    def test_many_items_bounded_concurrency(self):
        service = LocalAsyncService(delay=0.02)

        async def validator(value):
            await service.request("x", value)

        class S(Schema):
            ASYNC_CONCURRENCY = 3
            x = fields.Str(validate=validator)

        run(S().aload([{"x": str(i)} for i in range(10)], many=True))
        assert service.calls == 10
        assert service.max_in_flight <= 3
        assert service.max_in_flight >= 2

    def test_ordering_stages_still_sequential(self):
        events = []

        class S(Schema):
            name = fields.Str()

            @pre_load
            async def pre(self, data, **kwargs):
                events.append("pre-start")
                await asyncio.sleep(0.01)
                events.append("pre-end")
                return data

            @validates("name")
            async def check(self, value, **kwargs):
                events.append("validate")
                await asyncio.sleep(0)

            @post_load
            async def post(self, data, **kwargs):
                events.append("post")
                await asyncio.sleep(0)
                return data

        run(S().aload({"name": "x"}))
        assert events == ["pre-start", "pre-end", "validate", "post"]


class TestCancellation:
    def test_cancellation_awaits_all_started_tasks(self):
        entered = []
        released = []

        async def gate(index):
            entered.append(index)
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                released.append(index)
                raise

        def make_validator(index):
            async def validator(value):
                await gate(index)

            return validator

        class S(Schema):
            ASYNC_CONCURRENCY = 2
            a = fields.Str(validate=make_validator("a"))
            b = fields.Str(validate=make_validator("b"))
            c = fields.Str(validate=make_validator("c"))

        async def scenario():
            task = asyncio.create_task(S().aload({"a": "1", "b": "2", "c": "3"}))
            await asyncio.sleep(0.05)
            assert len(entered) == 2
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # allow cancellations of started child tasks to settle
            await asyncio.sleep(0.05)
            assert released == entered
            assert len(asyncio.all_tasks()) == 1

        asyncio.run(scenario())


class TestSyncRejection:
    def test_sync_load_rejects_async_hook(self):
        class S(Schema):
            @pre_load
            async def pre(self, data, **kwargs):
                return data

        with pytest.raises(RuntimeError, match="aload"):
            S().load({})

    def test_sync_validate_rejects_async_validator(self):
        async def remote(value):
            await asyncio.sleep(0)

        class S(Schema):
            name = fields.Str(validate=remote)

        with pytest.raises(RuntimeError, match="aload"):
            S().validate({"name": "x"})

    def test_sync_load_rejects_nested_async_schema(self):
        class Child(Schema):
            @validates("x")
            async def check(self, value, **kwargs):
                pass

            x = fields.Str()

        class Parent(Schema):
            child = fields.Nested(Child)

        with pytest.raises(RuntimeError, match="aload"):
            Parent().load({"child": {"x": "1"}})

    def test_sync_load_rejects_list_with_async_inner(self):
        async def remote(value):
            return None

        class S(Schema):
            values = fields.List(fields.Str(validate=remote))

        with pytest.raises(RuntimeError, match="aload"):
            S().load({"values": ["a"]})

    def test_coroutine_is_not_returned_as_field_value(self):
        # A validator that is async def but invoked via the sync field API
        # directly: guarded by And. Here we simulate an async validator passed
        # to a plain field in a fully synchronous schema by bypassing the
        # eager schema check (the field check still applies).
        async def remote(value):
            await asyncio.sleep(0)

        field = fields.Str(validate=remote)
        with pytest.raises(RuntimeError, match="avalidate"):
            field.deserialize("x")
        # And the coroutine must have been closed (no warning later).
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with pytest.raises(RuntimeError):
                fields.Str(validate=remote).deserialize("x")

    def test_async_field_pre_load_rejected_sync(self):
        async def pre(value):
            return value

        field = fields.Str(pre_load=pre)
        with pytest.raises(RuntimeError, match="aload"):
            field.deserialize("x")

    def test_plain_sync_schema_keeps_working(self):
        class S(Schema):
            name = fields.Str(validate=validate.Length(min=1))

        assert S().load({"name": "ok"}) == {"name": "ok"}
        assert S().validate({"name": ""}) == {
            "name": ["Shorter than minimum length 1."]
        }


class TestAsyncLoads:
    def test_aloads_decodes_then_aloads(self):
        class S(Schema):
            @validates("name")
            async def check(self, value, **kwargs):
                await asyncio.sleep(0)

            name = fields.Str()

            @post_load
            async def wrap(self, data, **kwargs):
                await asyncio.sleep(0)
                return data

        assert run(S().aloads(json.dumps({"name": "ok"}))) == {"name": "ok"}

    def test_aloads_propagates_validation_error(self):
        class S(Schema):
            @validates("name")
            async def check(self, value, **kwargs):
                await asyncio.sleep(0)
                if value == "bad":
                    raise ValidationError("bad")

            name = fields.Str()

        with pytest.raises(ValidationError) as exc:
            run(S().aloads(json.dumps({"name": "bad"})))
        assert exc.value.messages == {"name": ["bad"]}

    def test_nested_validation_tasks_cancelled(self):
        entered = asyncio.Event()
        finish = asyncio.Event()

        async def validator(value):
            entered.set()
            await finish.wait()

        class Child(Schema):
            x = fields.Str(validate=validator)

        class Parent(Schema):
            child = fields.Nested(Child)

        async def scenario():
            task = asyncio.create_task(Parent().aload({"child": {"x": "1"}}))
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            finish.set()
            await asyncio.sleep(0)

        asyncio.run(scenario())
