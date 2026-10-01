"""Tests for the asynchronous load/validate API (Schema.aload/avalidate)."""

import asyncio
import functools

import pytest

from marshmallow import (
    Schema,
    ValidationError,
    fields,
    post_load,
    pre_load,
    validate,
    validates,
    validates_schema,
)


class FakeAsyncService:
    """A local, controllable stand-in for an asynchronous network service."""

    def __init__(self, *, taken=(), delay=0):
        self.taken = set(taken)
        self.delay = delay
        self.calls = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def is_taken(self, value):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(self.delay)
            self.calls.append(value)
            return value in self.taken
        finally:
            self.in_flight -= 1


def run(coro):
    return asyncio.run(coro)


class AsyncUserSchema(Schema):
    """Schema whose hooks call a local async "service"."""

    name = fields.Str(required=True)
    age = fields.Int()

    def __init__(self, *args, service=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.service = service or FakeAsyncService()

    @validates("name")
    async def check_name_available(self, value, **kwargs):
        if await self.service.is_taken(value):
            raise ValidationError("Name is already taken.")

    @validates_schema
    async def check_age(self, data, **kwargs):
        if data.get("age") is not None and data["age"] < 0:
            raise ValidationError("Age must be positive.", "age")


class TestAsyncFieldValidation:
    def test_aload_valid_data(self):
        service = FakeAsyncService(taken={"taken"})
        schema = AsyncUserSchema(service=service)
        result = run(schema.aload({"name": "monty", "age": 42}))
        assert result == {"name": "monty", "age": 42}
        assert service.calls == ["monty"]

    def test_aload_invalid_data(self):
        service = FakeAsyncService(taken={"taken"})
        schema = AsyncUserSchema(service=service)
        with pytest.raises(ValidationError) as excinfo:
            run(schema.aload({"name": "taken"}))
        assert excinfo.value.messages == {"name": ["Name is already taken."]}

    def test_avalidate_returns_errors(self):
        service = FakeAsyncService(taken={"taken"})
        schema = AsyncUserSchema(service=service)
        assert run(schema.avalidate({"name": "taken"})) == {
            "name": ["Name is already taken."]
        }
        assert run(schema.avalidate({"name": "monty"})) == {}

    def test_aloads(self):
        schema = AsyncUserSchema()
        result = run(schema.aloads('{"name": "monty", "age": 42}'))
        assert result == {"name": "monty", "age": 42}

    def test_async_validator_passed_to_field(self):
        service = FakeAsyncService(taken={"taken"})

        async def is_available(value):
            if await service.is_taken(value):
                raise ValidationError("Name is already taken.")

        class UserSchema(Schema):
            name = fields.Str(validate=is_available)

        schema = UserSchema()
        assert run(schema.aload({"name": "monty"})) == {"name": "monty"}
        with pytest.raises(ValidationError) as excinfo:
            run(schema.aload({"name": "taken"}))
        assert excinfo.value.messages == {"name": ["Name is already taken."]}

    def test_async_validator_composed_with_and(self):
        service = FakeAsyncService(taken={"taken"})

        async def is_available(value):
            if await service.is_taken(value):
                raise ValidationError("Name is already taken.")

        class UserSchema(Schema):
            name = fields.Str(
                validate=validate.And(is_available, validate.Length(min=3))
            )

        schema = UserSchema()
        assert run(schema.avalidate({"name": "ok"})) == {
            "name": ["Shorter than minimum length 3."]
        }
        assert run(schema.avalidate({"name": "taken"})) == {
            "name": ["Name is already taken."]
        }
        assert run(schema.avalidate({"name": "monty"})) == {}

    def test_many_error_positions(self):
        service = FakeAsyncService(taken={"taken"})
        schema = AsyncUserSchema(service=service)
        errors = run(
            schema.avalidate(
                [{"name": "monty"}, {"name": "taken"}, {"name": "alice"}], many=True
            )
        )
        assert errors == {1: {"name": ["Name is already taken."]}}

    def test_many_result_order_preserved(self):
        service = FakeAsyncService(delay=0.001)
        schema = AsyncUserSchema(service=service)
        data = [{"name": f"user{i}"} for i in range(10)]
        assert run(schema.aload(data, many=True)) == data


class TestAsyncSchemaValidation:
    def test_schema_validator_error_position(self):
        schema = AsyncUserSchema()
        errors = run(schema.avalidate({"name": "monty", "age": -1}))
        assert errors == {"age": ["Age must be positive."]}

    def test_schema_validator_many_error_positions(self):
        schema = AsyncUserSchema()
        errors = run(
            schema.avalidate(
                [{"name": "monty", "age": 1}, {"name": "alice", "age": -1}], many=True
            )
        )
        assert errors == {1: {"age": ["Age must be positive."]}}

    def test_pass_collection_validator(self):
        class BandSchema(Schema):
            members = fields.List(fields.Str())

            @validates_schema(pass_collection=True)
            async def check_size(self, data, **kwargs):
                if len(data) > 2:
                    raise ValidationError("Too many items.")

        schema = BandSchema()
        assert run(schema.avalidate([{"members": []}], many=True)) == {}
        assert run(schema.avalidate([{"members": []}] * 3, many=True)) == {
            "_schema": ["Too many items."]
        }

    def test_pass_original_validator(self):
        seen = []

        class BandSchema(Schema):
            members = fields.List(fields.Str())

            @validates_schema(pass_original=True)
            async def check_original(self, data, original_data, **kwargs):
                seen.append(original_data)

        schema = BandSchema()
        run(schema.aload({"members": ["a"]}))
        assert seen == [{"members": ["a"]}]


class TestAsyncProcessors:
    def test_async_pre_and_post_load(self):
        class UserSchema(Schema):
            name = fields.Str()

            @pre_load
            async def strip_envelope(self, data, **kwargs):
                await asyncio.sleep(0)
                return data["user"]

            @post_load
            async def upper_name(self, data, **kwargs):
                await asyncio.sleep(0)
                data["name"] = data["name"].upper()
                return data

        schema = UserSchema()
        assert run(schema.aload({"user": {"name": "monty"}})) == {"name": "MONTY"}

    def test_async_pre_load_error(self):
        class UserSchema(Schema):
            name = fields.Str()

            @pre_load
            async def reject(self, data, **kwargs):
                await asyncio.sleep(0)
                raise ValidationError("Nope.")

        schema = UserSchema()
        with pytest.raises(ValidationError) as excinfo:
            run(schema.aload({"name": "monty"}))
        assert excinfo.value.messages == {"_schema": ["Nope."]}

    def test_async_post_load_many(self):
        class UserSchema(Schema):
            name = fields.Str()

            @post_load
            async def upper_name(self, data, **kwargs):
                await asyncio.sleep(0)
                data["name"] = data["name"].upper()
                return data

        schema = UserSchema()
        result = run(schema.aload([{"name": "a"}, {"name": "b"}], many=True))
        assert result == [{"name": "A"}, {"name": "B"}]

    def test_field_level_async_processors(self):
        async def upper(value):
            await asyncio.sleep(0)
            return value.upper()

        class UserSchema(Schema):
            name = fields.Str(post_load=upper)

        schema = UserSchema()
        assert run(schema.aload({"name": "monty"})) == {"name": "MONTY"}

    def test_mixed_sync_and_async_hooks(self):
        calls = []

        class UserSchema(Schema):
            name = fields.Str()

            @pre_load
            def sync_pre(self, data, **kwargs):
                calls.append("sync_pre")
                return data

            @pre_load
            async def async_pre(self, data, **kwargs):
                await asyncio.sleep(0)
                calls.append("async_pre")
                return data

            @validates("name")
            def sync_check(self, value, **kwargs):
                calls.append("sync_check")

            @validates("name")
            async def async_check(self, value, **kwargs):
                await asyncio.sleep(0)
                calls.append("async_check")

            @post_load
            def sync_post(self, data, **kwargs):
                calls.append("sync_post")
                return data

        schema = UserSchema()
        assert run(schema.aload({"name": "monty"})) == {"name": "monty"}
        # Hooks of the same type run in name resolution order; pre_load hooks
        # run before field validators, which run before post_load hooks.
        assert calls[:2] == ["async_pre", "sync_pre"]
        assert sorted(calls[2:4]) == ["async_check", "sync_check"]
        assert calls[4] == "sync_post"

    def test_hook_execution_order(self):
        calls = []

        class UserSchema(Schema):
            name = fields.Str()

            @pre_load
            async def pre(self, data, **kwargs):
                calls.append("pre_load")
                return data

            @validates("name")
            async def check_name(self, value, **kwargs):
                calls.append("field_validator")

            @validates_schema
            async def check_schema(self, data, **kwargs):
                calls.append("schema_validator")

            @post_load
            async def post(self, data, **kwargs):
                calls.append("post_load")
                return data

        run(UserSchema().aload({"name": "monty"}))
        assert calls == ["pre_load", "field_validator", "schema_validator", "post_load"]


class TestAsyncNested:
    def test_nested_schema_error_position(self):
        service = FakeAsyncService(taken={"taken"})

        class ChildSchema(Schema):
            name = fields.Str()

            @validates("name")
            async def check_name(self, value, **kwargs):
                if await service.is_taken(value):
                    raise ValidationError("Name is already taken.")

        class ParentSchema(Schema):
            child = fields.Nested(ChildSchema)
            children = fields.List(fields.Nested(ChildSchema))

        schema = ParentSchema()
        errors = run(
            schema.avalidate(
                {
                    "child": {"name": "taken"},
                    "children": [{"name": "monty"}, {"name": "taken"}],
                }
            )
        )
        assert errors == {
            "child": {"name": ["Name is already taken."]},
            "children": {1: {"name": ["Name is already taken."]}},
        }

    def test_nested_schema_valid_data(self):
        class ChildSchema(Schema):
            name = fields.Str()

            @post_load
            async def upper_name(self, data, **kwargs):
                await asyncio.sleep(0)
                data["name"] = data["name"].upper()
                return data

        class ParentSchema(Schema):
            child = fields.Nested(ChildSchema)

        schema = ParentSchema()
        assert run(schema.aload({"child": {"name": "monty"}})) == {
            "child": {"name": "MONTY"}
        }

    def test_nested_many_error_position(self):
        service = FakeAsyncService(taken={"taken"})

        class ChildSchema(Schema):
            name = fields.Str()

            @validates("name")
            async def check_name(self, value, **kwargs):
                if await service.is_taken(value):
                    raise ValidationError("Name is already taken.")

        class ParentSchema(Schema):
            child = fields.Nested(ChildSchema, many=True)

        schema = ParentSchema()
        errors = run(schema.avalidate({"child": [{"name": "ok"}, {"name": "taken"}]}))
        assert errors == {"child": {1: {"name": ["Name is already taken."]}}}


class TestSyncRejection:
    def test_sync_load_rejects_async_hooks(self):
        schema = AsyncUserSchema()
        with pytest.raises(ValueError, match="asynchronous"):
            schema.load({"name": "monty"})

    def test_sync_loads_rejects_async_hooks(self):
        schema = AsyncUserSchema()
        with pytest.raises(ValueError, match="asynchronous"):
            schema.loads('{"name": "monty"}')

    def test_sync_validate_rejects_async_hooks(self):
        schema = AsyncUserSchema()
        with pytest.raises(ValueError, match="asynchronous"):
            schema.validate({"name": "monty"})

    def test_sync_load_rejects_async_field_validator(self):
        async def is_available(value):
            return True

        class UserSchema(Schema):
            name = fields.Str(validate=is_available)

        with pytest.raises(ValueError, match="asynchronous"):
            UserSchema().load({"name": "monty"})

    def test_sync_load_rejects_async_field_processors(self):
        async def upper(value):
            return value.upper()

        class UserSchema(Schema):
            name = fields.Str(post_load=upper)

        with pytest.raises(ValueError, match="asynchronous"):
            UserSchema().load({"name": "monty"})

    def test_sync_load_does_not_return_coroutine(self):
        service = FakeAsyncService()

        class UserSchema(Schema):
            name = fields.Str()

            @validates("name")
            async def check_name(self, value, **kwargs):
                await service.is_taken(value)

        with pytest.raises(ValueError):
            UserSchema().load({"name": "monty"})

    def test_sync_load_still_works_without_async_hooks(self):
        class UserSchema(Schema):
            name = fields.Str(required=True)
            age = fields.Int()

            @validates("name")
            def check_name(self, value, **kwargs):
                if value == "bad":
                    raise ValidationError("Bad name.")

            @post_load
            def upper_name(self, data, **kwargs):
                data["name"] = data["name"].upper()
                return data

        schema = UserSchema()
        assert schema.load({"name": "monty", "age": "42"}) == {
            "name": "MONTY",
            "age": 42,
        }
        with pytest.raises(ValidationError):
            schema.load({"name": "bad"})


class TestAsyncEquivalence:
    def test_aload_matches_load_for_sync_schema(self):
        class UserSchema(Schema):
            name = fields.Str(required=True)
            age = fields.Int()

            @validates("age")
            def check_age(self, value, **kwargs):
                if value is not None and value < 0:
                    raise ValidationError("Age must be positive.")

            @post_load
            def upper_name(self, data, **kwargs):
                data["name"] = data["name"].upper()
                return data

        schema = UserSchema()
        data = {"name": "monty", "age": "42"}
        assert run(schema.aload(data)) == schema.load(data)
        assert run(schema.avalidate({"age": -1})) == schema.validate({"age": -1})

    def test_aload_partial_and_unknown(self):
        class UserSchema(Schema):
            name = fields.Str(required=True)

        schema = UserSchema()
        assert run(schema.aload({}, partial=True)) == {}
        with pytest.raises(ValidationError) as excinfo:
            run(schema.aload({"name": "a", "extra": 1}))
        assert excinfo.value.messages == {"extra": ["Unknown field."]}
        assert run(schema.aload({"name": "a", "extra": 1}, unknown="exclude")) == {
            "name": "a"
        }


class TestConcurrency:
    def test_max_concurrency_limits_parallelism(self):
        service = FakeAsyncService(delay=0.01)

        class UserSchema(Schema):
            name = fields.Str()

            @validates("name")
            async def check_name(self, value, **kwargs):
                await service.is_taken(value)

        schema = UserSchema()
        data = [{"name": f"user{i}"} for i in range(10)]
        assert run(schema.aload(data, many=True, max_concurrency=3)) == data
        assert service.max_in_flight > 1  # validation ran concurrently
        assert service.max_in_flight <= 3  # and respected the limit

    def test_invalid_max_concurrency(self):
        class UserSchema(Schema):
            name = fields.Str()

        with pytest.raises(ValueError, match="max_concurrency"):
            run(UserSchema().aload({"name": "monty"}, max_concurrency=0))

    def test_cancellation_stops_running_validators(self):
        started = asyncio.Event()
        release = asyncio.Event()  # never set
        cleaned_up = []

        async def blocking_check(value):
            started.set()
            try:
                await release.wait()
            finally:
                cleaned_up.append(value)

        class UserSchema(Schema):
            name = fields.Str()

            @validates("name")
            async def check_name(self, value, **kwargs):
                await blocking_check(value)

        async def main():
            task = asyncio.create_task(
                UserSchema().aload([{"name": "a"}, {"name": "b"}], many=True)
            )
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # The running validators were cancelled and cleaned up after
            assert sorted(cleaned_up) == ["a", "b"]
            # No background tasks are left running
            others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            assert others == []

        run(main())


class AsyncValidatorService:
    """Callable-instance async validator, mimicking an async service client."""

    def __init__(self):
        self.calls = []

    async def __call__(self, value):
        await asyncio.sleep(0)
        self.calls.append(value)
        if value == "bad":
            raise ValidationError("Invalid value.")


class TestAsyncValidatorForms:
    def test_callable_instance_async_call(self):
        service = AsyncValidatorService()

        class UserSchema(Schema):
            name = fields.Str(validate=service)

        schema = UserSchema()
        assert run(schema.aload({"name": "monty"})) == {"name": "monty"}
        assert run(schema.avalidate({"name": "bad"})) == {"name": ["Invalid value."]}
        with pytest.raises(ValueError, match="asynchronous"):
            schema.load({"name": "monty"})

    def test_partial_async_validator(self):
        async def is_not(value, *, forbidden):
            await asyncio.sleep(0)
            if value == forbidden:
                raise ValidationError("Invalid value.")

        class UserSchema(Schema):
            name = fields.Str(validate=functools.partial(is_not, forbidden="bad"))

        schema = UserSchema()
        assert run(schema.avalidate({"name": "bad"})) == {"name": ["Invalid value."]}
        with pytest.raises(ValueError, match="asynchronous"):
            schema.load({"name": "monty"})

    def test_and_wrapped_async_validator_rejected_in_sync_load(self):
        class UserSchema(Schema):
            name = fields.Str(validate=validate.And(AsyncValidatorService()))

        with pytest.raises(ValueError, match="asynchronous"):
            UserSchema().load({"name": "monty"})

    def test_standalone_field_adeserialize(self):
        field = fields.Str(validate=AsyncValidatorService())
        assert run(field.adeserialize("monty")) == "monty"
        with pytest.raises(ValidationError):
            run(field.adeserialize("bad"))

    def test_tuple_field_with_async_inner(self):
        class PairSchema(Schema):
            pair = fields.Tuple(
                (fields.Str(validate=AsyncValidatorService()), fields.Int())
            )

        assert run(PairSchema().avalidate({"pair": ["bad", 1]})) == {
            "pair": {0: ["Invalid value."]}
        }

    def test_nested_sync_load_rejects_async_hooks(self):
        class ChildSchema(Schema):
            name = fields.Str()

            @validates("name")
            async def check_name(self, value, **kwargs):
                pass

        class ParentSchema(Schema):
            child = fields.Nested(ChildSchema)

        with pytest.raises(ValueError, match="asynchronous"):
            ParentSchema().load({"child": {"name": "monty"}})

    def test_function_field_async_deserialize(self):
        async def parse(value):
            await asyncio.sleep(0)
            return value.upper()

        class UserSchema(Schema):
            name = fields.Function(deserialize=parse)

        schema = UserSchema()
        assert run(schema.aload({"name": "monty"})) == {"name": "MONTY"}
        with pytest.raises(ValueError, match="asynchronous"):
            schema.load({"name": "monty"})

    def test_method_field_async_deserialize(self):
        class UserSchema(Schema):
            name = fields.Method(deserialize="parse_name")

            async def parse_name(self, value):
                await asyncio.sleep(0)
                return value.upper()

        schema = UserSchema()
        assert run(schema.aload({"name": "monty"})) == {"name": "MONTY"}
        with pytest.raises(ValueError, match="asynchronous"):
            schema.load({"name": "monty"})

    def test_handle_error_called_in_async_load(self):
        handled = []

        class UserSchema(Schema):
            name = fields.Str()

            @validates("name")
            async def check_name(self, value, **kwargs):
                raise ValidationError("Boom.")

            def handle_error(self, error, data, *, many, **kwargs):
                handled.append(error.messages)

        with pytest.raises(ValidationError):
            run(UserSchema().aload({"name": "monty"}))
        assert handled == [{"name": ["Boom."]}]
