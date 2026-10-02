import datetime as dt

import pytest

from marshmallow import Schema, ValidationError, fields, validate


class EventSchema(Schema):
    start = fields.DateTime()
    end = fields.DateTime(
        load_default=fields.DependentDefault(
            lambda deps: deps["start"] + dt.timedelta(hours=1),
            depends_on=("start",),
        )
    )


class TestDependentDefault:
    def test_default_computed_from_dependency(self):
        start = dt.datetime(2026, 10, 2, 10, 0, 0)
        result = EventSchema().load({"start": start.isoformat()})
        assert result["end"] == start + dt.timedelta(hours=1)

    def test_explicit_value_skips_factory(self):
        calls = []

        class MySchema(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: calls.append(deps) or deps["start"] + 1,
                    depends_on=("start",),
                )
            )

        result = MySchema().load({"start": 1, "end": 100})
        assert result == {"start": 1, "end": 100}
        assert calls == []

    def test_declaration_order_does_not_matter(self):
        class MySchema(Schema):
            # Dependent field declared before its dependency
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["start"] + 1, depends_on=("start",)
                )
            )
            start = fields.Int()

        assert MySchema().load({"start": 41}) == {"start": 41, "end": 42}

    def test_chained_dependencies(self):
        class MySchema(Schema):
            c = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["b"] * 2, depends_on=("b",)
                )
            )
            a = fields.Int()
            b = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["a"] + 1, depends_on=("a",)
                )
            )

        assert MySchema().load({"a": 1}) == {"a": 1, "b": 2, "c": 4}

    def test_multiple_dependencies(self):
        class MySchema(Schema):
            x = fields.Int()
            y = fields.Int()
            total = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["x"] + deps["y"], depends_on=("x", "y")
                )
            )

        assert MySchema().load({"x": 2, "y": 3})["total"] == 5

    def test_unknown_dependency_raises_at_schema_init(self):
        class MySchema(Schema):
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: 1, depends_on=("nonexistent",)
                )
            )

        with pytest.raises(ValueError, match="nonexistent"):
            MySchema()

    def test_circular_dependency_raises_at_schema_init(self):
        class MySchema(Schema):
            a = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["b"], depends_on=("b",)
                )
            )
            b = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["a"], depends_on=("a",)
                )
            )

        with pytest.raises(ValueError, match="Circular dependency"):
            MySchema()

    def test_self_dependency_raises_at_schema_init(self):
        class MySchema(Schema):
            a = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["a"], depends_on=("a",)
                )
            )

        with pytest.raises(ValueError, match="Circular dependency"):
            MySchema()

    def test_failed_dependency_keeps_original_error_and_explains_default(self):
        class MySchema(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["start"] + 1, depends_on=("start",)
                )
            )

        with pytest.raises(ValidationError) as excinfo:
            MySchema().load({"start": "not-an-int"})
        errors = excinfo.value.messages
        # Original error on the dependency is preserved
        assert errors["start"] == ["Not a valid integer."]
        # The dependent field explains why its default could not be generated
        assert len(errors["end"]) == 1
        assert "start" in errors["end"][0]
        assert "default" in errors["end"][0].lower()

    def test_missing_dependency_without_default_blocks_default(self):
        class MySchema(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["start"] + 1, depends_on=("start",)
                )
            )

        with pytest.raises(ValidationError) as excinfo:
            MySchema().load({})
        errors = excinfo.value.messages
        assert "start" not in errors
        assert len(errors["end"]) == 1
        assert "start" in errors["end"][0]

    def test_generated_value_is_validated(self):
        class MySchema(Schema):
            start = fields.Int()
            end = fields.Int(
                validate=validate.Range(max=10),
                load_default=fields.DependentDefault(
                    lambda deps: deps["start"] + 100, depends_on=("start",)
                ),
            )

        with pytest.raises(ValidationError) as excinfo:
            MySchema().load({"start": 1})
        assert excinfo.value.messages["end"] == [
            "Must be less than or equal to 10."
        ]

    def test_generated_value_is_deserialized(self):
        class MySchema(Schema):
            start = fields.DateTime()
            end = fields.DateTime(
                load_default=fields.DependentDefault(
                    # Factory returns a string; it must be deserialized
                    lambda deps: (deps["start"] + dt.timedelta(hours=1)).isoformat(),
                    depends_on=("start",),
                )
            )

        start = dt.datetime(2026, 10, 2, 10, 0, 0)
        result = MySchema().load({"start": start.isoformat()})
        assert result["end"] == start + dt.timedelta(hours=1)

    def test_factory_receives_only_declared_dependencies(self):
        received = []

        class MySchema(Schema):
            a = fields.Int()
            b = fields.Int()
            c = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: received.append(dict(deps)) or deps["a"],
                    depends_on=("a",),
                )
            )

        MySchema().load({"a": 1, "b": 2})
        assert received == [{"a": 1}]

    def test_nested_schema_computes_per_object(self):
        class Inner(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["start"] + 1, depends_on=("start",)
                )
            )

        class Outer(Schema):
            inner = fields.Nested(Inner)

        result = Outer().load({"inner": {"start": 5}})
        assert result == {"inner": {"start": 5, "end": 6}}

    def test_many_computes_per_item_and_factory_called_once_per_item(self):
        calls = []

        class MySchema(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: calls.append(deps["start"]) or deps["start"] + 1,
                    depends_on=("start",),
                )
            )

        result = MySchema(many=True).load(
            [{"start": 1}, {"start": 2, "end": 20}, {"start": 3}]
        )
        assert result == [
            {"start": 1, "end": 2},
            {"start": 2, "end": 20},
            {"start": 3, "end": 4},
        ]
        # Factory ran exactly once per item missing the value
        assert calls == [1, 3]

    def test_many_does_not_share_mutable_defaults(self):
        class MySchema(Schema):
            start = fields.Int()
            tags = fields.List(
                fields.Str(),
                load_default=fields.DependentDefault(
                    lambda deps: [f"item-{deps['start']}"], depends_on=("start",)
                ),
            )

        result = MySchema(many=True).load([{"start": 1}, {"start": 2}])
        assert result[0]["tags"] == ["item-1"]
        assert result[1]["tags"] == ["item-2"]
        assert result[0]["tags"] is not result[1]["tags"]

    def test_nested_many_computes_per_object(self):
        class Inner(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["start"] + 1, depends_on=("start",)
                )
            )

        class Outer(Schema):
            items = fields.Nested(Inner, many=True)

        result = Outer().load({"items": [{"start": 1}, {"start": 2}]})
        assert result == {
            "items": [{"start": 1, "end": 2}, {"start": 2, "end": 3}]
        }

    def test_error_in_one_item_does_not_block_other_items(self):
        class MySchema(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(
                    lambda deps: deps["start"] + 1, depends_on=("start",)
                )
            )

        with pytest.raises(ValidationError) as excinfo:
            MySchema(many=True).load([{"start": "bad"}, {"start": 2}])
        errors = excinfo.value.messages
        assert "start" in errors[0]
        assert "end" in errors[0]
        assert 1 not in errors
        valid = excinfo.value.valid_data
        assert valid[1] == {"start": 2, "end": 3}

    def test_factory_raising_validation_error_is_reported(self):
        def factory(deps):
            raise ValidationError("cannot compute")

        class MySchema(Schema):
            start = fields.Int()
            end = fields.Int(
                load_default=fields.DependentDefault(factory, depends_on=("start",))
            )

        with pytest.raises(ValidationError) as excinfo:
            MySchema().load({"start": 1})
        assert excinfo.value.messages["end"] == ["cannot compute"]

    def test_non_callable_factory_raises(self):
        with pytest.raises(TypeError, match="callable"):
            fields.DependentDefault(42, depends_on=("a",))

    def test_dump_unaffected(self):
        start = dt.datetime(2026, 10, 2, 10, 0, 0)
        result = EventSchema().dump({"start": start, "end": start})
        assert result["start"] == start.isoformat()
