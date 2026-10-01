from typing import Annotated, Literal, Optional

import pytest

from pydantic import BaseModel, Field, TypeAdapter, WithJsonSchema, computed_field
from pydantic.json_schema import (
    GenerateJsonSchema,
    GenerateOpenAPI30JsonSchema,
    OpenAPI30Diagnostic,
    OpenAPI30SchemaError,
)


def test_optional_field_becomes_nullable():
    class Model(BaseModel):
        x: int | None = None

    assert Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema) == {
        'properties': {'x': {'default': None, 'nullable': True, 'title': 'X', 'type': 'integer'}},
        'title': 'Model',
        'type': 'object',
    }


def test_nullable_enum_includes_null():
    class Model(BaseModel):
        x: Literal['a', 'b'] | None = None

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    assert schema['properties']['x'] == {
        'default': None,
        'enum': ['a', 'b', None],
        'nullable': True,
        'title': 'X',
        'type': 'string',
    }


def test_optional_model_ref_wrapped_in_allof():
    class Inner(BaseModel):
        a: int

    class Model(BaseModel):
        inner: Inner | None = None

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    assert '$defs' not in schema
    assert schema['properties']['inner'] == {
        'allOf': [{'$ref': '#/components/schemas/Inner'}],
        'default': None,
        'nullable': True,
    }
    assert schema['components']['schemas']['Inner'] == {
        'properties': {'a': {'title': 'A', 'type': 'integer'}},
        'required': ['a'],
        'title': 'Inner',
        'type': 'object',
    }


def test_const_becomes_enum():
    class Model(BaseModel):
        x: Annotated[int, WithJsonSchema({'const': 5})]

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    assert schema['properties']['x'] == {'enum': [5], 'title': 'X'}


def test_exclusive_bounds_become_boolean_modifiers():
    class Model(BaseModel):
        x: int = Field(gt=0, lt=10)
        y: float = Field(ge=1.5, le=2.5)

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    assert schema['properties']['x'] == {
        'exclusiveMinimum': True,
        'exclusiveMaximum': True,
        'maximum': 10,
        'minimum': 0,
        'title': 'X',
        'type': 'integer',
    }
    assert schema['properties']['y'] == {'maximum': 2.5, 'minimum': 1.5, 'title': 'Y', 'type': 'number'}


def test_tuple_degrades_with_diagnostic():
    class Model(BaseModel):
        t: tuple[int, str]

    generator = GenerateOpenAPI30JsonSchema()
    schema = Model.model_json_schema(schema_generator=lambda **kwargs: generator)
    assert schema['properties']['t'] == {
        'items': {},
        'maxItems': 2,
        'minItems': 2,
        'title': 'T',
        'type': 'array',
    }
    assert generator.diagnostics == [
        OpenAPI30Diagnostic(
            path='/properties/t',
            keyword='prefixItems',
            message='Tuple types cannot be represented in OpenAPI 3.0; degraded to a homogeneous array schema.',
        )
    ]


def test_homogeneous_tuple_degrades_to_typed_items():
    class Model(BaseModel):
        t: tuple[int, int]

    generator = GenerateOpenAPI30JsonSchema()
    schema = Model.model_json_schema(schema_generator=lambda **kwargs: generator)
    assert schema['properties']['t']['items'] == {'type': 'integer'}
    assert len(generator.diagnostics) == 1


def test_strict_mode_raises_with_diagnostics():
    class Model(BaseModel):
        t: tuple[int, str]

    def strict_generator(**kwargs):
        kwargs.pop('on_unrepresentable', None)
        return GenerateOpenAPI30JsonSchema(on_unrepresentable='error', **kwargs)

    with pytest.raises(OpenAPI30SchemaError) as exc_info:
        Model.model_json_schema(schema_generator=strict_generator)
    assert exc_info.value.diagnostics[0].path == '/properties/t'
    assert exc_info.value.diagnostics[0].keyword == 'prefixItems'
    assert '/properties/t' in str(exc_info.value)


def test_unsupported_keywords_dropped_with_diagnostic():
    class Model(BaseModel):
        x: Annotated[list[int], WithJsonSchema({'type': 'array', 'contains': {'type': 'integer'}})]

    generator = GenerateOpenAPI30JsonSchema()
    schema = Model.model_json_schema(schema_generator=lambda **kwargs: generator)
    assert schema['properties']['x'] == {'title': 'X', 'type': 'array'}
    assert generator.diagnostics[0].keyword == 'contains'
    assert generator.diagnostics[0].path == '/properties/x'


def test_examples_become_single_example():
    class Model(BaseModel):
        x: int = Field(examples=[1, 2])

    generator = GenerateOpenAPI30JsonSchema()
    schema = Model.model_json_schema(schema_generator=lambda **kwargs: generator)
    assert schema['properties']['x']['example'] == 1
    assert 'examples' not in schema['properties']['x']
    assert generator.diagnostics[0].keyword == 'examples'


def test_recursive_model():
    class Node(BaseModel):
        name: str
        child: Optional['Node'] = None

    schema = Node.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    node_schema = schema['components']['schemas']['Node']
    assert node_schema['properties']['child'] == {
        'allOf': [{'$ref': '#/components/schemas/Node'}],
        'default': None,
        'nullable': True,
    }


def test_discriminated_union_preserved():
    class Cat(BaseModel):
        kind: Literal['cat'] = 'cat'
        meows: bool = True

    class Dog(BaseModel):
        kind: Literal['dog'] = 'dog'
        barks: bool = True

    class Model(BaseModel):
        pet: Cat | Dog = Field(discriminator='kind')

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    assert schema['properties']['pet'] == {
        'discriminator': {
            'mapping': {'cat': '#/components/schemas/Cat', 'dog': '#/components/schemas/Dog'},
            'propertyName': 'kind',
        },
        'oneOf': [{'$ref': '#/components/schemas/Cat'}, {'$ref': '#/components/schemas/Dog'}],
        'title': 'Pet',
    }
    assert set(schema['components']['schemas']) == {'Cat', 'Dog'}


def test_defaults_and_aliases_preserved():
    class Model(BaseModel):
        x: str = Field(default='hi', alias='theAlias')

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    assert schema['properties'] == {'theAlias': {'default': 'hi', 'title': 'Thealias', 'type': 'string'}}

    schema_no_alias = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema, by_alias=False)
    assert schema_no_alias['properties'] == {'x': {'default': 'hi', 'title': 'X', 'type': 'string'}}


def test_serialization_mode():
    class Model(BaseModel):
        x: int = 1

        @computed_field
        @property
        def doubled(self) -> int:
            return self.x * 2

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema, mode='serialization')
    assert schema['properties']['doubled'] == {'readOnly': True, 'title': 'Doubled', 'type': 'integer'}
    assert schema['required'] == ['doubled']


def test_type_array_union_format():
    class Model(BaseModel):
        x: int | str
        y: int | None = None

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema, union_format='primitive_type_array')
    assert schema['properties']['x'] == {'anyOf': [{'type': 'integer'}, {'type': 'string'}], 'title': 'X'}
    assert schema['properties']['y'] == {'default': None, 'nullable': True, 'title': 'Y', 'type': 'integer'}


def test_generate_definitions_via_type_adapter():
    class Model(BaseModel):
        x: int | None = None

    json_schemas_map, definitions = TypeAdapter.json_schemas(
        [(Model, 'validation', TypeAdapter(Model)), (Model, 'serialization', TypeAdapter(Model))],
        schema_generator=GenerateOpenAPI30JsonSchema,
    )
    assert json_schemas_map[(Model, 'validation')] == {'$ref': '#/components/schemas/Model'}
    assert json_schemas_map[(Model, 'serialization')] == {'$ref': '#/components/schemas/Model'}
    assert definitions == {
        '$defs': {
            'Model': {
                'properties': {'x': {'default': None, 'nullable': True, 'title': 'X', 'type': 'integer'}},
                'title': 'Model',
                'type': 'object',
            }
        }
    }


def test_default_generator_unaffected():
    class Inner(BaseModel):
        a: int

    class Model(BaseModel):
        x: int | None = None
        inner: Inner | None = None

    schema = Model.model_json_schema(schema_generator=GenerateJsonSchema)
    assert '$defs' in schema
    assert schema['properties']['x'] == {
        'anyOf': [{'type': 'integer'}, {'type': 'null'}],
        'default': None,
        'title': 'X',
    }


def test_additional_properties_boolean_preserved():
    class Model(BaseModel):
        model_config = {'extra': 'forbid'}
        x: int

    schema = Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)
    assert schema['additionalProperties'] is False
