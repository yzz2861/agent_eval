from typing import Annotated, Literal, Optional

import pytest

from pydantic import BaseModel, Field, computed_field
from pydantic.json_schema import (
    GenerateJsonSchema,
    GenerateOpenAPI30JsonSchema,
    OpenAPI30Incompatibility,
    OpenAPI30IncompatibilityError,
    models_json_schema,
    to_openapi_3_0_schema,
)


class DegradingGenerateOpenAPI30JsonSchema(GenerateOpenAPI30JsonSchema):
    on_incompatible = 'degrade'


def generate_degraded(model, mode='validation', **kwargs):
    generator = DegradingGenerateOpenAPI30JsonSchema(**kwargs)
    schema = generator.generate(model.__pydantic_core_schema__, mode=mode)
    return schema, generator.incompatibilities


def test_nullable_any_of_collapsed():
    class Model(BaseModel):
        a: int | None = None

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['a'] == {'default': None, 'title': 'A', 'type': 'integer', 'nullable': True}


def test_nullable_primitive_type_array():
    class Model(BaseModel):
        a: int | None = None

    schema, incompatibilities = generate_degraded(Model, union_format='primitive_type_array')
    assert incompatibilities == []
    assert schema['properties']['a'] == {'default': None, 'title': 'A', 'type': 'integer', 'nullable': True}


def test_multi_type_array_distributed_over_any_of():
    class Model(BaseModel):
        a: int | str

    schema, incompatibilities = generate_degraded(Model, union_format='primitive_type_array')
    assert incompatibilities == []
    assert schema['properties']['a'] == {'title': 'A', 'anyOf': [{'type': 'integer'}, {'type': 'string'}]}


def test_null_only_type_is_degraded():
    class Model(BaseModel):
        a: None

    schema, incompatibilities = generate_degraded(Model)
    assert schema['properties']['a'] == {'title': 'A', 'nullable': True}
    assert [(i.path, i.keyword) for i in incompatibilities] == [('#/properties/a', 'type')]


def test_const_converted_to_enum():
    class Model(BaseModel):
        a: Literal['x'] = 'x'

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['a'] == {'default': 'x', 'title': 'A', 'type': 'string', 'enum': ['x']}


def test_exclusive_minimum_maximum_boolean_form():
    class Model(BaseModel):
        a: Annotated[int, Field(gt=1, lt=10)]
        b: Annotated[int, Field(ge=1, le=10)]

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['a'] == {
        'title': 'A',
        'type': 'integer',
        'minimum': 1,
        'exclusiveMinimum': True,
        'maximum': 10,
        'exclusiveMaximum': True,
    }
    assert schema['properties']['b'] == {'title': 'B', 'type': 'integer', 'minimum': 1, 'maximum': 10}


def test_tuple_degraded_with_diagnostic():
    class Model(BaseModel):
        a: tuple[int, str]

    schema, incompatibilities = generate_degraded(Model)
    assert schema['properties']['a'] == {
        'title': 'A',
        'type': 'array',
        'minItems': 2,
        'maxItems': 2,
        'items': {'anyOf': [{'type': 'integer'}, {'type': 'string'}]},
    }
    assert [(i.path, i.keyword) for i in incompatibilities] == [('#/properties/a', 'prefixItems')]


def test_homogeneous_tuple_is_equivalent():
    class Model(BaseModel):
        a: tuple[int, int]

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['a'] == {
        'title': 'A',
        'type': 'array',
        'minItems': 2,
        'maxItems': 2,
        'items': {'type': 'integer'},
    }


def test_variadic_tuple_unchanged():
    class Model(BaseModel):
        a: tuple[int, ...]

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['a'] == {'title': 'A', 'type': 'array', 'items': {'type': 'integer'}}


def test_definitions_and_refs_rewritten():
    class Child(BaseModel):
        a: int

    class Model(BaseModel):
        child: Child

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert '$defs' not in schema
    assert schema['properties']['child'] == {'$ref': '#/definitions/Child'}
    assert set(schema['definitions']) == {'Child'}


def test_recursive_model_refs_preserved():
    class Node(BaseModel):
        child: Optional['Node'] = None

    schema, incompatibilities = generate_degraded(Node)
    assert incompatibilities == []
    node = schema['definitions']['Node']
    assert node['properties']['child'] == {
        'default': None,
        'nullable': True,
        'allOf': [{'$ref': '#/definitions/Node'}],
    }


def test_discriminated_union_preserved():
    class Cat(BaseModel):
        pet_type: Literal['cat']
        meows: int

    class Dog(BaseModel):
        pet_type: Literal['dog']
        barks: float

    class Model(BaseModel):
        pet: Cat | Dog = Field(discriminator='pet_type')

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['pet'] == {
        'title': 'Pet',
        'oneOf': [{'$ref': '#/definitions/Cat'}, {'$ref': '#/definitions/Dog'}],
        'discriminator': {
            'propertyName': 'pet_type',
            'mapping': {'cat': '#/definitions/Cat', 'dog': '#/definitions/Dog'},
        },
    }
    assert schema['definitions']['Cat']['properties']['pet_type']['enum'] == ['cat']


def test_defaults_and_aliases_preserved():
    class Model(BaseModel):
        a: int = Field(default=5, alias='aliasedA')

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert list(schema['properties']) == ['aliasedA']
    assert schema['properties']['aliasedA']['default'] == 5

    schema_by_name, _ = generate_degraded(Model, by_alias=False)
    assert list(schema_by_name['properties']) == ['a']


def test_serialization_mode():
    class Model(BaseModel):
        x: int = 1

        @computed_field
        @property
        def double(self) -> int:
            return self.x * 2

    validation_schema, _ = generate_degraded(Model, mode='validation')
    serialization_schema, incompatibilities = generate_degraded(Model, mode='serialization')
    assert incompatibilities == []
    assert 'double' not in validation_schema['properties']
    assert 'double' in serialization_schema['properties']


def test_ref_siblings_wrapped_in_all_of():
    class Sub(BaseModel):
        a: int

    class Model(BaseModel):
        s: Sub = Field(description='a sub model')

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['s'] == {
        'description': 'a sub model',
        'allOf': [{'$ref': '#/definitions/Sub'}],
    }


def test_examples_converted_to_example():
    class Model(BaseModel):
        a: int = Field(examples=[1, 2])

    schema, incompatibilities = generate_degraded(Model)
    assert incompatibilities == []
    assert schema['properties']['a'] == {'title': 'A', 'type': 'integer', 'example': 1}


def test_error_mode_raises_by_default():
    class Model(BaseModel):
        a: tuple[int, str]

    with pytest.raises(OpenAPI30IncompatibilityError) as exc_info:
        Model.model_json_schema(schema_generator=GenerateOpenAPI30JsonSchema)

    incompatibilities = exc_info.value.incompatibilities
    assert [(i.path, i.keyword) for i in incompatibilities] == [('#/properties/a', 'prefixItems')]
    assert '#/properties/a' in str(exc_info.value)


def test_error_mode_via_init_argument():
    class Model(BaseModel):
        a: tuple[int, str]

    generator = GenerateOpenAPI30JsonSchema(on_incompatible='degrade')
    schema = generator.generate(Model.__pydantic_core_schema__)
    assert 'prefixItems' not in schema['properties']['a']
    assert [(i.path, i.keyword) for i in generator.incompatibilities] == [('#/properties/a', 'prefixItems')]


def test_unsupported_keywords_dropped_with_diagnostic():
    schema, incompatibilities = to_openapi_3_0_schema(
        {
            'type': 'object',
            'patternProperties': {'^x': {'type': 'integer'}},
            'properties': {'a': {'not': {'type': 'string'}}},
        }
    )
    assert schema == {'type': 'object', 'properties': {'a': {}}}
    assert [(i.path, i.keyword) for i in incompatibilities] == [
        ('#', 'patternProperties'),
        ('#/properties/a', 'not'),
    ]


def test_boolean_schemas():
    schema, incompatibilities = to_openapi_3_0_schema({'type': 'array', 'items': False, 'additionalProperties': False})
    # `additionalProperties: false` is valid OpenAPI 3.0 and preserved; `items: false` is not.
    assert schema == {'type': 'array', 'items': {}, 'additionalProperties': False}
    assert [(i.path, i.keyword) for i in incompatibilities] == [('#/items', 'false')]


def test_to_openapi_3_0_schema_does_not_mutate_input():
    json_schema = {'$defs': {'A': {'const': 1}}, '$ref': '#/$defs/A'}
    converted, incompatibilities = to_openapi_3_0_schema(json_schema)
    assert json_schema == {'$defs': {'A': {'const': 1}}, '$ref': '#/$defs/A'}
    assert converted == {'definitions': {'A': {'enum': [1]}}, 'allOf': [{'$ref': '#/definitions/A'}]}
    assert incompatibilities == []


def test_incompatibility_paths_are_json_pointers():
    _, incompatibilities = to_openapi_3_0_schema(
        {'properties': {'a/b': {'prefixItems': [{'type': 'null'}], 'type': 'array'}}}
    )
    assert incompatibilities[0].path == '#/properties/a~1b/items'
    assert isinstance(incompatibilities[0], OpenAPI30Incompatibility)


def test_models_json_schema_uses_definitions_key():
    class Model(BaseModel):
        a: int

    json_schemas_map, top_level_schema = models_json_schema(
        [(Model, 'validation')], schema_generator=DegradingGenerateOpenAPI30JsonSchema
    )
    assert '$defs' not in top_level_schema
    assert set(top_level_schema['definitions']) == {'Model'}
    assert json_schemas_map[(Model, 'validation')] == {'$ref': '#/definitions/Model'}


def test_default_generator_unaffected():
    class Model(BaseModel):
        a: int | None = None
        b: tuple[int, str]
        c: Literal['x'] = 'x'

    schema = Model.model_json_schema()
    assert schema['properties']['a'] == {
        'anyOf': [{'type': 'integer'}, {'type': 'null'}],
        'default': None,
        'title': 'A',
    }
    assert 'prefixItems' in schema['properties']['b']
    assert schema['properties']['c']['const'] == 'x'

    _, top_level_schema = models_json_schema([(Model, 'validation')], schema_generator=GenerateJsonSchema)
    assert '$defs' in top_level_schema or 'definitions' not in top_level_schema
