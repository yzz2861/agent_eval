from __future__ import annotations

from typing import Generic, TypeVar

import pytest

from pydantic import (
    BaseModel,
    Field,
    PydanticUserError,
    ValidationError,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic.model_projection import depends_on, derive_model


def test_projection_copies_field_view_without_mutating_source() -> None:
    class Source(BaseModel):
        keep: str = Field(alias='keepAlias', min_length=1, default_factory=lambda: 'value')
        drop: int = Field(default=1, ge=1)

    Projected = derive_model(Source, ['keep'], model_name='Projected')

    assert list(Projected.model_fields) == ['keep']
    assert list(Source.model_fields) == ['keep', 'drop']
    assert not issubclass(Projected, Source)
    assert Source.model_fields['keep'].annotation is str
    assert Source.model_fields['drop'].annotation is int
    assert Projected.model_fields['keep'] is not Source.model_fields['keep']
    assert Projected.model_fields['keep'].alias == 'keepAlias'
    assert Projected.model_fields['keep'].metadata == Source.model_fields['keep'].metadata
    assert Projected.model_fields['keep'].default_factory is Source.model_fields['keep'].default_factory

    value = Projected.model_validate({'keepAlias': ' x '})
    assert value.model_dump(by_alias=True) == {'keepAlias': ' x '}


def test_projection_retains_aliases_constraints_default_factory_and_serialization() -> None:
    def factory() -> list[int]:
        return [1]

    class Source(BaseModel):
        items: list[int] = Field(alias='itemsAlias', min_length=1, default_factory=factory)
        ignored: str = 'ignored'

    Projected = derive_model(Source, ['items'], model_name='Projected')

    value = Projected.model_validate({'itemsAlias': ['2']})
    assert value.items == [2]
    assert value.model_dump(by_alias=True) == {'itemsAlias': [2]}
    schema = Projected.model_json_schema(mode='serialization')
    assert set(schema['properties']) == {'itemsAlias'}
    assert schema['properties']['itemsAlias']['minItems'] == 1

    with pytest.raises(ValidationError):
        Projected.model_validate({'itemsAlias': []})


def test_field_validator_is_retained_only_for_selected_targets() -> None:
    class Source(BaseModel):
        a: str
        b: str

        @field_validator('a', 'b')
        @classmethod
        def normalize(cls, value: str) -> str:
            return value.strip()

    Projected = derive_model(Source, ['a'], model_name='Projected')
    assert Projected(a=' x ').a == 'x'
    assert tuple(Projected.__pydantic_decorators__.field_validators['normalize'].info.fields) == ('a',)


def test_wildcard_validator_requires_dependency_declaration() -> None:
    class Source(BaseModel):
        a: str
        b: str

        @field_validator('*')
        @classmethod
        def normalize(cls, value: object) -> object:
            return value

    with pytest.raises(PydanticUserError, match='uses'):
        derive_model(Source, ['a'], model_name='Projected')

    Projected = derive_model(
        Source,
        ['a'],
        dependencies={'normalize': ('a',)},
        undeclared_model_decorators='exclude',
        model_name='Projected',
    )
    assert tuple(Projected.__pydantic_decorators__.field_validators['normalize'].info.fields) == ('a',)


def test_model_validator_must_declare_dependencies() -> None:
    class Source(BaseModel):
        a: str
        b: str

        @model_validator(mode='after')
        def validate_model(self) -> Source:
            if self.a != self.b:
                raise ValueError('mismatch')
            return self

    with pytest.raises(PydanticUserError, match='must declare its field dependencies'):
        derive_model(Source, ['a'], model_name='Projected')

    Projected = derive_model(
        Source,
        ['a'],
        dependencies={'validate_model': ('a',)},
        model_name='Projected',
    )
    assert 'validate_model' in Projected.__pydantic_decorators__.model_validators

    Excluded = derive_model(
        Source,
        ['a'],
        dependencies={'validate_model': ('b')},
        undeclared_model_decorators='exclude',
        missing_dependencies='exclude',
        model_name='Excluded',
    )
    assert 'validate_model' not in Excluded.__pydantic_decorators__.model_validators


def test_computed_field_dependency_policy() -> None:
    class Source(BaseModel):
        a: int
        b: int

        @computed_field
        @property
        def total(self) -> int:
            return self.a + self.b

    with pytest.raises(PydanticUserError, match='must declare its field dependencies'):
        derive_model(Source, ['a'], computed_fields=['total'], model_name='Projected')

    with pytest.raises(PydanticUserError, match='depends on fields that are not projected'):
        derive_model(
            Source,
            ['a'],
            computed_fields=['total'],
            dependencies={'total': ('a', 'b')},
            model_name='Projected',
        )

    Projected = derive_model(
        Source,
        ['a', 'b'],
        computed_fields=['total'],
        dependencies={'total': ('a', 'b')},
        model_name='Projected',
    )
    value = Projected.model_validate({'a': 1, 'b': 2})
    assert value.model_dump() == {'a': 1, 'b': 2, 'total': 3}
    schema = Projected.model_json_schema(mode='serialization')
    assert 'total' in schema['properties']


def test_depends_on_marker_declares_validator_and_computed_dependencies() -> None:
    class Source(BaseModel):
        a: int

        @model_validator(mode='after')
        @depends_on('a')
        def touch(self) -> Source:
            return self

        @computed_field
        @depends_on('a')
        @property
        def doubled(self) -> int:
            return self.a * 2

    Projected = derive_model(Source, ['a'], computed_fields=['doubled'], model_name='Projected')
    assert Projected(a='3').model_dump() == {'a': 3, 'doubled': 6}


def test_nested_models_are_recursively_projected_and_stable() -> None:
    class Inner(BaseModel):
        keep: int
        drop: str

    class Outer(BaseModel):
        first: Inner
        second: Inner
        ignored: bool = False

    Projected = derive_model(
        Outer,
        ['first', 'second'],
        nested_models=lambda model, path: ['keep'],
        model_name='Projected',
    )

    first_nested = Projected.model_fields['first'].annotation
    second_nested = Projected.model_fields['second'].annotation
    assert first_nested is second_nested
    assert tuple(first_nested.model_fields) == ('keep',)

    value = Projected.model_validate({'first': {'keep': '1'}, 'second': {'keep': '2', 'drop': 'x'}})
    assert value.model_dump() == {'first': {'keep': 1}, 'second': {'keep': 2}}


def test_recursive_projection_uses_one_stable_reference() -> None:
    class Node(BaseModel):
        value: int
        children: list[Node] = []
        ignored: str = 'ignored'

    Projected = derive_model(
        Node,
        ['value', 'children'],
        nested_models=lambda model, path: ['value', 'children'],
        model_name='ProjectedNode',
    )

    value = Projected.model_validate({'value': '1', 'children': [{'value': '2'}]})
    assert value.model_dump() == {'value': 1, 'children': [{'value': 2, 'children': []}]}
    schema = Projected.model_json_schema()
    assert schema['$ref'] == '#/$defs/ProjectedNode'


T = TypeVar('T')


def test_generic_concretization_is_projected() -> None:
    class Box(BaseModel, Generic[T]):
        value: T
        label: str = 'label'

    Projected = derive_model(Box, ['value'], model_name='ProjectedBox')
    Concrete = Projected[int]

    assert Concrete(value='7').value == 7
    assert tuple(Concrete.model_fields) == ('value',)
    assert Concrete.model_json_schema()['type'] == 'object'


def test_recursive_generic_concretization_is_stable() -> None:
    class Tree(BaseModel, Generic[T]):
        value: T
        children: list[Tree[T]] = []
        ignored: str = 'ignored'

    Projected = derive_model(
        Tree,
        ['value', 'children'],
        nested_models='all',
        model_name='ProjectedTree',
    )
    Concrete = Projected[int]

    value = Concrete.model_validate({'value': '1', 'children': [{'value': '2'}]})
    assert value.model_dump() == {'value': 1, 'children': [{'value': 2, 'children': []}]}
    schema = Concrete.model_json_schema()
    assert set(schema['$defs']) == {'ProjectedTree_int_'}
