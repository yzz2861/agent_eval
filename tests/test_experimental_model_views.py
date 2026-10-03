from typing import Generic, TypeVar

import pytest

from pydantic import BaseModel, Field, ValidationError, ValidationInfo, computed_field, field_validator, model_validator
from pydantic.errors import PydanticUserError
from pydantic.experimental.model_views import depends_on, derive_model


def test_derive_model_preserves_field_view_without_mutating_source() -> None:
    class Address(BaseModel):
        street: str
        city: str

    class User(BaseModel):
        model_config = {'extra': 'forbid'}
        name: str = Field(alias='NAME', min_length=2)
        tags: list[str] = Field(default_factory=list, alias='TAGS')
        secret: str
        address: Address

    UserInput = derive_model(
        User,
        ('name', 'tags', 'address'),
        name='UserInput',
        nested_models={Address: ('street',)},
    )

    assert set(UserInput.model_fields) == {'name', 'tags', 'address'}
    assert set(User.model_fields) == {'name', 'tags', 'secret', 'address'}
    assert UserInput.model_fields['name'].validation_alias == 'NAME'
    assert UserInput.model_fields['name'].metadata
    assert UserInput.model_fields['tags'].default_factory is list
    assert UserInput.__bases__ == (BaseModel,)

    value = UserInput.model_validate({'NAME': 'Ada', 'address': {'street': 'Main', 'city': 'Hidden'}})
    assert value.model_dump(by_alias=True) == {
        'NAME': 'Ada',
        'TAGS': [],
        'address': {'street': 'Main'},
    }
    assert type(value.address).__name__.startswith('Address_View')
    with pytest.raises(ValidationError):
        UserInput.model_validate({'NAME': 'Ada', 'secret': 'x', 'address': {'street': 'Main'}})

    schema = UserInput.model_json_schema()
    assert set(schema['properties']) == {'NAME', 'TAGS', 'address'}
    address_definition = next(
        definition for name, definition in schema['$defs'].items() if name.startswith('Address_View')
    )
    assert set(address_definition['properties']) == {'street'}


def test_derive_model_validator_and_computed_dependencies() -> None:
    class User(BaseModel):
        first: str
        last: str

        @field_validator('first')
        @classmethod
        def normalize_first(cls, value: str) -> str:
            return value.strip()

        @model_validator(mode='after')
        def require_names(self) -> 'User':
            if not self.first or not self.last:
                raise ValueError('names are required')
            return self

        @depends_on('first', 'last')
        @computed_field
        @property
        def full_name(self) -> str:
            return f'{self.first} {self.last}'

    with pytest.raises(PydanticUserError, match='depends on field'):
        derive_model(User, ('first', 'full_name'), name='BadUserInput')

    SafeInput = derive_model(
        User,
        ('first',),
        name='SafeUserInput',
        on_missing_dependency='exclude',
    )
    value = SafeInput.model_validate({'first': ' Ada '})
    assert value.model_dump() == {'first': 'Ada'}
    assert not SafeInput.__pydantic_decorators__.model_validators
    assert not SafeInput.model_computed_fields
    assert set(SafeInput.model_json_schema(mode='serialization')['properties']) == {
        'first',
    }

    FullInput = derive_model(User, ..., name='FullUserInput')
    with pytest.raises(ValidationError):
        FullInput.model_validate({'first': '', 'last': ''})


def test_derive_model_recursive_types_use_stable_refs() -> None:
    class Node(BaseModel):
        value: int = Field(gt=0)
        ignored: str
        children: list['Node'] = []
        parent: 'Node | None' = None

    NodeInput = derive_model(Node, ('value', 'children', 'parent'), name='NodeInput')
    nested_annotation = NodeInput.model_fields['children'].annotation
    assert nested_annotation.__args__[0] is NodeInput
    assert NodeInput.model_fields['parent'].annotation.__args__[0] is NodeInput

    payload = {'value': 1, 'children': [{'value': 2, 'ignored': 'x'}], 'parent': {'value': 3}}
    value = NodeInput.model_validate(payload)
    assert value.children[0] is not value.parent
    assert type(value.children[0]) is NodeInput
    assert type(value.parent) is NodeInput
    assert value.model_dump() == {
        'value': 1,
        'children': [{'value': 2, 'children': [], 'parent': None}],
        'parent': {'value': 3, 'children': [], 'parent': None},
    }
    assert set(NodeInput.model_json_schema()['$defs']['NodeInput']['properties']) == {
        'value',
        'children',
        'parent',
    }


def test_derive_model_parameterized_generic_keeps_concrete_view() -> None:
    T = TypeVar('T')

    class Item(BaseModel):
        keep: int
        drop: int

    class Box(BaseModel, Generic[T]):
        item: T
        items: list[T]

    BoxInput = derive_model(
        Box[Item],
        ('item', 'items'),
        name='BoxItemInput',
        nested_models={Item: ('keep',)},
    )
    assert BoxInput.model_fields['item'].annotation.__name__.startswith('Item_View')
    assert BoxInput.model_fields['items'].annotation.__args__[0] is BoxInput.model_fields['item'].annotation

    value = BoxInput.model_validate(
        {
            'item': {'keep': 1, 'drop': 2},
            'items': [{'keep': 3, 'drop': 4}],
        }
    )
    assert value.model_dump() == {'item': {'keep': 1}, 'items': [{'keep': 3}]}
    assert type(value.items[0]) is type(value.item)


def test_derive_model_reuses_same_concrete_nested_view() -> None:
    T = TypeVar('T')

    class Item(BaseModel):
        keep: int
        drop: int

    class Box(BaseModel, Generic[T]):
        item: T

    class Holder(BaseModel):
        first: Box[Item]
        second: Box[Item]

    HolderInput = derive_model(
        Holder,
        ('first', 'second'),
        name='HolderInput',
        nested_models={Item: ('keep',)},
    )
    first_box = HolderInput.model_fields['first'].annotation
    second_box = HolderInput.model_fields['second'].annotation
    assert first_box is second_box
    assert first_box.model_fields['item'].annotation is second_box.model_fields['item'].annotation


def test_derive_generic_model_and_parameterized_view_apply_nested_selection() -> None:
    T = TypeVar('T')

    class Item(BaseModel):
        keep: int
        drop: int

    class Box(BaseModel, Generic[T]):
        item: T
        drop: str

    BoxView = derive_model(
        Box,
        ('item',),
        name='BoxView',
        nested_models={Item: ('keep',)},
    )
    ConcreteBox = BoxView[Item]

    assert BoxView[Item] is ConcreteBox
    assert ConcreteBox.model_fields['item'].annotation.__name__.startswith('Item_View')
    assert ConcreteBox(item={'keep': 1, 'drop': 2}).model_dump() == {'item': {'keep': 1}}


def test_field_validator_with_validation_info_requires_dependency_policy() -> None:
    class User(BaseModel):
        first: str
        last: str

        @field_validator('first')
        @classmethod
        def validate_first(cls, value: str, info: ValidationInfo) -> str:
            if info.data.get('last') == 'hidden':
                raise ValueError('invalid')
            return value

    with pytest.raises(PydanticUserError, match='depends on field'):
        derive_model(User, ('first',), name='BadUserInput')

    SafeUser = derive_model(User, ('first',), name='SafeUserInput', on_missing_dependency='exclude')
    assert not SafeUser.__pydantic_decorators__.field_validators


def test_computed_field_nested_return_uses_selected_view() -> None:
    class Address(BaseModel):
        street: str
        city: str

    class User(BaseModel):
        address: Address

        @depends_on('address')
        @computed_field
        @property
        def home(self) -> Address:
            return self.address

    UserInput = derive_model(
        User,
        ('address', 'home'),
        name='UserWithHomeInput',
        nested_models={Address: ('street',)},
    )
    value = UserInput.model_validate({'address': {'street': 'Main', 'city': 'Hidden'}})

    assert type(value.home).__name__.startswith('Address_View')
    assert value.model_dump() == {'address': {'street': 'Main'}, 'home': {'street': 'Main'}}
    properties = UserInput.model_json_schema(mode='serialization')['properties']
    assert set(properties) == {'address', 'home'}
