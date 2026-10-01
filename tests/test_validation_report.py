from typing import Literal

import pytest

from pydantic import (
    BaseModel,
    DefaultFactorySource,
    DefaultSource,
    Field,
    InputPathSource,
    RootModel,
    ValidationError,
    field_validator,
)
from pydantic._internal._validation_report import AliasResolution
from pydantic.aliases import AliasChoices, AliasPath


class Inner(BaseModel):
    value: int


def test_model_validate_report_records_input_default_and_factory() -> None:
    factory_calls = 0

    def factory():
        nonlocal factory_calls
        factory_calls += 1
        return []

    class Model(BaseModel):
        a: int = Field(validation_alias=AliasChoices('a_alias', AliasPath('nested', 0), 'a'))
        b: str = 'default'
        c: list = Field(default_factory=factory)

    result, report = Model.model_validate(
        {'a_alias': 1, 'nested': [2], 'a': 3},
        validation_report=True,
    )

    assert result.a == 1
    assert isinstance(report.fields['a'].source, InputPathSource)
    assert report.fields['a'].source.path == ('a_alias',)
    assert isinstance(report.fields['b'].source, DefaultSource)
    assert isinstance(report.fields['c'].source, DefaultFactorySource)
    assert [(alias.path, alias.consumed) for alias in report.fields['a'].aliases] == [
        (('a_alias',), True),
        (('nested', 0), False),
        (('a',), False),
    ]
    assert factory_calls == 1


def test_report_distinguishes_equal_values_by_lookup_path() -> None:
    class Model(BaseModel):
        x: int = Field(validation_alias=AliasChoices('x_alias', 'x'))

    by_alias, report_alias = Model.model_validate({'x_alias': 1, 'x': 1}, validation_report=True)
    by_name, report_name = Model.model_validate(
        {'x_alias': 1, 'x': 1},
        by_alias=False,
        by_name=True,
        validation_report=True,
    )

    assert by_alias.x == by_name.x == 1
    assert report_alias.fields['x'].source.path == ('x_alias',)
    assert report_name.fields['x'].source.path == ('x',)


def test_runtime_by_alias_and_by_name_flags_are_reflected() -> None:
    class Model(BaseModel):
        x: int = Field(validation_alias='x_alias')
        model_config = {'populate_by_name': True}

    _, alias_report = Model.model_validate({'x_alias': 1, 'x': 2}, validation_report=True)
    _, name_report = Model.model_validate(
        {'x_alias': 1, 'x': 2},
        by_alias=False,
        by_name=True,
        validation_report=True,
    )

    assert alias_report.fields['x'].source.path == ('x_alias',)
    assert name_report.fields['x'].source.path == ('x',)
    assert name_report.fields['x'].aliases == (AliasResolution(kind='alias', path=('x_alias',), consumed=False),)


def test_report_covers_nested_models_lists_and_union_branch() -> None:
    class Model(BaseModel):
        inner: Inner
        items: list[Inner | int]
        optional: Inner | None = None

    _, report = Model.model_validate(
        {
            'inner': {'value': 1},
            'items': [{'value': 2}, 3],
            'optional': {'value': 4},
        },
        validation_report=True,
    )

    assert report.fields['inner'].value.kind == 'model'
    assert report.fields['inner'].value.fields['value'].source.path == ('inner', 'value')
    assert report.fields['items'].value.items[0].kind == 'union'
    assert report.fields['items'].value.items[0].union_choice == 0
    assert report.fields['items'].value.items[0].fields['value'].source.path == ('items', 0, 'value')
    assert report.fields['items'].value.items[1].union_choice == 1
    assert report.fields['optional'].value.kind == 'model'
    assert report.fields['optional'].value.fields['value'].source.path == (
        'optional',
        'value',
    )


def test_report_does_not_run_user_validator_or_default_factory_more_than_once() -> None:
    validator_calls = 0
    factory_calls = 0

    def factory():
        nonlocal factory_calls
        factory_calls += 1
        return []

    class Model(BaseModel):
        x: int = 1
        values: list = Field(default_factory=factory)

        @field_validator('x')
        @classmethod
        def count_validator(cls, value: int) -> int:
            nonlocal validator_calls
            validator_calls += 1
            return value

    Model.model_validate({'x': 5}, validation_report=True)

    assert validator_calls == 1
    assert factory_calls == 1


def test_report_is_opt_in_and_ordinary_call_return_type_is_unchanged() -> None:
    class Model(BaseModel):
        x: int

    result = Model.model_validate({'x': 1})
    assert type(result) is Model


def test_report_validator_is_built_only_on_request(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic._internal import _validation_report

    class Model(BaseModel):
        x: int

    calls = 0
    original = _validation_report.SchemaValidator

    def counting_validator(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(_validation_report, 'SchemaValidator', counting_validator)
    Model.model_validate({'x': 1})
    assert calls == 0
    Model.model_validate({'x': 1}, validation_report=True)
    assert calls == 1


def test_root_model_report_records_root_value() -> None:
    class Root(RootModel[int]):
        pass

    _, report = Root.model_validate(5, validation_report=True)
    assert report.fields['root'].source.path == ()
    assert report.fields['root'].value.kind == 'value'


def test_report_revalidates_model_instances_with_revalidate_always() -> None:
    class Child(BaseModel):
        x: int

    class Parent(BaseModel):
        model_config = {'revalidate_instances': 'always'}

        child: Child

    _, report = Parent.model_validate({'child': Child(x=1)}, validation_report=True)
    assert report.fields['child'].value.fields['x'].source.path == ('child', 'x')


def test_report_preserves_validation_context() -> None:
    seen = []

    class Model(BaseModel):
        x: int

        @field_validator('x', mode='wrap')
        @classmethod
        def read_context(cls, value, handler, info):
            seen.append(info.context)
            return handler(value)

    _, report = Model.model_validate({'x': 1}, context={'secret': 'value'}, validation_report=True)
    assert seen == [{'secret': 'value'}]
    assert report.fields['x'].source.path == ('x',)


def test_report_does_not_store_input_values() -> None:
    class Secret:
        pass

    secret = Secret()

    class Model(BaseModel):
        secret: object

    _, report = Model.model_validate({'secret': secret}, validation_report=True)
    assert 'Secret' not in repr(report)
    assert report.fields['secret'].source.path == ('secret',)


def test_report_resolves_alias_paths_from_attributes() -> None:
    class Leaf:
        value = 7

    class Container:
        nested = Leaf()

    class Model(BaseModel):
        value: int = Field(validation_alias=AliasPath('nested', 'value'))

    _, report = Model.model_validate(
        Container(),
        from_attributes=True,
        validation_report=True,
    )
    assert report.fields['value'].source.path == ('nested', 'value')


def test_report_is_not_returned_for_validation_failure() -> None:
    class Model(BaseModel):
        x: int

    with pytest.raises(ValidationError):
        Model.model_validate({'x': 'bad'}, validation_report=True)


def test_report_covers_tagged_union_branch_and_alias_path() -> None:
    class Cat(BaseModel):
        kind: Literal['cat']
        lives: int

    class Dog(BaseModel):
        kind: Literal['dog']
        good: bool

    class Model(BaseModel):
        pet: Cat | Dog = Field(discriminator='kind')
        value: int = Field(validation_alias=AliasPath('payload', 'numbers', 1))

    _, report = Model.model_validate(
        {'pet': {'kind': 'dog', 'good': True}, 'payload': {'numbers': [10, 20]}},
        validation_report=True,
    )

    assert report.fields['pet'].value.union_choice == 'dog'
    assert report.fields['pet'].value.fields['good'].source.path == (
        'pet',
        'good',
    )
    assert report.fields['value'].source.path == ('payload', 'numbers', 1)


def test_report_uses_smart_union_selected_structural_branch() -> None:
    class LessSpecific(BaseModel):
        x: int

    class MoreSpecific(BaseModel):
        x: int
        y: int

    class Model(BaseModel):
        value: LessSpecific | MoreSpecific

    result, report = Model.model_validate({'value': {'x': 1, 'y': 2}}, validation_report=True)
    assert type(result.value) is MoreSpecific
    assert report.fields['value'].value.union_choice == 1
    assert report.fields['value'].value.model_name == 'MoreSpecific'


def test_report_covers_nested_default_factory_and_tuple_items() -> None:
    class Child(BaseModel):
        x: int = 1

    class Parent(BaseModel):
        child: Child
        values: tuple[Inner, ...]

    _, report = Parent.model_validate(
        {'child': {}, 'values': ({'value': 2},)},
        validation_report=True,
    )

    assert isinstance(report.fields['child'].value.fields['x'].source, DefaultSource)
    assert report.fields['values'].value.kind == 'tuple'
    assert report.fields['values'].value.items[0].fields['value'].source.path == (
        'values',
        0,
        'value',
    )
