from typing import Annotated, Literal

import pytest

from pydantic import (
    AliasChoices,
    AliasPath,
    BaseModel,
    DefaultFactorySource,
    DefaultSource,
    Discriminator,
    Field,
    ValidationInputPath,
    ValidationReport,
    field_validator,
)


def test_default_validation_returns_model() -> None:
    class Model(BaseModel):
        x: int = 1

    result = Model.model_validate({})

    assert isinstance(result, Model)
    assert result.x == 1


def test_reports_alias_name_and_default_sources() -> None:
    class Inner(BaseModel):
        value: str = Field('default', validation_alias=AliasChoices('alias_value', 'value'))

    class Model(BaseModel):
        x: int
        y: int = Field(validation_alias='alias_y')
        inner: Inner

    model, report = Model.model_validate(
        {'x': 1, 'alias_y': 2, 'inner': {'value': 'same'}},
        validation_report=True,
    )

    assert isinstance(model, Model)
    assert isinstance(report, ValidationReport)
    assert report.fields['x'].sources == [ValidationInputPath(('x',))]
    assert report.fields['y'].sources == [ValidationInputPath(('alias_y',))]
    assert report.fields['inner'].fields['value'].sources == [ValidationInputPath(('value',))]
    assert report.fields['inner'].fields['value'].unconsumed_aliases == [('alias_value',)]


def test_reports_equal_input_values_from_different_aliases() -> None:
    class FirstModel(BaseModel):
        x: int = Field(validation_alias=AliasChoices('first', 'second', 'x'))

    class SecondModel(BaseModel):
        model_config = {'populate_by_name': True}
        x: int = Field(validation_alias=AliasChoices('first', 'second', 'x'))

    _, first_report = FirstModel.model_validate({'first': 1, 'second': 1, 'x': 1}, validation_report=True)
    _, second_report = SecondModel.model_validate(
        {'second': 1, 'first': 1, 'x': 1},
        validation_report=True,
    )

    assert first_report.fields['x'].sources == [ValidationInputPath(('first',))]
    assert first_report.fields['x'].unconsumed_aliases == [('second',)]
    assert second_report.fields['x'].sources == [ValidationInputPath(('second',))]
    assert second_report.fields['x'].unconsumed_aliases == [('first',)]


def test_reports_alias_path_nested_models_and_lists() -> None:
    class Item(BaseModel):
        value: str

    class Model(BaseModel):
        items: list[Item] = Field(validation_alias=AliasPath('payload', 'items'))
        scalar: list[int] = Field(validation_alias=AliasChoices('numbers', AliasPath('payload', 'numbers')))

    _, report = Model.model_validate(
        {'payload': {'items': [{'value': 'a'}, {'value': 'b'}], 'numbers': [1, 2]}},
        validation_report=True,
    )

    assert report.fields['items'].sources == [ValidationInputPath(('payload', 'items'))]
    assert report.fields['items'].fields['0'].fields['value'].sources == [ValidationInputPath(('value',))]
    assert report.fields['scalar'].sources == [ValidationInputPath(('numbers',))]
    assert report.fields['scalar'].items[0].sources == [ValidationInputPath((0,))]
    assert report.fields['scalar'].unconsumed_aliases == [('payload', 'numbers')]


def test_reports_default_and_default_factory_without_rerunning() -> None:
    factory_calls = 0
    validator_calls = 0

    def factory() -> list[int]:
        nonlocal factory_calls
        factory_calls += 1
        return [factory_calls]

    class Model(BaseModel):
        static_value: int = 7
        factory_value: list[int] = Field(default_factory=factory)
        validated: int = 3

        @field_validator('validated')
        @classmethod
        def validate(cls, value: int) -> int:
            nonlocal validator_calls
            validator_calls += 1
            return value

    Model.model_validate({'validated': 3})
    _, report = Model.model_validate({'validated': 3}, validation_report=True)

    assert factory_calls == 2
    assert validator_calls == 2
    assert report.fields['static_value'].sources == [DefaultSource()]
    assert report.fields['factory_value'].sources == [DefaultFactorySource()]
    assert report.fields['validated'].sources == [ValidationInputPath(('validated',))]


def test_report_does_not_store_sensitive_values() -> None:
    class Model(BaseModel):
        password: str

    _, report = Model.model_validate({'password': 'super-secret'}, validation_report=True)

    assert 'super-secret' not in repr(report)
    assert report.fields['password'].sources == [ValidationInputPath(('password',))]


def test_reports_selected_union_branch() -> None:
    class Cat(BaseModel):
        type: Literal['cat']
        meow: str

    class Dog(BaseModel):
        type: Literal['dog']
        bark: str

    class Model(BaseModel):
        pet: Annotated[Cat | Dog, Discriminator('type')]

    _, report = Model.model_validate({'pet': {'type': 'dog', 'bark': 'woof'}}, validation_report=True)

    assert report.fields['pet'].union_choice == 1
    assert report.fields['pet'].fields['bark'].sources == [ValidationInputPath(('bark',))]
    with pytest.raises(KeyError):
        report.fields['pet'].fields['meow']
