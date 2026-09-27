from functools import cached_property

import pytest

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, RootModel, ValidationError, model_validator


class Range(BaseModel):
    start: int
    end: int

    @model_validator(mode='after')
    def _check_order(self):
        if self.start > self.end:
            raise ValueError('start must not exceed end')
        return self


def test_model_update_returns_new_model():
    r = Range(start=1, end=5)
    updated = r.model_update({'start': 3, 'end': 4})

    assert updated is not r
    assert (updated.start, updated.end) == (3, 4)
    assert updated.model_fields_set == {'start', 'end'}
    # The original instance is untouched:
    assert (r.start, r.end) == (1, 5)
    assert r.model_fields_set == {'start', 'end'}


def test_model_update_cross_field_validation_atomic():
    r = Range(start=1, end=5)

    # Jointly valid update succeeds in one call, even though each individual
    # value would violate the cross-field constraint against the old state:
    updated = r.model_update({'start': 10, 'end': 20})
    assert (updated.start, updated.end) == (10, 20)

    # A jointly invalid update fails and leaves everything untouched:
    with pytest.raises(ValidationError):
        r.model_update({'start': 10, 'end': 2})
    assert (r.start, r.end) == (1, 5)
    assert r.model_fields_set == {'start', 'end'}


def test_model_update_fields_set_preserved_on_failure():
    class M(BaseModel):
        a: int
        b: int = 0

    m = M(a=1)
    assert m.model_fields_set == {'a'}

    with pytest.raises(ValidationError):
        m.model_update({'a': 'not an int', 'b': 2})

    assert m.model_fields_set == {'a'}
    assert m.a == 1
    assert m.b == 0

    m2 = m.model_update({'b': 2})
    assert m2.model_fields_set == {'a', 'b'}


def test_model_update_inplace():
    r = Range(start=1, end=5)
    result = r.model_update({'start': 2, 'end': 9}, inplace=True)

    assert result is r
    assert (r.start, r.end) == (2, 9)
    assert r.model_fields_set == {'start', 'end'}


def test_model_update_inplace_failure_leaves_instance_untouched():
    class M(BaseModel):
        model_config = ConfigDict(extra='allow')

        a: int
        _priv = PrivateAttr(default=0)

    m = M(a=1, extra_stuff='x')
    m._priv = 42
    fields_set_before = set(m.model_fields_set)

    with pytest.raises(ValidationError):
        m.model_update({'a': 'not an int'}, inplace=True)

    assert m.a == 1
    assert m.__pydantic_extra__ == {'extra_stuff': 'x'}
    assert m._priv == 42
    assert m.model_fields_set == fields_set_before


def test_model_update_inplace_frozen_rejected():
    class M(BaseModel):
        model_config = ConfigDict(frozen=True)

        a: int

    m = M(a=1)
    with pytest.raises(ValidationError) as exc_info:
        m.model_update({'a': 2}, inplace=True)
    assert exc_info.value.errors()[0]['type'] == 'frozen_instance'
    assert m.a == 1

    # Non-inplace updates are still allowed on frozen models:
    assert m.model_update({'a': 2}).a == 2


def test_model_update_alias():
    class M(BaseModel):
        x: int = Field(alias='XAlias')

    m = M(XAlias=1)
    updated = m.model_update({'XAlias': 3})
    assert updated.x == 3
    assert updated.model_fields_set == {'x'}

    # Revalidation preserves aliases, so round-tripping the current state works:
    assert updated.model_dump(by_alias=True) == {'XAlias': 3}


def test_model_update_validation_alias_choices():
    from pydantic import AliasChoices

    class M(BaseModel):
        x: int = Field(validation_alias=AliasChoices('x1', 'x2'))

    m = M(x1=1)
    updated = m.model_update({'x2': 5})
    assert updated.x == 5
    assert updated.model_fields_set == {'x'}


def test_model_update_context():
    class M(BaseModel):
        a: int

        @model_validator(mode='after')
        def _check_context(self, info):
            if info.context and self.a > info.context.get('max', 10):
                raise ValueError('too big')
            return self

    m = M(a=5)
    assert m.model_update({'a': 8}, context={'max': 10}).a == 8
    with pytest.raises(ValidationError):
        m.model_update({'a': 8}, context={'max': 6})
    assert m.a == 5


def test_model_update_cached_property_not_stale():
    class M(BaseModel):
        a: int

        @cached_property
        def double(self):
            return self.a * 2

    m = M(a=2)
    assert m.double == 4
    assert 'double' in m.__dict__

    updated = m.model_update({'a': 5})
    assert 'double' not in updated.__dict__
    assert updated.double == 10

    m.model_update({'a': 7}, inplace=True)
    assert 'double' not in m.__dict__
    assert m.double == 14


def test_model_update_model_validator_mutations_only_on_success():
    class M(BaseModel):
        a: int
        b: int = 0

        @model_validator(mode='after')
        def _mutate(self):
            self.b = self.a * 10
            if self.a < 0:
                raise ValueError('negative')
            return self

    m = M(a=1)
    assert m.b == 10

    updated = m.model_update({'a': 2})
    assert updated.b == 20

    with pytest.raises(ValidationError):
        m.model_update({'a': -1}, inplace=True)
    # The validator's mutation of the candidate did not leak into the original:
    assert (m.a, m.b) == (1, 10)


def test_model_update_extra_allow():
    class M(BaseModel):
        model_config = ConfigDict(extra='allow')

        a: int

    m = M(a=1, old='kept')
    updated = m.model_update({'a': 2, 'new': 'added'})
    assert updated.__pydantic_extra__ == {'old': 'kept', 'new': 'added'}
    assert 'new' in updated.model_fields_set
    assert m.__pydantic_extra__ == {'old': 'kept'}


def test_model_update_extra_forbid_failure_atomic():
    class M(BaseModel):
        model_config = ConfigDict(extra='forbid')

        a: int

    m = M(a=1)
    with pytest.raises(ValidationError):
        m.model_update({'a': 2, 'unknown': 1}, inplace=True)
    assert m.a == 1
    assert m.model_fields_set == {'a'}


def test_model_update_private_attributes_carried_to_new_instance():
    class M(BaseModel):
        a: int
        _priv = PrivateAttr(default=0)

    m = M(a=1)
    m._priv = 42

    updated = m.model_update({'a': 2})
    assert updated._priv == 42

    m.model_update({'a': 3}, inplace=True)
    assert m._priv == 42


def test_model_update_defaults_not_in_fields_set():
    class M(BaseModel):
        a: int
        b: int = 5

    m = M(a=1)
    updated = m.model_update({'a': 2})
    # Defaulted fields keep their value and stay out of `fields_set`:
    assert updated.b == 5
    assert updated.model_fields_set == {'a'}


def test_model_update_root_model():
    class R(RootModel[int]):
        pass

    r = R(1)
    updated = r.model_update({'root': 5})
    assert updated.root == 5
    assert updated.model_fields_set == {'root'}
    assert r.root == 1

    r.model_update({'root': 7}, inplace=True)
    assert r.root == 7

    with pytest.raises(ValidationError):
        r.model_update({'root': 'not an int'})
    assert r.root == 7

    with pytest.raises(ValidationError):
        r.model_update({'other': 1})
