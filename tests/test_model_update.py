"""Tests for `BaseModel.model_update`."""

from functools import cached_property

import pytest

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    RootModel,
    ValidationError,
    computed_field,
    field_validator,
    model_validator,
)


class Range(BaseModel):
    start: int
    end: int

    @model_validator(mode='after')
    def check_order(self):
        if self.start > self.end:
            raise ValueError('start must not exceed end')
        return self


def test_update_returns_new_validated_model():
    r = Range(start=1, end=5)

    updated = r.model_update({'start': 3, 'end': 10})

    assert updated is not r
    assert updated.start == 3
    assert updated.end == 10
    # the original instance is unchanged:
    assert r.start == 1
    assert r.end == 5


def test_update_validates_values():
    r = Range(start=1, end=5)

    with pytest.raises(ValidationError):
        r.model_update({'start': 'not an int'})

    assert r.start == 1


def test_update_cross_field_constraint_success():
    r = Range(start=1, end=5)

    # updating only `start` would violate the constraint, updating both at once is fine:
    updated = r.model_update({'start': 10, 'end': 20})

    assert updated.start == 10
    assert updated.end == 20


def test_update_cross_field_constraint_failure_is_atomic():
    r = Range(start=1, end=5)
    fields_set_before = set(r.__pydantic_fields_set__)
    dict_before = dict(r.__dict__)

    with pytest.raises(ValidationError):
        r.model_update({'start': 10})  # start > end in the candidate state

    assert r.start == 1
    assert r.end == 5
    assert r.__dict__ == dict_before
    assert r.__pydantic_fields_set__ == fields_set_before


def test_update_in_place():
    r = Range(start=1, end=5)

    result = r.model_update({'start': 2, 'end': 3}, in_place=True)

    assert result is r
    assert r.start == 2
    assert r.end == 3
    assert r.__pydantic_fields_set__ == {'start', 'end'}


def test_update_in_place_failure_is_atomic():
    r = Range(start=1, end=5)
    fields_set_before = set(r.__pydantic_fields_set__)

    with pytest.raises(ValidationError):
        r.model_update({'start': 10}, in_place=True)

    assert r.start == 1
    assert r.end == 5
    assert r.__pydantic_fields_set__ == fields_set_before


def test_update_fields_set_is_union_of_previous_and_updated():
    class M(BaseModel):
        a: int
        b: int = 5

    m = M(a=1)
    assert m.__pydantic_fields_set__ == {'a'}

    updated = m.model_update({'b': 9})
    assert updated.b == 9
    assert updated.__pydantic_fields_set__ == {'a', 'b'}
    # fields not explicitly set keep their current value and stay out of fields_set:
    updated = m.model_update({})
    assert updated.b == 5
    assert updated.__pydantic_fields_set__ == {'a'}


def test_update_failure_preserves_extra_and_private_attributes():
    class M(BaseModel):
        model_config = ConfigDict(extra='allow')

        x: int
        _cache: int = PrivateAttr(default=0)

    m = M(x=1, extra_key='a')
    m._cache = 42
    fields_set_before = set(m.__pydantic_fields_set__)

    with pytest.raises(ValidationError):
        m.model_update({'x': 'not an int'})

    assert m.x == 1
    assert m.__pydantic_extra__ == {'extra_key': 'a'}
    assert m.__pydantic_private__ == {'_cache': 42}
    assert m.__pydantic_fields_set__ == fields_set_before


def test_update_extra_allow():
    class M(BaseModel):
        model_config = ConfigDict(extra='allow')

        x: int

    m = M(x=1, foo='a')

    updated = m.model_update({'foo': 'b', 'bar': 2})
    assert updated.foo == 'b'
    assert updated.bar == 2
    assert updated.__pydantic_fields_set__ == {'x', 'foo', 'bar'}
    assert m.foo == 'a'
    assert not hasattr(m, 'bar')

    m.model_update({'foo': 'c'}, in_place=True)
    assert m.foo == 'c'


def test_update_extra_forbid():
    class M(BaseModel):
        model_config = ConfigDict(extra='forbid')

        x: int

    m = M(x=1)
    with pytest.raises(ValidationError):
        m.model_update({'unknown': 1})
    assert m.x == 1


def test_update_accepts_aliases_and_field_names():
    class M(BaseModel):
        x: int = Field(alias='X')
        y: int = Field(validation_alias=AliasChoices('Y', 'why'))

    m = M(X=1, Y=2)

    updated = m.model_update({'X': 10, 'why': 20})
    assert updated.x == 10
    assert updated.y == 20
    assert updated.__pydantic_fields_set__ == {'x', 'y'}

    # field names are accepted as well:
    updated = m.model_update({'x': 30, 'y': 40})
    assert updated.x == 30
    assert updated.y == 40


def test_update_passes_validation_context():
    class M(BaseModel):
        x: int

        @field_validator('x')
        @classmethod
        def check_max(cls, v, info):
            if info.context is not None and v > info.context.get('max', float('inf')):
                raise ValueError('too big')
            return v

    m = M(x=1)

    assert m.model_update({'x': 100}, context={'max': 200}).x == 100
    assert m.model_update({'x': 100}).x == 100

    with pytest.raises(ValidationError):
        m.model_update({'x': 100}, context={'max': 10})
    assert m.x == 1


def test_update_frozen_model_rejects_in_place():
    class M(BaseModel):
        model_config = ConfigDict(frozen=True)

        x: int

    m = M(x=1)

    with pytest.raises(ValidationError) as exc_info:
        m.model_update({'x': 2}, in_place=True)
    assert exc_info.value.errors()[0]['type'] == 'frozen_instance'
    assert m.x == 1

    # non-in-place updates are still allowed on frozen models:
    updated = m.model_update({'x': 2})
    assert updated.x == 2
    assert m.x == 1


def test_update_frozen_field_rejects_in_place():
    class M(BaseModel):
        x: int = Field(frozen=True)
        y: int

    m = M(x=1, y=2)

    with pytest.raises(ValidationError) as exc_info:
        m.model_update({'x': 10}, in_place=True)
    assert exc_info.value.errors()[0]['type'] == 'frozen_field'

    m.model_update({'y': 20}, in_place=True)
    assert m.y == 20


def test_update_clears_cached_computed_properties():
    class M(BaseModel):
        x: int
        y: int

        @computed_field
        @cached_property
        def total(self) -> int:
            return self.x + self.y

    m = M(x=1, y=2)
    assert m.total == 3
    assert 'total' in m.__dict__  # the value is now cached

    updated = m.model_update({'x': 10})
    assert updated.total == 12

    m.model_update({'x': 10}, in_place=True)
    assert 'total' not in m.__dict__  # the stale cache entry was dropped
    assert m.total == 12


def test_update_model_validator_mutations_apply_only_on_success():
    class M(BaseModel):
        x: int
        _doubled: int = PrivateAttr(default=0)

        @model_validator(mode='after')
        def double(self):
            self._doubled = self.x * 2
            return self

    m = M(x=1)
    assert m._doubled == 2

    updated = m.model_update({'x': 5})
    assert updated._doubled == 10
    # the original instance is not affected by the validator run on the candidate:
    assert m._doubled == 2

    m.model_update({'x': 7}, in_place=True)
    assert m._doubled == 14

    with pytest.raises(ValidationError):
        m.model_update({'x': 'not an int'}, in_place=True)
    assert m._doubled == 14


def test_update_preserves_private_attributes():
    class M(BaseModel):
        x: int
        _cache: int = PrivateAttr(default=0)

    m = M(x=1)
    m._cache = 42

    updated = m.model_update({'x': 2})
    assert updated._cache == 42

    m.model_update({'x': 3}, in_place=True)
    assert m._cache == 42


def test_update_root_model():
    class R(RootModel):
        root: int

    r = R(1)

    updated = r.model_update({'root': 2})
    assert updated.root == 2
    assert r.root == 1

    r.model_update({'root': 3}, in_place=True)
    assert r.root == 3

    with pytest.raises(ValueError, match='Unknown field'):
        r.model_update({'other': 1})


def test_update_values_are_validated_not_assigned():
    class M(BaseModel):
        x: int

    m = M(x=1)

    # input is validated/coerced, unlike `model_copy(update=...)`:
    updated = m.model_update({'x': '2'})
    assert updated.x == 2
    assert isinstance(updated.x, int)
