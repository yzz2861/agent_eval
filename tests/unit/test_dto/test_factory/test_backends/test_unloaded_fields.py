from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import pytest

from litestar.dto import DataclassDTO, DTOConfig
from litestar.dto._backend import DTOBackend
from litestar.exceptions.dto_exceptions import UnloadedFieldException
from litestar.serialization import encode_json
from litestar.typing import FieldDefinition


@dataclass
class NestedModel:
    a: int
    b: str


@dataclass
class Model:
    a: int
    b: Optional[str]
    nested: NestedModel
    nested_list: list[NestedModel] = field(default_factory=list)


def _mark_unloaded(instance: Any, *field_names: str) -> Any:
    instance.__unloaded_fields__ = set(field_names)
    return instance


class UnloadedAwareDTO(DataclassDTO[Model]):
    @classmethod
    def is_field_loaded(cls, instance: Any, field_name: str) -> bool:
        return field_name not in getattr(instance, "__unloaded_fields__", ())


def make_dto_factory(strategy: Any, use_experimental_dto_backend: bool) -> type[DataclassDTO]:
    class Factory(UnloadedAwareDTO):
        config = DTOConfig(
            unloaded_fields_strategy=strategy,
            experimental_codegen_backend=use_experimental_dto_backend,
        )
        model_type = Model

    return Factory


def make_backend(dto_factory: type[DataclassDTO], backend_cls: type[DTOBackend]) -> DTOBackend:
    return backend_cls(
        dto_factory=dto_factory,
        field_definition=FieldDefinition.from_annotation(Model),
        model_type=Model,
        wrapper_attribute_name=None,
        is_data_field=False,
        handler_id="test",
    )


def make_model(**kwargs: Any) -> Model:
    defaults: dict[str, Any] = {
        "a": 1,
        "b": "b",
        "nested": NestedModel(a=1, b="two"),
        "nested_list": [NestedModel(a=1, b="two")],
    }
    return Model(**{**defaults, **kwargs})


def test_omit_unloaded_field(use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(make_dto_factory("omit", use_experimental_dto_backend), backend_cls)
    model = _mark_unloaded(make_model(), "a")
    assert encode_json(backend.encode_data(model)) == (
        b'{"b":"b","nested":{"a":1,"b":"two"},"nested_list":[{"a":1,"b":"two"}]}'
    )


def test_loaded_none_is_not_unloaded(use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(make_dto_factory("omit", use_experimental_dto_backend), backend_cls)
    model = _mark_unloaded(make_model(b=None), "a")
    assert encode_json(backend.encode_data(model)) == (
        b'{"b":null,"nested":{"a":1,"b":"two"},"nested_list":[{"a":1,"b":"two"}]}'
    )


def test_raise_unloaded_field(use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(make_dto_factory("raise", use_experimental_dto_backend), backend_cls)
    model = _mark_unloaded(make_model(), "a")
    with pytest.raises(UnloadedFieldException) as exc_info:
        backend.encode_data(model)
    assert exc_info.value.field_path == "a"
    assert "a" in exc_info.value.detail


def test_omit_unloaded_nested_field(use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(make_dto_factory("omit", use_experimental_dto_backend), backend_cls)
    model = _mark_unloaded(make_model(), "nested")
    assert encode_json(backend.encode_data(model)) == b'{"a":1,"b":"b","nested_list":[{"a":1,"b":"two"}]}'


def test_nested_field_path_in_exception(use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(make_dto_factory("raise", use_experimental_dto_backend), backend_cls)
    model = make_model(nested=_mark_unloaded(NestedModel(a=1, b="two"), "b"))
    with pytest.raises(UnloadedFieldException) as exc_info:
        backend.encode_data(model)
    assert exc_info.value.field_path == "nested.b"


def test_nested_collection_field_path_in_exception(
    use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]
) -> None:
    backend = make_backend(make_dto_factory("raise", use_experimental_dto_backend), backend_cls)
    model = make_model(nested_list=[_mark_unloaded(NestedModel(a=1, b="two"), "b")])
    with pytest.raises(UnloadedFieldException) as exc_info:
        backend.encode_data(model)
    assert exc_info.value.field_path == "nested_list.b"


def test_omit_unloaded_field_in_nested_collection(
    use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]
) -> None:
    backend = make_backend(make_dto_factory("omit", use_experimental_dto_backend), backend_cls)
    model = make_model(nested_list=[_mark_unloaded(NestedModel(a=1, b="two"), "b")])
    assert encode_json(backend.encode_data(model)) == (
        b'{"a":1,"b":"b","nested":{"a":1,"b":"two"},"nested_list":[{"a":1}]}'
    )


def test_no_strategy_does_not_check_loaded_state(
    use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]
) -> None:
    backend = make_backend(make_dto_factory(None, use_experimental_dto_backend), backend_cls)
    model = _mark_unloaded(make_model(), "a")
    assert encode_json(backend.encode_data(model)) == (
        b'{"a":1,"b":"b","nested":{"a":1,"b":"two"},"nested_list":[{"a":1,"b":"two"}]}'
    )


def test_data_field_not_affected(use_experimental_dto_backend: bool, backend_cls: type[DTOBackend]) -> None:
    dto_factory = make_dto_factory("raise", use_experimental_dto_backend)
    backend = backend_cls(
        dto_factory=dto_factory,
        field_definition=FieldDefinition.from_annotation(Model),
        model_type=Model,
        wrapper_attribute_name=None,
        is_data_field=True,
        handler_id="test",
    )
    data = {"a": 1, "b": "b", "nested": {"a": 1, "b": "two"}, "nested_list": [{"a": 1, "b": "two"}]}
    assert backend.transfer_data_from_builtins(data) == make_model()
