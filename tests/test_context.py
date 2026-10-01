import asyncio
import threading
from typing import Dict, List

import pytest
from attrs import define

from cattrs import BaseConverter, Converter
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn, override


@define
class Inner:
    value: str


@define
class Outer:
    inner: Inner


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_context_is_passed_to_nested_hooks(converter_cls):
    converter = converter_cls()

    def unstructure_inner(inner, *, context):
        return f"{inner.value}@{context['timezone']}"

    converter.register_unstructure_hook(Inner, unstructure_inner)

    def structure_inner(data, _, *, context):
        return Inner(data.removesuffix(f"@{context['timezone']}"))

    converter.register_structure_hook(Inner, structure_inner)

    result = converter.unstructure(
        Outer(Inner("meeting")), context={"timezone": "Asia/Shanghai"}
    )
    assert result == {"inner": "meeting@Asia/Shanghai"}

    structured = converter.structure(
        result, Outer, context={"timezone": "Asia/Shanghai"}
    )
    assert structured == Outer(Inner("meeting"))


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_cached_hook_does_not_retain_previous_context(converter_cls):
    converter = converter_cls()
    seen = []

    def hook(value, *, context):
        seen.append(context)
        return value

    converter.register_unstructure_hook(str, hook)

    converter.unstructure("first", context={"timezone": "Europe/London"})
    converter.unstructure("second", context={"timezone": "Pacific/Auckland"})

    assert seen == [
        {"timezone": "Europe/London"},
        {"timezone": "Pacific/Auckland"},
    ]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_hook_factories_receive_context_without_caching_it(converter_cls):
    converter = converter_cls()
    seen = []

    def factory(cls):
        def hook(inner, _, *, context):
            seen.append(context)
            return cls(inner.upper())

        return hook

    converter.register_structure_hook_factory(lambda cls: cls is Inner, factory)

    assert converter.structure("value", Inner, context="first") == Inner("VALUE")
    assert converter.structure("other", Inner, context="second") == Inner("OTHER")
    assert seen == ["first", "second"]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_predicate_hooks_receive_context(converter_cls):
    converter = converter_cls()

    converter.register_unstructure_hook_func(
        lambda cls: cls is Inner, lambda inner, *, context: (inner.value, context)
    )

    assert converter.unstructure(Inner("value"), context="tenant") == (
        "value",
        "tenant",
    )


def test_generated_attribute_overrides_receive_context():
    @define
    class Configured:
        when: str

    converter = Converter()
    unstructure_fn = make_dict_unstructure_fn(
        Configured,
        converter,
        when=override(
            unstruct_hook=lambda value, *, context: f"{value}@{context['timezone']}"
        ),
    )
    structure_fn = make_dict_structure_fn(
        Configured,
        converter,
        when=override(
            struct_hook=lambda value,
            _,
            *,
            context: value.removesuffix(f"@{context['timezone']}"),
        ),
    )
    converter.register_unstructure_hook(Configured, unstructure_fn)
    converter.register_structure_hook(Configured, structure_fn)

    context = {"timezone": "Asia/Shanghai"}
    raw = converter.unstructure(Configured("10:00"), context=context)
    assert raw == {"when": "10:00@Asia/Shanghai"}
    assert converter.structure(raw, Configured, context=context) == Configured(
        "10:00"
    )


def test_generated_collections_pass_context_to_nested_hooks():
    converter = Converter()

    converter.register_unstructure_hook(
        Inner, lambda inner, *, context: f"{inner.value}@{context}"
    )
    converter.register_structure_hook(
        Inner, lambda value, _, *, context: Inner(value.removesuffix(f"@{context}"))
    )

    raw = converter.unstructure(
        {"items": [Inner("a"), Inner("b")]},
        unstructure_as=Dict[str, List[Inner]],
        context="tenant",
    )
    assert raw == {"items": ["a@tenant", "b@tenant"]}

    structured = converter.structure(
        raw, Dict[str, List[Inner]], context="tenant"
    )
    assert structured == {"items": [Inner("a"), Inner("b")]}


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_nested_conversion_restores_outer_context(converter_cls):
    converter = converter_cls()
    events = []

    def inner_hook(inner, *, context):
        events.append(("inner", context["timezone"]))
        converter.unstructure("nested", unstructure_as=str, context="inner")
        events.append(("inner-after", context["timezone"]))
        return inner.value

    def string_hook(value, *, context):
        events.append(("string", context))
        return value

    converter.register_unstructure_hook(Inner, inner_hook)
    converter.register_unstructure_hook(str, string_hook)

    converter.unstructure(Inner("outer"), context={"timezone": "UTC"})
    assert events == [
        ("inner", "UTC"),
        ("string", "inner"),
        ("inner-after", "UTC"),
    ]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_nested_conversion_without_context_argument_inherits_outer_context(
    converter_cls,
):
    converter = converter_cls()
    seen = []

    def inner_hook(inner, *, context):
        seen.append(context)
        converter.unstructure(inner.value, unstructure_as=str)
        return inner.value

    def string_hook(value, *, context):
        seen.append(context)
        return value

    converter.register_unstructure_hook(Inner, inner_hook)
    converter.register_unstructure_hook(str, string_hook)

    converter.unstructure(Inner("value"), context="outer")

    assert seen == ["outer", "outer"]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_optional_keyword_only_context_is_explicit(converter_cls):
    converter = converter_cls()

    converter.register_unstructure_hook(
        str, lambda value, *, context=None: (value, context)
    )
    converter.register_structure_hook(
        Inner, lambda value, cl, *, context=None: cl(f"{value}:{context}")
    )

    assert converter.unstructure("value", context="ignored") == (
        "value",
        "ignored",
    )
    assert converter.structure("value", Inner, context="ignored") == Inner(
        "value:ignored"
    )


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_required_context_hook_without_call_context_raises(converter_cls):
    converter = converter_cls()
    converter.register_unstructure_hook(str, lambda value, *, context: value)

    with pytest.raises(TypeError, match="context"):
        converter.unstructure("value")


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_context_named_positional_parameter_is_not_injected(converter_cls):
    converter = converter_cls()

    converter.register_structure_hook(
        Inner, lambda value, cl, context=None: cl(f"{value}:{context}")
    )

    assert converter.structure("value", Inner, context="ignored") == Inner(
        "value:None"
    )


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_context_is_restored_after_hook_exception(converter_cls):
    converter = converter_cls()

    def failing_hook(value, *, context):
        converter.unstructure("nested", unstructure_as=str, context="inner")
        raise RuntimeError(context)

    def string_hook(value, *, context):
        return value, context

    converter.register_unstructure_hook(int, failing_hook)
    converter.register_unstructure_hook(str, string_hook)

    with pytest.raises(RuntimeError, match="outer"):
        converter.unstructure(1, context="outer")

    assert converter.unstructure("after", context="next") == ("after", "next")


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_context_is_restored_when_nested_conversion_raises(converter_cls):
    converter = converter_cls()
    seen = []

    def inner_hook(inner, *, context):
        seen.append(context)
        try:
            converter.unstructure("nested", unstructure_as=str, context="inner")
        except RuntimeError:
            pass
        seen.append(context)
        return inner.value

    def failing_string_hook(value, *, context):
        raise RuntimeError(context)

    converter.register_unstructure_hook(Inner, inner_hook)
    converter.register_unstructure_hook(str, failing_string_hook)

    assert converter.unstructure(Inner("value"), context="outer") == "value"
    assert seen == ["outer", "outer"]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_context_is_isolated_between_threads(converter_cls):
    converter = converter_cls()
    barrier = threading.Barrier(2)
    results = {}

    def hook(value, *, context):
        barrier.wait(timeout=5)
        results[threading.get_ident()] = context
        return value

    converter.register_unstructure_hook(str, hook)

    first = threading.Thread(
        target=lambda: converter.unstructure("first", context="first")
    )
    second = threading.Thread(
        target=lambda: converter.unstructure("second", context="second")
    )

    first.start()
    second.start()
    first.join()
    second.join()

    assert set(results.values()) == {"first", "second"}


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_context_is_isolated_between_async_tasks(converter_cls):
    converter = converter_cls()
    barrier = threading.Barrier(2)
    enter = asyncio.Event()

    def hook(value, *, context):
        barrier.wait(timeout=5)
        return value, context

    converter.register_unstructure_hook(str, hook)

    async def worker(value, context):
        await enter.wait()
        return await asyncio.to_thread(converter.unstructure, value, context=context)

    async def main():
        tasks = [
            asyncio.create_task(worker("first", "first")),
            asyncio.create_task(worker("second", "second")),
        ]
        await asyncio.sleep(0)
        enter.set()
        return await asyncio.gather(*tasks)

    assert set(asyncio.run(main())) == {("first", "first"), ("second", "second")}


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_context_does_not_become_an_instance_attribute(converter_cls):
    converter = converter_cls()

    converter.register_unstructure_hook(Inner, lambda inner, *, context: inner.value)
    converter.unstructure(Inner("value"), context="tenant")

    assert not hasattr(Inner("value"), "context")
