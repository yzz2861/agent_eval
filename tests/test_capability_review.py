from io import BytesIO

import pytest

from jinja2 import DictLoader
from jinja2.bccache import BytecodeCache
from jinja2.capabilities import CapabilityReviewer
from jinja2.capabilities import UnknownDynamicCallError
from jinja2.sandbox import SandboxedEnvironment


class MemoryBytecodeCache(BytecodeCache):
    def __init__(self):
        self.values = {}

    def load_bytecode(self, bucket):
        data = self.values.get(bucket.key)
        if data is not None:
            bucket.bytecode_from_string(data)

    def dump_bytecode(self, bucket):
        out = BytesIO()
        bucket.write_bytecode(out)
        self.values[bucket.key] = out.getvalue()


def make_env(cache=None):
    return SandboxedEnvironment(
        loader=DictLoader(
            {
                "affected.html": "[{{ name | compliance_tag }}]",
                "other.html": "[{{ name | upper }}]",
                "lazy.html": "{% include child_name %}",
                "child.html": "child:{{ name | upper }}",
                "dynamic.html": "{{ callbacks[name]() }}",
            }
        ),
        bytecode_cache=cache,
    )


def test_filter_replacement_only_invalidates_affected_template():
    cache = MemoryBytecodeCache()
    env = make_env(cache)
    env.filters["compliance_tag"] = lambda value: f"safe:{value}"

    affected = env.review_capabilities("affected.html")
    other = env.review_capabilities("other.html")
    env.approve_capabilities(report=affected)
    env.approve_capabilities(report=other)

    assert affected.filter_bindings["compliance_tag"].obj is env.filters["compliance_tag"]
    assert env.render_reviewed("affected.html", name="a") == "[safe:a]"
    assert env.render_reviewed("other.html", name="b") == "[B]"
    assert len(cache.values) == 2

    def test_double(value):
        return f"double:{value}"

    env.filters["compliance_tag"] = test_double

    changed = env.review_capabilities("affected.html")
    unchanged = env.review_capabilities("other.html")
    assert changed.requires_review
    assert changed.changed_filters == ("compliance_tag",)
    assert unchanged.approved
    assert env.capability_reviewer.is_approved("other.html")

    audit = env.capability_reviewer.recheck_all()
    assert "affected.html" in audit.changed
    assert "other.html" in audit.stable
    assert env.render_reviewed("other.html", name="still") == "[STILL]"

    with pytest.raises(Exception):
        env.render_reviewed("affected.html", name="a")

    reviewed = env.approve_capabilities("affected.html")
    assert reviewed.approved
    assert env.render_reviewed("affected.html", name="a") == "[double:a]"


def test_overlay_same_named_filter_uses_effective_callable():
    env = SandboxedEnvironment()
    env.filters["label"] = lambda value: f"base:{value}"
    overlay = env.overlay()
    overlay.filters = {**env.filters, "label": lambda value: f"overlay:{value}"}

    base_report = env.review_capabilities(source="{{ x | label }}", name="x.html")
    overlay_report = overlay.review_capabilities(
        source="{{ x | label }}", name="x.html"
    )

    assert base_report.filters["label"]("v") == "base:v"
    assert overlay_report.filters["label"]("v") == "overlay:v"
    assert overlay_report.changed_filters == ("label",)


def test_lazy_template_reference_is_recorded_and_runtime_resolution_works():
    env = make_env()
    report = env.review_capabilities("lazy.html")
    assert len(report.lazy_references) == 1
    assert report.lazy_references[0].dynamic

    env.approve_capabilities(report=report)
    result = env.render_reviewed(
        "lazy.html", child_name="child.html", name="ok"
    )
    assert result == "child:OK"


def test_unknown_dynamic_call_is_not_approved_by_default():
    env = make_env()
    report = env.review_capabilities("dynamic.html")
    assert len(report.unknown_dynamic_calls) == 1

    with pytest.raises(UnknownDynamicCallError):
        env.approve_capabilities(report=report)

    safe_reviewer = CapabilityReviewer(env, allow_unknown_dynamic_calls=True)
    approved = safe_reviewer.approve(
        source="{{ run() }}", name="context-dynamic.html"
    )

    def run():
        return "ran"

    assert safe_reviewer.render(
        "context-dynamic.html", context={"run": run}
    ) == "ran"


def test_shared_registry_survives_new_backend_environment():
    cache = MemoryBytecodeCache()
    registry = None
    first = make_env(cache)
    registry = first.capability_registry
    first.filters["compliance_tag"] = lambda value: f"one:{value}"
    report = first.review_capabilities("affected.html")
    first.approve_capabilities(report=report)
    assert first.render_reviewed("affected.html", name="x") == "[one:x]"

    second = make_env(cache)
    second.capability_registry = registry
    second.capability_reviewer = CapabilityReviewer(second, registry=registry)
    second.filters["compliance_tag"] = lambda value: f"two:{value}"

    changed = second.review_capabilities("affected.html")
    assert changed.changed_filters == ("compliance_tag",)
    other = second.review_capabilities("other.html")
    assert not other.approved  # never approved in first environment
