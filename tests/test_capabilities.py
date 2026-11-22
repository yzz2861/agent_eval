import pytest
from jinja2 import DictLoader
from jinja2.bccache import FileSystemBytecodeCache
from jinja2.exceptions import CapabilityReviewRequired
from jinja2.exceptions import UnapprovedCapability
from jinja2.sandbox import SandboxedEnvironment


def _double(value):
    return value * 2


def test_manifest_records_compiled_dependencies():
    env = SandboxedEnvironment(
        loader=DictLoader(
            {
                "parent": '{% include "child" %}{{ 1|custom }}{{ 1 is even }}',
                "child": "child",
            }
        )
    )
    env.filters["custom"] = _double
    env.tests["even"] = lambda value: value % 2 == 0
    template = env.get_template("parent")
    manifest = template.capability_manifest
    assert manifest.filters["custom"]
    assert manifest.tests["even"]
    assert manifest.templates == ["child"]


def test_changed_filter_requires_review_and_rebinds():
    env = SandboxedEnvironment()
    env.filters["custom"] = _double
    template = env.from_string("{{ 1|custom }}")
    assert template.render() == "2"
    template.render()

    def replacement(value):
        return "replacement-" + str(value)

    env.filters["custom"] = replacement

    with pytest.raises(CapabilityReviewRequired):
        template.render()

    review = env.review_capabilities(template)
    assert review.approved
    assert [cap.key for cap in review.changed] == ["filter:custom"]
    assert not review.pending
    assert template.render() == "replacement-1"


def test_unrelated_template_keeps_working_after_filter_change():
    env = SandboxedEnvironment()
    env.filters["custom"] = _double
    changed = env.from_string("{{ 1|custom }}")
    unrelated = env.from_string("plain {{ 1 + 1 }}")
    assert changed.render() == "2"
    assert unrelated.render() == "plain 2"
    env.filters["custom"] = lambda value: "changed"

    with pytest.raises(CapabilityReviewRequired):
        changed.render()

    assert unrelated.render() == "plain 2"


def test_shared_bytecode_cache_rechecks_only_affected_template(tmp_path):
    cache = FileSystemBytecodeCache(str(tmp_path))
    sources = {
        "affected": "{{ 1|custom }}",
        "unrelated": "{{ 1 + 1 }}",
    }
    first = SandboxedEnvironment(loader=DictLoader(sources), bytecode_cache=cache)
    first.filters["custom"] = _double
    assert first.get_template("affected").render() == "2"
    assert first.get_template("unrelated").render() == "2"

    refreshed = SandboxedEnvironment(loader=DictLoader(sources), bytecode_cache=cache)
    refreshed.filters["custom"] = lambda value: "new-" + str(value)
    affected = refreshed.get_template("affected")
    unrelated = refreshed.get_template("unrelated")

    assert unrelated.render() == "2"

    with pytest.raises(CapabilityReviewRequired):
        affected.render()

    assert refreshed.review_capabilities(affected).approved
    assert affected.render() == "new-1"
    assert unrelated.render() == "2"


def test_overlay_rebinds_same_named_filter(tmp_path):
    cache = FileSystemBytecodeCache(str(tmp_path))
    base = SandboxedEnvironment(
        loader=DictLoader({"page": "{{ 1|custom }}", "other": "other"}),
        bytecode_cache=cache,
    )
    base.filters["custom"] = _double
    assert base.get_template("page").render() == "2"

    overlay = base.overlay()
    overlay.filters["custom"] = lambda value: "overlay-" + str(value)
    page = overlay.get_template("page")
    other = overlay.get_template("other")

    with pytest.raises(CapabilityReviewRequired):
        page.render()

    assert other.render() == "other"
    assert overlay.review_capabilities(page).approved
    assert page.render() == "overlay-1"
    assert base.get_template("page").render() == "2"


def test_delayed_include_is_reviewed_when_resolved():
    env = SandboxedEnvironment(
        loader=DictLoader(
            {"parent": "P[{% include name %}]", "child": "C{{ 1|custom }}"}
        )
    )
    env.filters["custom"] = _double
    parent = env.get_template("parent")
    assert parent.capability_manifest.dynamic_templates == ["include"]
    assert parent.render(name="child") == "P[C2]"

    env.filters["custom"] = lambda value: "changed"

    with pytest.raises(CapabilityReviewRequired):
        parent.render(name="child")

    child = env.get_template("child")
    assert env.review_capabilities(child).approved
    assert parent.render(name="child") == "P[Cchanged]"


def test_unknown_dynamic_call_is_denied_until_reviewed():
    env = SandboxedEnvironment()
    template = env.from_string("{{ handler() }}")
    assert template.render(handler=lambda: "before") == "before"
    assert env.review_capabilities(template).approved

    with pytest.raises(UnapprovedCapability):
        template.render(handler=lambda: "after")


def test_reviewer_can_approve_dynamic_call():
    seen = []

    def reviewer(review):
        seen.append([cap.key for cap in review.pending])
        review.approve()
        return True

    env = SandboxedEnvironment()
    env.capability_reviewer = reviewer
    template = env.from_string("{{ handler() }}")
    assert template.render(handler=lambda: "ok") == "ok"
    assert seen


def test_macro_calls_are_internal_capabilities():
    env = SandboxedEnvironment()
    template = env.from_string("{% macro hi() %}hi{% endmacro %}{{ hi() }}")
    assert env.review_capabilities(template).approved
    assert template.render() == "hi"


def test_reviewer_sees_same_name_changed_binding():
    reviews = []

    def reviewer(review):
        reviews.append([cap.key for cap in review.changed])
        review.approve()
        return True

    env = SandboxedEnvironment()
    env.capability_reviewer = reviewer
    env.filters["custom"] = _double
    template = env.from_string("{{ 1|custom }}")
    assert template.render() == "2"
    env.filters["custom"] = lambda value: "changed"
    assert template.render() == "changed"
    assert reviews[-1] == ["filter:custom"]


def test_denied_review_blocks_render():
    env = SandboxedEnvironment()
    env.filters["custom"] = _double
    template = env.from_string("{{ 1|custom }}")
    with pytest.raises(CapabilityReviewRequired):
        env.review_capabilities(template, reviewer=lambda review: False)


def test_strict_mode_requires_explicit_review():
    env = SandboxedEnvironment()
    env.require_capability_review = True
    template = env.from_string("ok")
    with pytest.raises(CapabilityReviewRequired):
        template.render()
    assert env.review_capabilities(template).approved
    assert template.render() == "ok"


def test_changed_test_requires_review():
    env = SandboxedEnvironment()
    env.tests["even"] = lambda value: value % 2 == 0
    template = env.from_string("{{ 2 is even }}")
    assert template.render() == "True"
    env.tests["even"] = lambda value: False
    with pytest.raises(CapabilityReviewRequired):
        template.render()
    assert env.review_capabilities(template).approved
    assert template.render() == "False"


def test_capability_policy_allow_list():
    from jinja2 import CapabilityPolicy

    env = SandboxedEnvironment()
    policy = CapabilityPolicy()
    policy.allow("filter:custom")
    env.capability_policy = policy
    env.filters["custom"] = _double
    template = env.from_string("{{ 1|custom }}")
    assert template.render() == "2"


def test_template_review_alias():
    env = SandboxedEnvironment()
    env.filters["custom"] = _double
    template = env.from_string("{{ 1|custom }}")
    review = template.review_capabilities()
    assert review.approved
    assert template.dependencies["filters"]["custom"]
