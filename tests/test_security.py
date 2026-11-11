import pytest
from jinja2 import Environment
from jinja2.exceptions import SecurityError
from jinja2.exceptions import TemplateRuntimeError
from jinja2.exceptions import TemplateSyntaxError
from jinja2.exceptions import UndefinedError
from jinja2.nodes import EvalContext
from jinja2.runtime import ChainableUndefined
from jinja2.sandbox import ATTRIBUTE_REASON_MISSING
from jinja2.sandbox import ATTRIBUTE_REASON_POLICY_DENIED
from jinja2.sandbox import ATTRIBUTE_REASON_UNRENDERABLE
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2.sandbox import SandboxedEnvironment
from jinja2.sandbox import unsafe
from markupsafe import escape


class PrivateStuff:
    def bar(self):
        return 23

    @unsafe
    def foo(self):
        return 42

    def __repr__(self):
        return "PrivateStuff"


class PublicStuff:
    def bar(self):
        return 23

    def _foo(self):
        return 42

    def __repr__(self):
        return "PublicStuff"


class TestSandbox:
    def test_unsafe(self, env):
        env = SandboxedEnvironment()
        pytest.raises(
            SecurityError, env.from_string("{{ foo.foo() }}").render, foo=PrivateStuff()
        )
        assert env.from_string("{{ foo.bar() }}").render(foo=PrivateStuff()) == "23"

        pytest.raises(
            SecurityError, env.from_string("{{ foo._foo() }}").render, foo=PublicStuff()
        )
        assert env.from_string("{{ foo.bar() }}").render(foo=PublicStuff()) == "23"
        assert env.from_string("{{ foo.__class__ }}").render(foo=42) == ""
        assert env.from_string("{{ foo.func_code }}").render(foo=lambda: None) == ""
        # security error comes from __class__ already.
        pytest.raises(
            SecurityError,
            env.from_string("{{ foo.__class__.__subclasses__() }}").render,
            foo=42,
        )

    def test_immutable_environment(self, env):
        env = ImmutableSandboxedEnvironment()
        pytest.raises(SecurityError, env.from_string("{{ [].append(23) }}").render)
        pytest.raises(SecurityError, env.from_string("{{ [].clear() }}").render)
        pytest.raises(SecurityError, env.from_string("{{ [1].pop() }}").render)
        pytest.raises(SecurityError, env.from_string("{{ {1:2}.clear() }}").render)

    def test_restricted(self, env):
        env = SandboxedEnvironment()
        pytest.raises(
            TemplateSyntaxError,
            env.from_string,
            "{% for item.attribute in seq %}...{% endfor %}",
        )
        pytest.raises(
            TemplateSyntaxError,
            env.from_string,
            "{% for foo, bar.baz in seq %}...{% endfor %}",
        )

    def test_template_data(self, env):
        env = Environment(autoescape=True)
        t = env.from_string(
            "{% macro say_hello(name) %}"
            "<p>Hello {{ name }}!</p>{% endmacro %}"
            '{{ say_hello("<blink>foo</blink>") }}'
        )
        escaped_out = "<p>Hello &lt;blink&gt;foo&lt;/blink&gt;!</p>"
        assert t.render() == escaped_out
        assert str(t.module) == escaped_out
        assert escape(t.module) == escaped_out
        assert t.module.say_hello("<blink>foo</blink>") == escaped_out
        assert (
            escape(t.module.say_hello(EvalContext(env), "<blink>foo</blink>"))
            == escaped_out
        )
        assert escape(t.module.say_hello("<blink>foo</blink>")) == escaped_out

    def test_attr_filter(self, env):
        env = SandboxedEnvironment()
        tmpl = env.from_string('{{ cls|attr("__subclasses__")() }}')
        pytest.raises(SecurityError, tmpl.render, cls=int)

    def test_binary_operator_intercepting(self, env):
        def disable_op(left, right):
            raise TemplateRuntimeError("that operator so does not work")

        for expr, ctx, rv in ("1 + 2", {}, "3"), ("a + 2", {"a": 2}, "4"):
            env = SandboxedEnvironment()
            env.binop_table["+"] = disable_op
            t = env.from_string(f"{{{{ {expr} }}}}")
            assert t.render(ctx) == rv
            env.intercepted_binops = frozenset(["+"])
            t = env.from_string(f"{{{{ {expr} }}}}")
            with pytest.raises(TemplateRuntimeError):
                t.render(ctx)

    def test_unary_operator_intercepting(self, env):
        def disable_op(arg):
            raise TemplateRuntimeError("that operator so does not work")

        for expr, ctx, rv in ("-1", {}, "-1"), ("-a", {"a": 2}, "-2"):
            env = SandboxedEnvironment()
            env.unop_table["-"] = disable_op
            t = env.from_string(f"{{{{ {expr} }}}}")
            assert t.render(ctx) == rv
            env.intercepted_unops = frozenset(["-"])
            t = env.from_string(f"{{{{ {expr} }}}}")
            with pytest.raises(TemplateRuntimeError):
                t.render(ctx)


class TestStringFormat:
    def test_basic_format_safety(self):
        env = SandboxedEnvironment()
        t = env.from_string('{{ "a{0.__class__}b".format(42) }}')
        assert t.render() == "ab"

    def test_basic_format_all_okay(self):
        env = SandboxedEnvironment()
        t = env.from_string('{{ "a{0.foo}b".format({"foo": 42}) }}')
        assert t.render() == "a42b"

    def test_safe_format_safety(self):
        env = SandboxedEnvironment()
        t = env.from_string('{{ ("a{0.__class__}b{1}"|safe).format(42, "<foo>") }}')
        assert t.render() == "ab&lt;foo&gt;"

    def test_safe_format_all_okay(self):
        env = SandboxedEnvironment()
        t = env.from_string('{{ ("a{0.foo}b{1}"|safe).format({"foo": 42}, "<foo>") }}')
        assert t.render() == "a42b&lt;foo&gt;"

    def test_empty_braces_format(self):
        env = SandboxedEnvironment()
        t1 = env.from_string('{{ ("a{}b{}").format("foo", "42")}}')
        t2 = env.from_string('{{ ("a{}b{}"|safe).format(42, "<foo>") }}')
        assert t1.render() == "afoob42"
        assert t2.render() == "a42b&lt;foo&gt;"


class TestStringFormatMap:
    def test_basic_format_safety(self):
        env = SandboxedEnvironment()
        t = env.from_string('{{ "a{x.__class__}b".format_map({"x":42}) }}')
        assert t.render() == "ab"

    def test_basic_format_all_okay(self):
        env = SandboxedEnvironment()
        t = env.from_string('{{ "a{x.foo}b".format_map({"x":{"foo": 42}}) }}')
        assert t.render() == "a42b"

    def test_safe_format_all_okay(self):
        env = SandboxedEnvironment()
        t = env.from_string(
            '{{ ("a{x.foo}b{y}"|safe).format_map({"x":{"foo": 42}, "y":"<foo>"}) }}'
        )
        assert t.render() == "a42b&lt;foo&gt;"

    def test_indirect_call(self):
        def run(value, arg):
            return value.run(arg)

        env = SandboxedEnvironment()
        env.filters["run"] = run
        t = env.from_string(
            """{% set
                ns = namespace(run="{0.__call__.__builtins__[__import__]}".format)
            %}
            {{ ns | run(not_here) }}
            """
        )

        with pytest.raises(SecurityError):
            t.render()


class TestStrictAttributeChecking:
    def test_property_side_effect_is_not_triggered_when_denied(self):
        class Billing:
            getter_calls = 0

            @property
            def _billing(self):
                type(self).getter_calls += 1
                return "secret-query-result"

            @property
            def plan(self):
                type(self).getter_calls += 1
                return "enterprise"

        env = SandboxedEnvironment(strict_attribute_checking=True)
        billing = Billing()

        undefined = env.getattr(billing, "_billing")
        assert undefined.reason_code == ATTRIBUTE_REASON_POLICY_DENIED
        assert Billing.getter_calls == 0

        assert env.from_string("{{ billing._billing }}").render(billing=billing) == ""
        assert Billing.getter_calls == 0

        assert (
            env.from_string('{{ "{0._billing}".format(billing) }}').render(
                billing=billing
            )
            == ""
        )
        assert (
            env.from_string('{{ "{x._billing}".format_map({"x": billing}) }}').render(
                billing=billing
            )
            == ""
        )
        assert Billing.getter_calls == 0

        assert env.getattr(billing, "plan") == "enterprise"
        assert Billing.getter_calls == 1

    def test_cached_property_is_checked_before_resolution(self):
        from functools import cached_property

        class Cached:
            denied_calls = 0
            allowed_calls = 0

            @cached_property
            def _billing(self):
                type(self).denied_calls += 1
                return "secret"

            @cached_property
            def public(self):
                type(self).allowed_calls += 1
                return "value"

        env = SandboxedEnvironment(strict_attribute_checking=True)
        cached = Cached()

        assert env.getattr(cached, "_billing").reason_code == (
            ATTRIBUTE_REASON_POLICY_DENIED
        )
        assert Cached.denied_calls == 0
        assert env.getattr(cached, "public") == "value"
        assert Cached.allowed_calls == 1
        assert env.getattr(cached, "public") == "value"
        assert Cached.allowed_calls == 1

    def test_instance_attribute_shadows_class_attribute(self):
        class Shadowed:
            value = "class-value"

        shadowed = Shadowed()
        shadowed.value = "instance-value"
        env = SandboxedEnvironment(strict_attribute_checking=True)

        assert env.getattr(shadowed, "value") == "instance-value"

    def test_instance_attribute_shadows_dynamic_fallback(self):
        class Dynamic:
            calls = 0

            def __getattr__(self, name):
                type(self).calls += 1
                return "dynamic-value"

        dynamic = Dynamic()
        dynamic.__dict__["value"] = "instance-value"
        env = SandboxedEnvironment(strict_attribute_checking=True)

        assert env.getattr(dynamic, "value") == "instance-value"
        assert Dynamic.calls == 0

    def test_property_data_descriptor_keeps_python_precedence(self):
        class Described:
            getter_calls = 0

            @property
            def value(self):
                type(self).getter_calls += 1
                return "property-value"

        described = Described()
        described.__dict__["value"] = "instance-value"
        env = SandboxedEnvironment(strict_attribute_checking=True)

        assert env.getattr(described, "value") == "property-value"
        assert Described.getter_calls == 1

    def test_descriptor_chain_is_classified_before_resolution(self):
        class TrackingDescriptor:
            calls = 0

            def __get__(self, obj, owner=None):
                type(self).calls += 1
                return "descriptor-value"

        class Described:
            public = TrackingDescriptor()
            _private = TrackingDescriptor()

        env = SandboxedEnvironment(strict_attribute_checking=True)
        described = Described()

        assert env.getattr(described, "_private").reason_code == (
            ATTRIBUTE_REASON_POLICY_DENIED
        )
        assert TrackingDescriptor.calls == 0
        assert env.getattr(described, "public") == "descriptor-value"
        assert TrackingDescriptor.calls == 1

    def test_dynamic_proxy_denies_getattr_and_getitem_consistently(self):
        class LazyProxy:
            def __init__(self):
                self.calls = []

            def __getattr__(self, name):
                self.calls.append(("getattr", name))
                if name == "_billing":
                    return "secret"

                return f"value-{name}"

            def __getitem__(self, name):
                self.calls.append(("getitem", name))
                if name == "_billing":
                    return "secret"

                return f"value-{name}"

        env = SandboxedEnvironment(strict_attribute_checking=True)
        proxy = LazyProxy()

        for lookup in (
            lambda: env.getattr(proxy, "_billing"),
            lambda: env.getitem(proxy, "_billing"),
        ):
            result = lookup()
            assert result.reason_code == ATTRIBUTE_REASON_POLICY_DENIED

        assert proxy.calls == []
        assert env.getattr(proxy, "public") == "value-public"
        assert env.getitem(proxy, "public") == "value-public"

    def test_dynamic_proxy_exception_message_is_not_exposed(self):
        class ExplodingProxy:
            def __getattr__(self, name):
                raise RuntimeError("sensitive proxy failure")

        env = SandboxedEnvironment(strict_attribute_checking=True)
        proxy = ExplodingProxy()
        undefined = env.getattr(proxy, "public")

        assert undefined.reason_code == ATTRIBUTE_REASON_UNRENDERABLE

        with pytest.raises(UndefinedError) as exc_info:
            env.from_string("{{ proxy.public() }}").render(proxy=proxy)

        assert exc_info.value.reason_code == ATTRIBUTE_REASON_UNRENDERABLE
        assert "sensitive proxy failure" not in str(exc_info.value)
        assert repr(proxy) not in str(exc_info.value)

    def test_missing_and_unrenderable_have_distinct_reasons(self):
        class Broken:
            @property
            def value(self):
                raise ValueError("sensitive value failure")

        env = SandboxedEnvironment(strict_attribute_checking=True)
        broken = Broken()

        assert env.getattr(object(), "missing").reason_code == (
            ATTRIBUTE_REASON_MISSING
        )
        assert env.getattr(broken, "value").reason_code == (
            ATTRIBUTE_REASON_UNRENDERABLE
        )

        with pytest.raises(UndefinedError) as exc_info:
            env.from_string("{{ broken.value() }}").render(broken=broken)

        assert exc_info.value.reason_code == ATTRIBUTE_REASON_UNRENDERABLE
        assert "sensitive value failure" not in str(exc_info.value)

    def test_chainable_undefined_keeps_reason_for_denied_access(self):
        class Billing:
            calls = 0

            @property
            def _billing(self):
                type(self).calls += 1
                return "secret"

        env = SandboxedEnvironment(
            strict_attribute_checking=True, undefined=ChainableUndefined
        )
        billing = Billing()
        result = env.getattr(billing, "_billing")

        assert isinstance(result, ChainableUndefined)
        assert result.reason_code == ATTRIBUTE_REASON_POLICY_DENIED
        assert result.other["nested"].deeper is result
        assert (
            env.from_string("{{ billing._billing.other.nested }}").render(
                billing=billing
            )
            == ""
        )
        assert Billing.calls == 0

    def test_allowed_values_and_format_wrappers_still_work(self):
        class Allowed:
            public = "class-value"

            @property
            def computed(self):
                return "computed-value"

        env = SandboxedEnvironment(strict_attribute_checking=True)
        allowed = Allowed()

        assert env.getattr(allowed, "public") == "class-value"
        assert env.getattr(allowed, "computed") == "computed-value"
        assert env.getitem({"public": "item-value"}, "public") == "item-value"
        assert env.getitem({"_private": "hidden"}, "_private").reason_code == (
            ATTRIBUTE_REASON_POLICY_DENIED
        )

        assert env.from_string('{{ "a{0.__class__}b".format(42) }}').render() == "ab"
        assert (
            env.from_string('{{ "a{0.public}b".format({"public": 42}) }}').render()
            == "a42b"
        )
        assert (
            env.from_string(
                '{{ ("a{0.__class__}b{1}"|safe).format(42, "<foo>") }}'
            ).render()
            == "ab&lt;foo&gt;"
        )
        assert (
            env.from_string('{{ "a{x.__class__}b".format_map({"x": 42}) }}').render()
            == "ab"
        )

    def test_default_mode_keeps_existing_resolution(self):
        class Billing:
            calls = 0

            @property
            def _billing(self):
                type(self).calls += 1
                return "secret"

        env = SandboxedEnvironment()
        billing = Billing()

        assert env.strict_attribute_checking is False
        assert env.getattr(billing, "_billing").reason_code == (
            ATTRIBUTE_REASON_POLICY_DENIED
        )
        assert Billing.calls == 1
        assert env.from_string("{{ billing.plan }}").render(billing=billing) == ""

    def test_policy_aliases(self):
        env = SandboxedEnvironment(strict_attributes=True)
        assert env.strict_attribute_checking is True

        env = SandboxedEnvironment(attribute_policy="strict")
        assert env.strict_attribute_checking is True

        env = SandboxedEnvironment(attribute_policy="legacy")
        assert env.strict_attribute_checking is False

    def test_attr_filter(self) -> None:
        env = SandboxedEnvironment()
        t = env.from_string(
            """{{ "{0.__call__.__builtins__[__import__]}"
                  | attr("format")(not_here) }}"""
        )

        with pytest.raises(SecurityError):
            t.render()
