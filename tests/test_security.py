import time

import pytest
from jinja2 import DictLoader
from jinja2 import Environment
from jinja2 import RenderBudget
from jinja2 import RenderBudgetExceeded
from jinja2.exceptions import SecurityError
from jinja2.exceptions import TemplateRuntimeError
from jinja2.exceptions import TemplateSyntaxError
from jinja2.nodes import EvalContext
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2.sandbox import SandboxedEnvironment
from jinja2.sandbox import unsafe
from markupsafe import escape


class TestRenderBudget:
    def test_infinite_shallow_output_is_bounded(self):
        env = SandboxedEnvironment()
        template = env.from_string("{% for i in range(100000) %}x{% endfor %}")
        budget = RenderBudget(output_bytes=10)

        with pytest.raises(RenderBudgetExceeded) as exc_info:
            template.render(render_budget=budget)

        assert exc_info.value.limit == "output_bytes"
        assert exc_info.value.used > 10
        assert "output_bytes" in str(exc_info.value)

    def test_nested_range_output_is_bounded(self):
        env = SandboxedEnvironment()
        source = (
            "{% for i in range(1000) %}"
            "{% for j in range(1000) %}"
            "{{ i }}{{ j }}"
            "{% endfor %}{% endfor %}"
        )
        template = env.from_string(source)
        budget = RenderBudget(fragments=25)

        with pytest.raises(RenderBudgetExceeded) as exc_info:
            template.render(render_budget=budget)

        assert exc_info.value.limit == "fragments"
        assert exc_info.value.used == 26
        assert "fragments" in str(exc_info.value)

    def test_many_single_byte_fragments_stop_before_next_yield(self):
        env = SandboxedEnvironment()
        template = env.from_string("{% for i in range(100) %}x{% endfor %}")
        budget = RenderBudget(fragments=5)
        fragments = []

        with pytest.raises(RenderBudgetExceeded):
            for fragment in template.generate(render_budget=budget):
                fragments.append(fragment)

        assert fragments == ["x"] * 5

    def test_range_elements_accumulate_across_calls(self):
        env = SandboxedEnvironment()
        template = env.from_string(
            "{% for i in range(30) %}{{ i }}{% endfor %}"
            "{% for i in range(30) %}{{ i }}{% endfor %}"
        )
        budget = RenderBudget(range_elements=50)

        with pytest.raises(RenderBudgetExceeded) as exc_info:
            template.render(render_budget=budget)

        assert exc_info.value.limit == "range_elements"
        assert exc_info.value.used == 60

    def test_nested_includes_share_one_budget(self):
        loader = DictLoader(
            {
                "outer.html": "{% include 'inner.html' %}",
                "inner.html": "{% include 'leaf.html' %}",
                "leaf.html": "{% for i in range(2) %}x{% endfor %}",
            }
        )
        env = SandboxedEnvironment(loader=loader)
        template = env.get_template("outer.html")
        budget = RenderBudget(template_includes=1)

        with pytest.raises(RenderBudgetExceeded) as exc_info:
            template.render(render_budget=budget)

        assert exc_info.value.limit == "template_includes"
        assert exc_info.value.used == 2

        budget = RenderBudget(template_includes=2)
        assert template.render(render_budget=budget) == "xx"
        assert budget.template_includes_used == 2

    def test_extends_shares_budget(self):
        loader = DictLoader(
            {
                "child.html": (
                    "{% extends 'parent.html' %}{% block body %}child{% endblock %}"
                ),
                "parent.html": "{% block body %}parent{% endblock %}",
            }
        )
        env = SandboxedEnvironment(loader=loader)
        template = env.get_template("child.html")

        with pytest.raises(RenderBudgetExceeded) as exc_info:
            template.render(render_budget=RenderBudget(template_includes=0))

        assert exc_info.value.limit == "template_includes"

    def test_sync_and_async_share_limit_semantics(self, run_async_fn):
        source = "{% for i in range(100) %}x{% endfor %}"
        sync_env = SandboxedEnvironment()
        async_env = SandboxedEnvironment(enable_async=True)
        sync_template = sync_env.from_string(source)
        async_template = async_env.from_string(source)

        sync_budget = RenderBudget(output_bytes=7)
        with pytest.raises(RenderBudgetExceeded) as sync_exc:
            sync_template.render(render_budget=sync_budget)

        async def render():
            return await async_template.render_async(
                render_budget=RenderBudget(output_bytes=7)
            )

        with pytest.raises(RenderBudgetExceeded) as async_exc:
            run_async_fn(render)

        assert sync_exc.value.limit == async_exc.value.limit == "output_bytes"
        assert sync_exc.value.used == async_exc.value.used == 8

    def test_async_generate_enforces_budget(self, run_async_fn):
        env = SandboxedEnvironment(enable_async=True)
        template = env.from_string("{% for i in range(100) %}x{% endfor %}")

        async def collect():
            fragments = []
            with pytest.raises(RenderBudgetExceeded):
                async for fragment in template.generate_async(
                    render_budget=RenderBudget(fragments=3)
                ):
                    fragments.append(fragment)
            return fragments

        assert run_async_fn(collect) == ["x"] * 3

    def test_generator_close_leaves_no_resumable_state(self):
        env = SandboxedEnvironment()
        template = env.from_string("{% for i in range(100) %}x{% endfor %}")
        generator = template.generate(render_budget=RenderBudget(output_bytes=1000))

        assert next(generator) == "x"
        generator.close()

        with pytest.raises(StopIteration):
            next(generator)

    def test_async_generator_close_leaves_no_resumable_state(self, run_async_fn):
        env = SandboxedEnvironment(enable_async=True)
        template = env.from_string("{% for i in range(100) %}x{% endfor %}")

        async def close_early():
            generator = template.generate_async(
                render_budget=RenderBudget(output_bytes=1000)
            )
            assert await generator.__anext__() == "x"
            await generator.aclose()

            with pytest.raises(StopAsyncIteration):
                await generator.__anext__()

        run_async_fn(close_early)

    def test_environment_is_reusable_after_budget_failure(self):
        env = SandboxedEnvironment()
        template = env.from_string("{% for i in range(100) %}{{ i }}{% endfor %}")

        with pytest.raises(RenderBudgetExceeded):
            template.render(render_budget=RenderBudget(output_bytes=1))

        assert template.render() == "".join(map(str, range(100)))

        second_budget = RenderBudget(output_bytes=1000)
        assert template.render(render_budget=second_budget) == "".join(
            map(str, range(100))
        )
        assert second_budget.range_elements_used == 100

    def test_wall_time_stops_cpu_bound_template_without_yields(self):
        env = SandboxedEnvironment()
        template = env.from_string(
            "{% for i in range(100000) %}"
            "{% for j in range(100000) %}"
            "{% set x = i * j %}"
            "{% endfor %}{% endfor %}"
        )
        budget = RenderBudget(wall_time=0.2)
        start = time.monotonic()

        with pytest.raises(RenderBudgetExceeded) as exc_info:
            template.render(render_budget=budget)

        assert time.monotonic() - start < 2.0
        assert exc_info.value.limit == "wall_time"
        assert "wall_time" in str(exc_info.value)

    def test_wall_time_enforced_in_async_render(self, run_async_fn):
        env = SandboxedEnvironment(enable_async=True)
        template = env.from_string(
            "{% for i in range(100000) %}"
            "{% for j in range(100000) %}"
            "{% set x = i * j %}"
            "{% endfor %}{% endfor %}"
        )

        async def render():
            await template.render_async(render_budget=RenderBudget(wall_time=0.2))

        start = time.monotonic()
        with pytest.raises(RenderBudgetExceeded) as exc_info:
            run_async_fn(render)

        assert time.monotonic() - start < 2.0
        assert exc_info.value.limit == "wall_time"

    def test_no_budget_keeps_default_behavior(self):
        env = SandboxedEnvironment()
        template = env.from_string("{% for i in range(3) %}{{ i }}{% endfor %}")

        assert template.render() == "012"
        assert list(template.generate()) == ["0", "1", "2"]


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

    def test_attr_filter(self) -> None:
        env = SandboxedEnvironment()
        t = env.from_string(
            """{{ "{0.__call__.__builtins__[__import__]}"
                  | attr("format")(not_here) }}"""
        )

        with pytest.raises(SecurityError):
            t.render()
