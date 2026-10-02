from __future__ import annotations

import asyncio

import pytest
from jinja2 import DictLoader
from jinja2 import TemplateRuntimeError

from quart import before_render_template
from quart import Blueprint
from quart import g
from quart import Quart
from quart import render_template
from quart import render_template_block
from quart import render_template_string
from quart import request
from quart import Response
from quart import ResponseReturnValue
from quart import session
from quart import stream_template_block
from quart import stream_template_string
from quart import template_rendered


@pytest.fixture(scope="function")
def app() -> Quart:
    app = Quart(__name__)
    app.secret_key = "secret"

    return app


@pytest.fixture(scope="function")
def blueprint() -> Blueprint:
    blueprint = Blueprint("blueprint", __name__)

    @blueprint.route("/")
    def index() -> str:
        return ""

    return blueprint


async def test_template_render(app: Quart) -> None:
    async with app.app_context():
        rendered = await render_template_string("{{ foo }}", foo="bar")
    assert rendered == "bar"


async def test_default_template_context(app: Quart) -> None:
    async with app.app_context():
        g.foo = "bar"
        rendered = await render_template_string("{{ g.foo }}")
    assert rendered == "bar"
    async with app.test_request_context("/"):
        session["foo"] = "bar"
        rendered = await render_template_string(
            "{{ request.method }} {{ request.path }} {{ session.foo }}"
        )
    assert rendered == "GET / bar"


async def test_template_context_processors(app: Quart, blueprint: Blueprint) -> None:
    @blueprint.context_processor
    async def blueprint_context() -> dict:
        await asyncio.sleep(0.01)  # Test the ability to await
        return {"context": "foo"}

    @blueprint.app_context_processor
    async def app_blueprint_context() -> dict:
        return {"global_context": "boo"}

    @app.context_processor
    async def app_context() -> dict:
        return {"context": "bar"}

    app.register_blueprint(blueprint)

    async with app.app_context():
        rendered = await render_template_string("{{ context }}")
    assert rendered == "bar"

    async with app.test_request_context("/"):
        rendered = await render_template_string("{{ context }} {{ global_context }}")
    assert rendered == "foo boo"

    async with app.test_request_context("/other"):
        rendered = await render_template_string("{{ context }} {{ global_context }}")
    assert rendered == "bar boo"


async def test_template_globals(app: Quart, blueprint: Blueprint) -> None:
    @blueprint.app_template_global()
    def blueprint_global(value: str) -> str:
        return value.upper()

    @app.template_global()
    def app_global(value: str) -> str:
        return value.lower()

    app.register_blueprint(blueprint)

    async with app.app_context():
        rendered = await render_template_string(
            "{{ app_global('BAR') }} {{ blueprint_global('foo') }}"
        )
    assert rendered == "bar FOO"


async def test_template_filters(app: Quart, blueprint: Blueprint) -> None:
    @blueprint.app_template_filter()
    def blueprint_filter(value: str) -> str:
        return value.upper()

    @app.template_filter()
    def app_filter(value: str) -> str:
        return value.lower()

    app.register_blueprint(blueprint)

    async with app.app_context():
        rendered = await render_template_string("{{ 'App' | app_filter }}")
    assert rendered == "app"

    async with app.test_request_context("/"):
        rendered = await render_template_string("{{ 'App' | blueprint_filter }}")
    assert rendered == "APP"


async def test_template_tests(app: Quart, blueprint: Blueprint) -> None:
    @blueprint.app_template_test()
    def blueprint_test(value: int) -> bool:
        return value == 5

    @app.template_test()
    def app_test(value: int) -> bool:
        return value == 3

    app.register_blueprint(blueprint)

    async with app.app_context():
        rendered = await render_template_string("{% if 3 is app_test %}foo{% endif %}")
    assert rendered == "foo"

    async with app.test_request_context("/"):
        rendered = await render_template_string(
            "{% if 5 is blueprint_test %}bar{% endif %}"
        )
    assert rendered == "bar"


async def test_simple_stream(app: Quart) -> None:
    @app.get("/")
    async def index() -> ResponseReturnValue:
        return await stream_template_string("{{ config }}", config=42)  # type: ignore

    test_client = app.test_client()
    response = await test_client.get("/")
    assert (await response.data) == b"42"

    @app.get("/2")
    async def index2() -> ResponseReturnValue:
        return Response(await stream_template_string("{{ config }}", config=43))

    test_client = app.test_client()
    response = await test_client.get("/2")
    assert (await response.data) == b"43"


async def test_render_template_block_inheritance_super_and_scope(app: Quart) -> None:
    output_calls = 0

    def page_output() -> str:
        nonlocal output_calls
        output_calls += 1
        return "outside"

    app.jinja_env.loader = DictLoader(
        {
            "base.html": (
                "{{ page_output() }}\n"
                "{% set outside_value = 'outside' %}\n"
                "{% block content %}base {{ value }} {{ outside_value }}{% endblock %}"
            ),
            "child.html": (
                '{% extends "base.html" %}'
                "{% block content %}child {{ super() }}{% endblock %}"
            ),
        }
    )
    app.jinja_env.globals["page_output"] = page_output

    async with app.app_context():
        rendered = await render_template_block("child.html", "content", value="value")
        assert output_calls == 0
        full = await render_template("child.html", value="full")

    assert rendered == "child base value outside"
    assert full == "outside\n\nchild base full outside"


async def test_render_template_block_nested_block_super(app: Quart) -> None:
    app.jinja_env.loader = DictLoader(
        {
            "base.html": (
                "{% block outer %}outer "
                "{% block inner %}base{% endblock %}"
                "{% endblock %}"
            ),
            "child.html": (
                '{% extends "base.html" %}'
                "{% block outer %}child-outer {{ super() }}{% endblock %}"
                "{% block inner %}child-inner {{ super() }}{% endblock %}"
            ),
        }
    )

    async with app.app_context():
        rendered = await render_template_block("child.html", "inner")

    assert rendered == "child-inner base"


async def test_render_template_block_parent_only_block(app: Quart) -> None:
    app.jinja_env.loader = DictLoader(
        {
            "base.html": (
                "{% block content %}base{% endblock %}"
                "{% block other %}other{% endblock %}"
            ),
            "child.html": '{% extends "base.html" %}',
        }
    )

    async with app.app_context():
        rendered = await render_template_block("child.html", "other")

    assert rendered == "other"


async def test_render_template_block_with_scoped_setup(app: Quart) -> None:
    app.jinja_env.loader = DictLoader(
        {
            "base.html": "{% block content %}base{% endblock %}",
            "page.html": (
                "{% for value in values() %}{{ value }}{% endfor %}"
                "{% block content %}main{% endblock %}"
            ),
        }
    )

    iterations = 0

    def values():
        nonlocal iterations
        iterations += 1
        yield "unselected"

    async with app.app_context():
        rendered = await render_template_block("page.html", "content")

    assert rendered == "main"
    assert iterations == 0


async def test_render_template_block_include_setup_without_include_output(
    app: Quart,
) -> None:
    included_outputs = 0
    included_setup = 0

    def include_output() -> str:
        nonlocal included_outputs
        included_outputs += 1
        return "included"

    def include_setup() -> None:
        nonlocal included_setup
        included_setup += 1

    app.jinja_env.loader = DictLoader(
        {
            "include.html": (
                "{{ include_output() }}{% set ignored = include_setup() %}"
            ),
            "page.html": (
                "{% include 'include.html' %}{% block content %}main{% endblock %}"
            ),
        }
    )
    app.jinja_env.globals["include_output"] = include_output
    app.jinja_env.globals["include_setup"] = include_setup

    async with app.app_context():
        rendered = await render_template_block("page.html", "content")

    assert rendered == "main"
    assert included_setup == 1
    assert included_outputs == 0


async def test_render_template_block_uses_processors_and_async_filter(
    app: Quart,
) -> None:
    calls = []

    @app.context_processor
    async def add_context() -> dict[str, str]:
        return {"processor_value": "processor"}

    @app.template_filter("record")
    async def record(value: str, label: str) -> str:
        calls.append(label)
        return value.upper()

    app.jinja_env.loader = DictLoader(
        {
            "index.html": (
                "{% block content %}"
                "{{ value|record('block') }} {{ processor_value }}"
                "{% endblock %}"
            )
        }
    )

    before_signals = []

    @before_render_template.connect_via(app)
    def before(sender: Quart, template: object, context: dict) -> None:
        before_signals.append(
            (template.name, context["value"], context["g"].signal_value)
        )

    async with app.test_request_context("/path"):
        g.signal_value = "signal"
        rendered = await render_template_block(
            "index.html", "content", value=request.path
        )

    assert rendered == "/PATH processor"
    assert calls == ["block"]
    assert before_signals == [("index.html", "/path", "signal")]


async def test_render_template_block_missing_block_error(app: Quart) -> None:
    app.jinja_env.loader = DictLoader(
        {"index.html": "{% block content %}content{% endblock %}"}
    )

    async with app.app_context():
        with pytest.raises(TemplateRuntimeError, match="Block 'missing'"):
            await render_template_block("index.html", "missing")
        with pytest.raises(TemplateRuntimeError, match="Block 'missing'"):
            await stream_template_block("index.html", "missing")

    app.jinja_env.loader = DictLoader(
        {
            "base.html": "{% block content %}content{% endblock %}",
            "child.html": '{% extends "base.html" %}',
        }
    )

    async with app.app_context():
        with pytest.raises(TemplateRuntimeError, match="Available blocks: content"):
            await render_template_block("child.html", "missing")


async def test_stream_template_block_signals_and_early_cleanup(app: Quart) -> None:
    closed = False
    consumed = []
    before_templates = []
    rendered_templates = []

    async def sections():
        nonlocal closed
        try:
            consumed.append("started")
            yield "b"
            yield "c"
        finally:
            closed = True

    app.jinja_env.loader = DictLoader(
        {
            "index.html": (
                "{% block content %}"
                "a"
                "{% for item in sections() %}{{ item }}{% endfor %}"
                "{% endblock %}"
            )
        }
    )

    @template_rendered.connect_via(app)
    def rendered(sender: Quart, template: object, context: dict) -> None:
        rendered_templates.append((template.name, context["block_value"]))

    @before_render_template.connect_via(app)
    def before(sender: Quart, template: object, context: dict) -> None:
        before_templates.append((template.name, context["block_value"]))

    async with app.app_context():
        stream = await stream_template_block(
            "index.html",
            "content",
            block_value="value",
            sections=sections,
        )
        assert await stream.__anext__() == "a"
        assert await stream.__anext__() == "b"
        await stream.aclose()

    assert consumed == ["started"]
    assert closed is True
    assert before_templates == [("index.html", "value")]
    assert rendered_templates == [("index.html", "value")]
