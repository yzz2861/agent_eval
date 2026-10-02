from __future__ import annotations

import asyncio

import pytest
from jinja2 import DictLoader

from quart import before_render_template
from quart import Blueprint
from quart import g
from quart import has_request_context
from quart import Quart
from quart import render_template
from quart import render_template_block
from quart import render_template_string
from quart import Response
from quart import ResponseReturnValue
from quart import session
from quart import stream_template_block
from quart import stream_template_string
from quart import template_rendered
from quart import TemplateBlockNotFoundError
from quart.globals import app_ctx


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


BLOCK_TEMPLATES = {
    "layout.html": (
        "HEADER[{{ counter() }}]"
        "{% block content %}parent-content{% endblock %}"
        "{% block sidebar %}sidebar{% endblock %}"
        "FOOTER"
    ),
    "page.html": (
        '{% extends "layout.html" %}'
        "{% block content %}child({{ super() }})"
        "{% block inner %}inner:{{ name | shout }}{% endblock %}"
        "{% endblock %}"
    ),
    "dynamic.html": (
        "{% extends layout %}{% block content %}dynamic({{ super() }}){% endblock %}"
    ),
    "context.html": (
        "{% block info %}"
        "{{ from_processor }} {{ g.value }} {{ request.path }}"
        "{% endblock %}"
    ),
}


@pytest.fixture(scope="function")
def block_app() -> Quart:
    app = Quart(__name__)
    app.jinja_env.loader = DictLoader(BLOCK_TEMPLATES)
    calls: list[int] = []

    def counter() -> int:
        calls.append(1)
        return len(calls)

    async def shout(value: str) -> str:
        await asyncio.sleep(0)
        return value.upper()

    app.jinja_env.globals["counter"] = counter
    app.jinja_env.filters["shout"] = shout
    app.config["COUNTER_CALLS"] = calls

    @app.context_processor
    async def processor() -> dict:
        return {"from_processor": "cpu"}

    return app


async def test_render_template_block(block_app: Quart) -> None:
    async with block_app.app_context():
        rendered = await render_template_block("page.html", "content", name="quart")
    # Inheritance, super(), nested blocks and async filters work, whilst
    # the counter() output expression outside the block is not executed.
    assert rendered == "child(parent-content)inner:QUART"
    assert block_app.config["COUNTER_CALLS"] == []


async def test_render_template_block_nested(block_app: Quart) -> None:
    async with block_app.app_context():
        rendered = await render_template_block("page.html", "inner", name="quart")
    assert rendered == "inner:QUART"
    assert block_app.config["COUNTER_CALLS"] == []


async def test_render_template_block_inherited_only(block_app: Quart) -> None:
    async with block_app.app_context():
        rendered = await render_template_block("page.html", "sidebar")
    assert rendered == "sidebar"


async def test_render_template_block_dynamic_extends(block_app: Quart) -> None:
    async with block_app.app_context():
        rendered = await render_template_block(
            "dynamic.html", "content", layout="layout.html"
        )
    assert rendered == "dynamic(parent-content)"


async def test_render_template_block_template_list(block_app: Quart) -> None:
    async with block_app.app_context():
        rendered = await render_template_block(
            ["missing.html", "page.html"], "content", name="quart"
        )
    assert rendered == "child(parent-content)inner:QUART"


async def test_render_template_block_not_found(block_app: Quart) -> None:
    async with block_app.app_context():
        with pytest.raises(TemplateBlockNotFoundError) as exc_info:
            await render_template_block("page.html", "missing")
    assert "missing" in str(exc_info.value)
    assert "page.html" in str(exc_info.value)


async def test_render_template_block_context(block_app: Quart) -> None:
    async with block_app.test_request_context("/path"):
        g.value = "gee"
        rendered = await render_template_block("context.html", "info")
    assert rendered == "cpu gee /path"


async def test_render_template_block_signals(block_app: Quart) -> None:
    before = []
    after = []

    async def before_handler(sender: Quart, template: object, **extra: object) -> None:
        before.append(template)

    async def after_handler(sender: Quart, template: object, **extra: object) -> None:
        after.append(template)

    before_render_template.connect(before_handler, block_app)
    template_rendered.connect(after_handler, block_app)
    try:
        async with block_app.app_context():
            await render_template_block("page.html", "content", name="quart")
    finally:
        before_render_template.disconnect(before_handler, block_app)
        template_rendered.disconnect(after_handler, block_app)
    assert len(before) == 1
    assert len(after) == 1


async def test_render_template_full_page_unchanged(block_app: Quart) -> None:
    async with block_app.app_context():
        rendered = await render_template("page.html", name="quart")
    assert rendered == "HEADER[1]child(parent-content)inner:QUARTsidebarFOOTER"
    assert block_app.config["COUNTER_CALLS"] == [1]


async def test_stream_template_block(block_app: Quart) -> None:
    async with block_app.test_request_context("/stream"):
        original = app_ctx._get_current_object()
        iterator = await stream_template_block("page.html", "content", name="quart")
        chunks = [chunk async for chunk in iterator]
        # The copied context is cleaned up once the stream is exhausted.
        assert app_ctx._get_current_object() is original
    assert "".join(chunks) == "child(parent-content)inner:QUART"
    assert block_app.config["COUNTER_CALLS"] == []
    assert not has_request_context()


async def test_stream_template_block_early_close(block_app: Quart) -> None:
    async with block_app.test_request_context("/stream"):
        original = app_ctx._get_current_object()
        iterator = await stream_template_block("page.html", "content", name="quart")
        first = await iterator.__anext__()
        assert first != ""
        # The context is kept whilst the stream is being consumed.
        assert app_ctx._get_current_object() is not original
        await iterator.aclose()
        # Closing early cleans the copied context up again.
        assert app_ctx._get_current_object() is original


async def test_stream_template_block_response(block_app: Quart) -> None:
    @block_app.get("/")
    async def index() -> ResponseReturnValue:
        return await stream_template_block("page.html", "content", name="quart")  # type: ignore

    test_client = block_app.test_client()
    response = await test_client.get("/")
    assert (await response.data) == b"child(parent-content)inner:QUART"
    assert block_app.config["COUNTER_CALLS"] == []
