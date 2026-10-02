from quart import Quart
from quart import render_template
from quart import render_template_block
from quart import stream_template_block

app = Quart(__name__)

counter_calls = {"count": 0}


def counter() -> int:
    """Page-level function proving unselected output is not executed."""
    counter_calls["count"] += 1
    return counter_calls["count"]


app.jinja_env.globals["counter"] = counter


@app.get("/")
async def page() -> str:
    """Full first-load render of the whole page."""
    return await render_template("page.html", name="Quart")


@app.get("/content")
async def content() -> str:
    """Partial refresh rendering only the content block."""
    return await render_template_block("page.html", "content", name="Quart")


@app.get("/content/stream")
async def content_stream():
    """Streaming partial refresh of only the content block."""
    return await stream_template_block("page.html", "content", name="Quart")


@app.get("/counter")
async def counter_value() -> dict:
    return {"counter_calls": counter_calls["count"]}


def run() -> None:
    app.run()
