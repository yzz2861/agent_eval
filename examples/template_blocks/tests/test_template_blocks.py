from template_blocks import app
from template_blocks import counter_calls


async def test_full_page_render_executes_counter():
    counter_calls["count"] = 0
    test_client = app.test_client()
    response = await test_client.get("/")
    body = await response.get_data(as_text=True)
    assert "<h1>Hello Quart!</h1>" in body
    assert "<blockquote>Default content from the layout</blockquote>" in body
    assert "counter: 1" in body
    assert "counter: 2" in body
    # The header and footer both called counter().
    assert counter_calls["count"] == 2


async def test_block_render_skips_page_output():
    counter_calls["count"] = 0
    test_client = app.test_client()
    response = await test_client.get("/content")
    body = await response.get_data(as_text=True)
    assert "<h1>Hello Quart!</h1>" in body
    assert "<blockquote>Default content from the layout</blockquote>" in body
    assert "Header" not in body
    assert "Footer" not in body
    # Nothing outside the content block was executed.
    assert counter_calls["count"] == 0


async def test_stream_block_render_skips_page_output():
    counter_calls["count"] = 0
    test_client = app.test_client()
    response = await test_client.get("/content/stream")
    body = await response.get_data(as_text=True)
    assert "<h1>Hello Quart!</h1>" in body
    assert "<blockquote>Default content from the layout</blockquote>" in body
    assert "Header" not in body
    assert counter_calls["count"] == 0
