"""Incremental delivery of GraphQL results over multipart/mixed responses."""

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from functools import partial
from http import HTTPStatus
from typing import Any

from anyio import CancelScope, create_task_group, get_cancelled_exc_class
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

DEFAULT_INCREMENTAL_BOUNDARY = "graphql"


def accepts_incremental_delivery(request: Request) -> bool:
    """Check if the request's `Accept` header allows `multipart/mixed` responses.

    # Required arguments

    `request`: the `Request` instance from Starlette or FastAPI.
    """
    accept = request.headers.get("Accept", "")
    for item in accept.split(","):
        media_type = item.split(";")[0].strip().lower()
        if media_type in ("multipart/mixed", "multipart/*"):
            return True
    return False


class IncrementalDeliveryResponse(Response):
    """Streams GraphQL incremental delivery results as a multipart/mixed response.

    Sends the initial result and each subsequent patch as a separate multipart
    part, then terminates the response with the closing boundary. Closes the
    subsequent results stream when the response completes or the client
    disconnects.
    """

    def __init__(
        self,
        *,
        initial_result: dict,
        subsequent_results: AsyncIterator[dict],
        boundary: str = DEFAULT_INCREMENTAL_BOUNDARY,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initializes the incremental delivery response.

        # Required arguments

        `initial_result`: a JSON-serializable `dict` with the initial result.

        `subsequent_results`: an async iterator of JSON-serializable `dict`
        with subsequent patches.

        # Optional arguments

        `boundary`: a `str` with the multipart boundary to use. Defaults to
        `"graphql"`.

        `headers`: a `dict` of additional headers to send with the response.
        """
        super().__init__()
        self.initial_result = initial_result
        self.subsequent_results = subsequent_results
        self.boundary = boundary
        self.status_code = HTTPStatus.OK
        self.body = None

        _headers = {
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
        if headers:
            _headers.update(headers)
        self.media_type = f'multipart/mixed; boundary="{boundary}"'
        self.init_headers(_headers)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """The main entrypoint for the response, called by Starlette.

        # Required arguments

        `scope`: the connection scope information.

        `receive`: an awaitable callable that will yield a new event dictionary
        when one is available.

        `send`: an awaitable callable taking a single event dictionary as a
        positional argument.
        """
        async with create_task_group() as task_group:

            async def wrap_cancelling(func: Callable[[], Awaitable[None]]) -> None:
                await func()
                task_group.cancel_scope.cancel()

            task_group.start_soon(wrap_cancelling, partial(self.stream_results, send))
            await wrap_cancelling(partial(self.listen_for_disconnect, receive))

    async def stream_results(self, send: Send) -> None:
        """Streams the initial result and subsequent patches to the client.

        Always closes the subsequent results stream, also when the client
        disconnects before all patches were sent.

        # Required arguments

        `send`: the Starlette `Send` callable.
        """
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )

        try:
            await send(self.encode_part(self.initial_result))
            async for patch in self.subsequent_results:
                await send(self.encode_part(patch))
            await send(
                {
                    "type": "http.response.body",
                    "body": self.encode_end_boundary(),
                    "more_body": True,
                }
            )
        except get_cancelled_exc_class():
            pass
        finally:
            with CancelScope(shield=True):
                await self.close_subsequent_results()
                await send(
                    {"type": "http.response.body", "body": b"", "more_body": False}
                )

    def encode_part(self, payload: dict) -> dict[str, Any]:
        """Encodes a single multipart part with JSON payload.

        # Required arguments

        `payload`: a JSON-serializable `dict` to send in this part.
        """
        part = (
            f"--{self.boundary}\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{json.dumps(payload)}\r\n"
        )
        return {
            "type": "http.response.body",
            "body": part.encode("utf-8"),
            "more_body": True,
        }

    def encode_end_boundary(self) -> bytes:
        """Encodes the closing multipart boundary."""
        return f"--{self.boundary}--\r\n".encode()

    async def close_subsequent_results(self) -> None:
        """Closes the subsequent results stream, if it's closable."""
        aclose = getattr(self.subsequent_results, "aclose", None)
        if aclose is not None:
            await aclose()

    @staticmethod
    async def listen_for_disconnect(receive: Receive) -> None:
        """Listens for the client disconnect event.

        Exits when the client disconnects, which cancels the response's
        task group and stops the streaming.

        # Required arguments

        `receive`: the Starlette `Receive` callable.
        """
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
