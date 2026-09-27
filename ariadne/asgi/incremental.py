"""Incremental delivery (defer/stream) support for the ASGI HTTP handler.

Implements a `multipart/mixed` streaming response that sends the initial
execution result followed by subsequent incremental patches, each in its
own part, following the incremental delivery over HTTP convention:

```
---
Content-Type: application/json; charset=utf-8

{"data": {...}, "hasNext": true}
---
Content-Type: application/json; charset=utf-8

{"data": {...}, "path": [...], "label": "...", "hasNext": false}
-----
```
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from graphql import ExecutionResult
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from ..format_error import format_error

if TYPE_CHECKING:
    from ..types import ErrorFormatter, IncrementalExecutionResults, IncrementalPatch

MULTIPART_CONTENT_TYPE = 'multipart/mixed; boundary="-"'

_PART_HEADERS = b"---\r\nContent-Type: application/json; charset=utf-8\r\n\r\n"
_TERMINATOR = b"-----\r\n"


def client_accepts_incremental_delivery(accept_header: str) -> bool:
    """Returns `True` if the `Accept` header allows `multipart/mixed` responses."""
    return "multipart/mixed" in accept_header.lower()


async def close_incremental_results(results: IncrementalExecutionResults) -> None:
    """Closes the subsequent results iterator of incremental results.

    Does nothing if the iterator doesn't define an `aclose` method.
    """
    aclose = getattr(results.subsequent_results, "aclose", None)
    if aclose is not None:
        await aclose()


def format_initial_result(
    result: ExecutionResult,
    error_formatter: ErrorFormatter,
    debug: bool = False,
) -> dict[str, Any]:
    """Formats the initial `ExecutionResult` as an incremental delivery payload.

    The payload preserves `data`, `errors` and `extensions` from the result
    and marks the stream as unfinished with `"hasNext": True`.
    """
    payload: dict[str, Any] = {"data": result.data}
    if result.errors:
        payload["errors"] = [error_formatter(error, debug) for error in result.errors]
    if result.extensions:
        payload["extensions"] = result.extensions
    payload["hasNext"] = True
    return payload


def format_incremental_patch(
    patch: IncrementalPatch,
    error_formatter: ErrorFormatter,
    debug: bool = False,
) -> dict[str, Any]:
    """Formats a single `IncrementalPatch` as an incremental delivery payload.

    Preserves the patch's `data`, `path`, `label`, `errors` and `extensions`,
    and includes the `hasNext` marker indicating if more patches follow.
    """
    payload: dict[str, Any] = {"data": patch.data}
    if patch.path is not None:
        payload["path"] = patch.path
    if patch.label is not None:
        payload["label"] = patch.label
    if patch.errors:
        payload["errors"] = [error_formatter(error, debug) for error in patch.errors]
    if patch.extensions:
        payload["extensions"] = patch.extensions
    payload["hasNext"] = patch.has_next
    return payload


class IncrementalMultipartResponse(Response):
    """An ASGI response streaming incremental delivery results.

    Sends the initial result and subsequent patches as parts of a
    `multipart/mixed` response. The patch source is always closed when the
    response finishes, is closed, or the client disconnects.
    """

    def __init__(
        self,
        results: IncrementalExecutionResults,
        *,
        error_formatter: ErrorFormatter = format_error,
        debug: bool = False,
        status_code: int = 200,
    ) -> None:
        """Initializes the streaming response.

        # Required arguments

        `results`: an `IncrementalExecutionResults` with the initial result
        and an async iterator of subsequent patches.

        # Optional arguments

        `error_formatter`: an `ErrorFormatter` used to format errors in the
        initial result and patches. Defaults to Ariadne's `format_error`.

        `debug`: a `bool` telling the error formatter if it should include
        debugging information. Defaults to `False`.

        `status_code`: an HTTP status code of the response. Defaults to 200.
        """
        super().__init__(
            status_code=status_code,
            headers={"Content-Type": MULTIPART_CONTENT_TYPE},
        )
        # Response body is streamed, so the content length is unknown
        self.raw_headers = [
            (name, value)
            for name, value in self.raw_headers
            if name != b"content-length"
        ]
        self.results = results
        self.error_formatter = error_formatter
        self.debug = debug

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Streams the initial result and subsequent patches to the client.

        Closes the subsequent results iterator in a `finally` block so the
        patch source is released even if sending fails midway (for example
        when the client disconnects).
        """
        subsequent_results = self.results.subsequent_results
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": self.status_code,
                    "headers": self.raw_headers,
                }
            )

            initial_payload = format_initial_result(
                self.results.initial_result, self.error_formatter, self.debug
            )
            await self._send_payload(send, initial_payload)

            has_next = True
            async for patch in subsequent_results:
                has_next = patch.has_next
                await self._send_payload(
                    send,
                    format_incremental_patch(patch, self.error_formatter, self.debug),
                )

            if has_next:
                await self._send_payload(send, {"hasNext": False})

            await send(
                {
                    "type": "http.response.body",
                    "body": _TERMINATOR,
                    "more_body": False,
                }
            )
        finally:
            await close_incremental_results(self.results)

    async def _send_payload(self, send: Send, payload: dict[str, Any]) -> None:
        body = (
            _PART_HEADERS
            + json.dumps(payload, separators=(",", ":")).encode("utf-8")
            + b"\r\n"
        )
        await send({"type": "http.response.body", "body": body, "more_body": True})
