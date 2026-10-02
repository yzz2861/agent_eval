"""Errors raised by the idempotency-key middleware."""

from __future__ import annotations

from .. import errors as http_errors


class IdempotencyInProgress(http_errors.HTTPConflict):
    """409 Conflict returned while an idempotent request is being processed.

    The original request is still being handled by another request or
    application instance. The caller may safely retry after the suggested
    delay; doing so does not execute the responder again.

    The ``Retry-After`` response header communicates the suggested polling
    interval in seconds.
    """

    def __init__(
        self,
        *,
        retry_after: float,
        description: str | None = None,
    ) -> None:
        super().__init__(
            title='409 Conflict',
            description=description
            or (
                'A request with the same Idempotency-Key is still being '
                'processed. Retry after the delay given in Retry-After.'
            ),
            headers=[('Retry-After', str(max(1, int(retry_after))))],
        )


class IdempotencyKeyReused(http_errors.HTTPUnprocessableEntity):
    """422 Unprocessable Entity for an Idempotency-Key reuse mismatch.

    The same key was already used within the configured scope and route with
    a different request fingerprint (e.g. a different request body or
    content type).
    """

    def __init__(self) -> None:
        super().__init__(
            title='422 Unprocessable Entity',
            description=(
                'The Idempotency-Key was previously used with a different '
                'request payload. Reuse a key only for retries of the '
                'identical request.'
            ),
        )


class IdempotencyResultUnknown(http_errors.HTTPConflict):
    """409 Conflict returned when a previous attempt's outcome is unknown.

    The request that originally claimed the key stopped before its response
    could be committed. The server cannot tell whether the responder's side
    effects took place, so it neither replays a response nor re-executes the
    responder automatically. The caller must reconcile the business state
    out of band and ask an administrator to release the key once it is safe
    to retry.
    """

    def __init__(self) -> None:
        super().__init__(
            title='409 Conflict',
            description=(
                'The previous attempt with this Idempotency-Key ended '
                'before its result was recorded. The outcome is unknown; '
                'please reconcile the request before retrying.'
            ),
            code=40901,
        )
