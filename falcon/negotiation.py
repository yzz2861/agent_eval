"""Server-driven content negotiation via ``produces`` declarations."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

from falcon import errors
from falcon.util import mediatypes

if TYPE_CHECKING:
    from falcon.request import Request
    from falcon.response import Response

__all__ = ('produces',)

_T = TypeVar('_T')

_PRODUCES_ATTRIBUTE = '__falcon_produces__'


def produces(*media_types: str) -> Callable[[_T], _T]:
    """Declare the media types a resource or responder can produce.

    When a resource class or an individual responder is decorated with
    ``@falcon.produces(...)``, the framework negotiates the response media
    type against the request's ``Accept`` header, choosing among the
    declared types that have a handler registered via
    :attr:`falcon.ResponseOptions.media_handlers`, and serializes
    :attr:`resp.media <falcon.Response.media>` with the selected handler.

    The negotiation takes quality factors, wildcards, and media type
    parameters of the ``Accept`` header into account, and media ranges
    with ``q=0`` exclude the corresponding type from selection. When
    several declared types are equally acceptable, the one declared first
    wins. If the client does not accept any of the declared types, an
    instance of :class:`falcon.HTTPNotAcceptable` (``406``) is raised
    instead of silently falling back to a default representation.

    A responder-level declaration takes precedence over a resource-level
    one. An explicitly assigned :attr:`resp.content_type
    <falcon.Response.content_type>` always takes precedence over
    negotiation, in which case no negotiation is performed at all.

    Note:
        When negotiation takes place, ``Accept`` is merged into the
        response's ``Vary`` header (preserving any existing values), and
        only the selected media handler is invoked to serialize
        :attr:`resp.media <falcon.Response.media>`.

    Note:
        Error responses (including the ``406`` error itself) are not
        subject to ``produces`` negotiation; they are serialized by the
        configured error serializer (see
        :meth:`falcon.App.set_error_serializer`). If the error
        representation cannot satisfy the ``Accept`` header either, the
        response is sent without a body rather than risking recursive
        negotiation failures.

    Args:
        media_types (str): One or more Internet media types that the
            decorated resource or responder is able to produce, in
            decreasing order of preference.

    Raises:
        ValueError: No media types were given, or one of them is not a
            non-empty string.
    """
    if not media_types:
        raise ValueError('produces() requires at least one media type')

    for media_type in media_types:
        if not isinstance(media_type, str) or not media_type.strip():
            raise ValueError(
                'produces() media types must be non-empty strings, got: {!r}'.format(
                    media_type
                )
            )

    def decorator(target: _T) -> _T:
        setattr(target, _PRODUCES_ATTRIBUTE, tuple(media_types))
        return target

    return decorator


def negotiate_content(
    req: Request, resp: Response, resource: object, responder: object
) -> None:
    """Negotiate the response media type for a ``produces`` declaration.

    This helper is invoked by the framework after the responder and all
    middleware have run, but before the response body is rendered. It is
    a no-op unless the resource or responder was decorated with
    :func:`produces`, :attr:`resp.media <falcon.Response.media>` is set,
    and no explicit content type was assigned to the response.

    Args:
        req: The current request object.
        resp: The current response object.
        resource: The routed resource instance, if any.
        responder: The routed responder, if any.

    Raises:
        falcon.HTTPNotAcceptable: The client does not accept any of the
            declared media types that have a registered handler.
    """
    media_types = getattr(responder, _PRODUCES_ATTRIBUTE, None)
    if media_types is None and resource is not None:
        media_types = getattr(resource, _PRODUCES_ATTRIBUTE, None)

    if not media_types:
        return

    # NOTE: An explicitly assigned Content-Type always takes precedence
    #   over negotiation, and there is nothing to negotiate when the
    #   responder did not set resp.media.
    if resp.media is None or resp.content_type:
        return

    handlers = resp.options.media_handlers
    accept = req.accept

    selected = None
    selected_quality = 0.0

    for media_type in media_types:
        # NOTE: Only declared types with a registered media handler can
        #   actually be produced.
        if media_type not in handlers:
            continue

        try:
            quality = mediatypes.quality(media_type, accept)
        except ValueError:
            # NOTE: A malformed Accept header matches nothing.
            quality = 0.0

        # NOTE: A strict comparison keeps the first declared type in the
        #   case of equal quality factors (declaration order breaks ties).
        if quality > selected_quality:
            selected = media_type
            selected_quality = quality

    if selected is None:
        raise errors.HTTPNotAcceptable(
            description='This resource can only produce representations '
            'of the following media types: {}.'.format(', '.join(media_types))
        )

    resp.content_type = selected

    vary = resp.get_header('Vary')
    if vary is None:
        resp.set_header('Vary', 'Accept')
    elif 'accept' not in (token.strip().lower() for token in vary.split(',')):
        resp.append_header('Vary', 'Accept')
