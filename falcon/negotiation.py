"""Server-driven content negotiation for response media."""

from __future__ import annotations

from typing import Any, Callable, TYPE_CHECKING, TypeVar

from falcon.errors import HTTPNotAcceptable
from falcon.util.mediatypes import quality

if TYPE_CHECKING:
    from falcon.request import Request
    from falcon.response import Response

__all__ = ('produces',)

_ResponderT = TypeVar('_ResponderT', bound=Callable[..., Any])


def produces(*media_types: str) -> Callable[[_ResponderT], _ResponderT]:
    """Decorate a responder to declare the media types it can produce.

    When a responder (or its resource, via a ``produces`` class attribute)
    declares the media types it can produce, the framework negotiates the
    response media type against the request's ``Accept`` header, and
    serializes :attr:``~falcon.Response.media`` with the selected, registered
    media handler.

    Quality factors, wildcards, and media type parameters are taken into
    account per RFC 9110, and entries excluded with ``q=0`` are never
    selected. When several declared types are equally acceptable, the one
    declared first wins. A responder-level declaration takes precedence
    over a resource-level one.

    If none of the declared types is acceptable to the client, an instance
    of :class:``~falcon.HTTPNotAcceptable`` (``406``) is raised instead of
    silently falling back to the default media type. Error responses
    (including the ``406`` itself) are exempt from this negotiation; they
    are rendered by the app's error serializer, so negotiation can never
    recurse.

    Note:
        An explicitly set :attr:``~falcon.Response.content_type`` always
        takes precedence, and disables negotiation for that response.

    Args:
        media_types (str): One or more Internet media types that the
            decorated responder is able to produce, in the order of
            preference used to break ties.

    Raises:
        ValueError: No media type was provided.
    """
    if not media_types:
        raise ValueError('produces() requires at least one media type.')

    def decorator(responder: _ResponderT) -> _ResponderT:
        setattr(responder, '__falcon_produces__', tuple(media_types))
        return responder

    return decorator


def negotiate_response_media(
    req: Request, resp: Response, resource: Any, responder: Any
) -> None:
    """Negotiate the response media type for a successful request.

    This function is called by the framework after the responder and any
    response middleware have run. It is a no-op unless the resource or the
    responder declares ``produces`` and the response carries a
    :attr:``~falcon.Response.media`` value that would actually be rendered.

    Args:
        req: The request object.
        resp: The response object.
        resource: The resource instance that handled the request, if any.
        responder: The responder callable that handled the request, if any.

    Raises:
        HTTPNotAcceptable: No declared media type is acceptable to the
            client, or none of the acceptable declared types has a
            registered media handler.
    """
    media_types = getattr(responder, '__falcon_produces__', None)
    if media_types is None:
        if resource is None:
            return

        media_types = getattr(resource, 'produces', None)
        if media_types is None:
            return

    if isinstance(media_types, str):
        media_types = (media_types,)

    if not media_types:
        return

    # Only negotiate when resp.media would actually be rendered,
    #   i.e. it is set, and neither resp.text nor resp.data takes
    #   precedence over it.
    if resp.media is None or resp.text is not None or resp.data is not None:
        return

    # An explicitly set Content-Type always takes precedence over
    #   negotiation.
    if resp.content_type:
        return

    handlers = resp.options.media_handlers
    accept = req.accept

    acceptable: list[str] = []
    selected = None
    selected_quality = 0.0

    for media_type in media_types:
        if not media_type:
            continue

        # Only types with a registered handler can be serialized,
        #   so only they participate in the negotiation.
        handler, _, _ = handlers._resolve(media_type, '', False)
        if handler is None:
            continue

        acceptable.append(media_type)

        try:
            qvalue = quality(media_type, accept)
        except ValueError:
            # A malformed Accept header matches nothing.
            qvalue = 0.0

        # A strict comparison keeps the first declared type when
        #   several types are equally acceptable.
        if qvalue > selected_quality:
            selected = media_type
            selected_quality = qvalue

    if selected is None:
        description = (
            'The resource is unable to produce a representation that is '
            'acceptable to the client.'
        )
        if acceptable:
            description += ' Available media types: ' + ', '.join(acceptable) + '.'

        raise HTTPNotAcceptable(description=description)

    resp.content_type = selected
    _merge_vary_accept(resp)


def _merge_vary_accept(resp: Response) -> None:
    """Merge ``Accept`` into the response's ``Vary`` header."""
    vary = resp.get_header('Vary')
    if vary is None:
        resp.vary = ('Accept',)
        return

    existing = [value.strip() for value in vary.split(',')]
    lowered = {value.lower() for value in existing}
    if 'accept' not in lowered and '*' not in lowered:
        resp.vary = (*existing, 'Accept')
