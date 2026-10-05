"""
Evaluation of conditional request headers (``If-Match``,
``If-Unmodified-Since``, ``If-None-Match`` and ``If-Modified-Since``)
against a known current resource state.

Unlike :meth:`webob.response.Response.conditional_response_app`, which can
only be used once the response has already been generated, the helpers in
this module are meant to be called *before* the request body is consumed
and before the resource is modified.  This makes them usable for unsafe
methods such as ``PUT``, where a failed precondition must abort the request
with ``412 Precondition Failed`` instead of being applied.

The preconditions are evaluated in the order mandated by RFC 9110
section 13.2.2:

1. ``If-Match`` (strong comparison, all methods) -- ``412`` on failure.
2. ``If-Unmodified-Since`` (only when ``If-Match`` is absent) -- ``412``
   on failure.
3. ``If-None-Match`` (weak comparison) -- ``304`` on a match for
   ``GET``/``HEAD``, ``412`` for any other method.
4. ``If-Modified-Since`` (only when ``If-None-Match`` is absent, only for
   ``GET``/``HEAD``) -- ``304`` when the resource is not modified.

Header fields whose value cannot be parsed as an HTTP-date are ignored, as
required by the specification.  ETag header fields are parsed leniently
(following :class:`webob.etag.ETagMatcher`): an unparseable value is
treated as a single opaque tag, which in practice matches nothing sensible.

HTTP dates carry one-second resolution, so ``last_modified`` is truncated
to whole seconds before being compared; a naive ``datetime`` is assumed to
be UTC.
"""

from webob.datetime_utils import UTC
from webob.descriptors import parse_etag_response
from webob.etag import AnyETag, ETagMatcher

__all__ = ["evaluate_preconditions", "precondition_response"]

_SAFE_METHODS = ("GET", "HEAD")


def _truncate_to_second(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)

    return dt.replace(microsecond=0)


def evaluate_preconditions(request, resource_exists, etag=None, last_modified=None):
    """
    Evaluate the conditional request headers of ``request`` against the
    current state of the resource.

    :param request: a :class:`webob.request.BaseRequest` (only its method
        and headers are inspected; the request body is never touched).
    :param resource_exists: whether the target resource currently exists.
    :param etag: the current ETag of the resource, as it would appear in
        an ``ETag`` response header (e.g. ``'"abc"'`` or ``'W/"abc"'``),
        or ``None`` if the resource has no ETag.
    :param last_modified: the current modification time of the resource
        as a :class:`datetime.datetime`, or ``None`` if unknown.

    :returns: ``None`` if the request should proceed, otherwise the HTTP
        status code (``304`` or ``412``) that should be returned to the
        client without further processing.
    """
    resource_exists = bool(resource_exists)

    if resource_exists and etag:
        strong_etag = parse_etag_response(etag, strong=True)
        weak_etag = parse_etag_response(etag, strong=False)
    else:
        strong_etag = weak_etag = None

    if resource_exists and last_modified is not None:
        last_modified = _truncate_to_second(last_modified)
    else:
        last_modified = None

    environ = request.environ
    method = request.method

    # 1. If-Match is evaluated first, for every method, using strong
    #    comparison.  "If-Match: *" only requires the resource to exist.
    if_match = environ.get("HTTP_IF_MATCH")

    if if_match and if_match.strip():
        matcher = ETagMatcher.parse(if_match, strong=True)

        if matcher is AnyETag:
            matched = resource_exists
        else:
            matched = strong_etag is not None and strong_etag in matcher

        if not matched:
            return 412
    else:
        # 2. If-Unmodified-Since is only evaluated when If-Match is
        #    absent.  An unparseable date means the header is ignored.
        if_unmodified_since = request.if_unmodified_since

        if (
            if_unmodified_since is not None
            and last_modified is not None
            and last_modified > if_unmodified_since
        ):
            return 412

    # 3. If-None-Match uses weak comparison.  A match means the client's
    #    copy is current: 304 for GET/HEAD, 412 for everything else -- a
    #    failed write must never be disguised as "not modified".
    if_none_match = environ.get("HTTP_IF_NONE_MATCH")

    if if_none_match and if_none_match.strip():
        matcher = ETagMatcher.parse(if_none_match, strong=False)

        if matcher is AnyETag:
            matched = resource_exists
        else:
            matched = weak_etag is not None and weak_etag in matcher

        if matched:
            return 304 if method in _SAFE_METHODS else 412
    elif method in _SAFE_METHODS:
        # 4. If-Modified-Since is only evaluated when If-None-Match is
        #    absent, and only applies to GET/HEAD.
        if_modified_since = request.if_modified_since

        if (
            if_modified_since is not None
            and last_modified is not None
            and last_modified <= if_modified_since
        ):
            return 304

    return None


def precondition_response(request, resource_exists, etag=None, last_modified=None):
    """
    Convenience wrapper around :func:`evaluate_preconditions`.

    :returns: ``None`` if the request should proceed, otherwise a
        :class:`webob.exc.WSGIHTTPException` response (``304 Not
        Modified`` or ``412 Precondition Failed``) that should be returned
        to the client as-is.  A ``304`` response carries the resource's
        ``ETag`` and ``Last-Modified`` headers when they are known.
    """
    status_code = evaluate_preconditions(
        request, resource_exists, etag=etag, last_modified=last_modified
    )

    if status_code is None:
        return None

    from webob.exc import HTTPNotModified, HTTPPreconditionFailed

    if status_code == 304:
        response = HTTPNotModified()

        if etag:
            response.etag = etag

        if last_modified is not None:
            response.last_modified = _truncate_to_second(last_modified)
    else:
        response = HTTPPreconditionFailed()

    return response
