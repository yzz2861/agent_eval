import re

from bleach.sanitizer import Cleaner


class ClipboardBoundaryError(ValueError):
    """Raised when clipboard HTML does not identify a reliable fragment."""


_HEADER_LINE_RE = re.compile(
    rb"(Version|StartHTML|EndHTML|StartFragment|EndFragment):([^\r\n]*)"
    rb"(?:\r\n|\n|\r|$)"
)
_START_FRAGMENT_RE = re.compile(rb"<!--StartFragment-->")
_END_FRAGMENT_RE = re.compile(rb"<!--EndFragment-->")


def _clipboard_bytes(html):
    if isinstance(html, bytes):
        return html
    if isinstance(html, str):
        return html.encode("utf-8")
    message = (
        f"argument cannot be of {html.__class__.__name__!r} type, "
        + "must be of text or bytes type"
    )
    raise TypeError(message)


def _read_headers(html):
    headers = {}
    position = 0
    while position < len(html):
        if html[position] in (10, 13):
            break

        match = _HEADER_LINE_RE.match(html, position)
        if match is None:
            break

        name = match.group(1).decode("ascii")
        if name in headers:
            raise ClipboardBoundaryError(f"duplicate clipboard header: {name}")
        value = match.group(2).strip()
        if name == "Version":
            headers[name] = value.decode("ascii")
            position = match.end()
            continue
        try:
            headers[name] = int(value)
        except ValueError as exc:
            raise ClipboardBoundaryError(
                f"invalid clipboard header value: {name}"
            ) from exc
        position = match.end()

    if "Version" not in headers:
        raise ClipboardBoundaryError("missing clipboard header: Version")
    for name in ("StartHTML", "EndHTML", "StartFragment", "EndFragment"):
        if name not in headers:
            raise ClipboardBoundaryError(f"missing clipboard header: {name}")

    return headers


def _marker_span(html, marker_re, name):
    matches = tuple(marker_re.finditer(html))
    if len(matches) != 1:
        raise ClipboardBoundaryError(f"clipboard HTML must contain exactly one {name}")
    match = matches[0]
    return match.start(), match.end()


def extract_clipboard_fragment(html):
    """Return the selected HTML fragment from HTML clipboard data.

    Clipboard offsets are byte offsets into the original HTML payload. String
    input is encoded using UTF-8 before those offsets are checked. The HTML
    header offsets and fragment markers must describe the same byte range.

    :arg html: clipboard HTML as ``bytes`` or UTF-8 ``str``
    :returns: selected fragment decoded as Unicode
    :raises ClipboardBoundaryError: if boundaries are missing, ambiguous, or
        conflict
    :raises TypeError: if ``html`` is not bytes or text

    """
    payload = _clipboard_bytes(html)
    headers = _read_headers(payload)

    if not 0 <= headers["StartHTML"] < headers["EndHTML"] <= len(payload):
        raise ClipboardBoundaryError("invalid HTML byte range in clipboard headers")

    start_position, _ = _marker_span(
        payload, _START_FRAGMENT_RE, "StartFragment marker"
    )
    _, end_position = _marker_span(payload, _END_FRAGMENT_RE, "EndFragment marker")

    if not start_position < end_position <= len(payload):
        raise ClipboardBoundaryError("invalid fragment marker order")
    if not headers["StartHTML"] <= start_position < end_position <= headers["EndHTML"]:
        raise ClipboardBoundaryError(
            "fragment markers are outside the declared HTML range"
        )
    if headers["StartFragment"] != start_position:
        raise ClipboardBoundaryError(
            "StartFragment header and marker do not identify the same byte offset"
        )
    if headers["EndFragment"] != end_position:
        raise ClipboardBoundaryError(
            "EndFragment header and marker do not identify the same byte offset"
        )

    fragment_bytes = payload[start_position:end_position]
    try:
        return fragment_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClipboardBoundaryError(
            "selected clipboard fragment is not valid UTF-8"
        ) from exc


def clean_clipboard_html(
    html,
    tags=...,
    attributes=...,
    protocols=...,
    strip=False,
    strip_comments=True,
    css_sanitizer=...,
    cleaner=None,
):
    """Extract and clean the selected fragment from HTML clipboard data.

    Only the byte range explicitly identified by both the clipboard headers
    and the fragment markers is passed to a :class:`~bleach.sanitizer.Cleaner`.
    Content outside that range, including surrounding page notes, is never
    parsed by the cleaner.

    :arg html: clipboard HTML as ``bytes`` or UTF-8 ``str``
    :arg cleaner: existing ``Cleaner`` instance to use; when omitted, the other
        arguments are used to create one
    :returns: cleaned selected fragment as Unicode
    :raises ClipboardBoundaryError: if boundaries are missing, ambiguous, or
        conflict

    """
    fragment = extract_clipboard_fragment(html)

    if cleaner is None:
        cleaner_kwargs = {
            "strip": strip,
            "strip_comments": strip_comments,
        }
        if css_sanitizer is not ...:
            cleaner_kwargs["css_sanitizer"] = css_sanitizer
        if tags is not ...:
            cleaner_kwargs["tags"] = tags
        if attributes is not ...:
            cleaner_kwargs["attributes"] = attributes
        if protocols is not ...:
            cleaner_kwargs["protocols"] = protocols
        cleaner = Cleaner(**cleaner_kwargs)
    elif any(
        value is not ... for value in (tags, attributes, protocols, css_sanitizer)
    ):
        raise TypeError(
            "cleaner cannot be combined with Cleaner configuration arguments"
        )

    return cleaner.clean(fragment)


clean_clipboard = clean_clipboard_html
