"""Two thin drivers over the same event observer.

Both drivers feed the identical public ijson event tuples into one
:class:`CompletenessObserver`, so a synchronous short read and a push-based
feed produce interchangeable observations.
"""

import ijson

from .observer import CompletenessObserver


def audit_stream(stream, rules, buf_size=65536):
    """Drive ``ijson.parse`` from a binary, short-reading stream."""
    observer = CompletenessObserver(rules)
    try:
        for event in ijson.parse(stream, buf_size=buf_size):
            observer.feed(*event)
    except ijson.IncompleteJSONError as error:
        observer.mark_truncated(error)
    return observer.result


def audit_chunks(chunks, rules):
    """Drive ``ijson.parse_coro`` from caller-pushed byte chunks."""
    observer = CompletenessObserver(rules)
    parser = ijson.parse_coro(observer.coroutine())
    try:
        for chunk in chunks:
            parser.send(chunk)
        parser.close()
    except ijson.IncompleteJSONError as error:
        observer.mark_truncated(error)
    return observer.result


def audit_bytes(data, rules, chunk_size=4096):
    """Convenience wrapper that slices one byte string into push chunks."""
    chunks = [
        data[offset:offset + chunk_size]
        for offset in range(0, len(data), chunk_size)
    ]
    return audit_chunks(chunks, rules)
