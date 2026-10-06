"""
Explicit streaming transcoding of response bodies between charsets.

Legacy applications may emit text in a charset other than the one the
gateway wants to serve.  Buffering the whole body to re-encode it (or
mutating ``Response.charset`` after the fact) defeats streaming, so this
module provides an incremental pipeline instead:

* :class:`StreamTranscoder` incrementally decodes bytes from the source
  charset and re-encodes them to the target charset.  It deals with BOMs
  (via codecs such as ``utf-8-sig`` or ``utf-16``), multi-byte characters
  split across chunks, and the final encoder/decoder flush.

* :class:`TranscodingAppIter` wraps a WSGI ``app_iter`` and transcodes it
  chunk by chunk without buffering the whole body.  The wrapped iterable
  is closed exactly once, whether iteration completes, fails, or is
  closed early by the server.

* :func:`transcode_response` rewrites a :class:`webob.Response` in place
  so its body is transcoded on the fly, updating or dropping the headers
  that transcoding invalidates (``Content-Length``, ``ETag`` and
  ``Content-MD5``).

* :class:`TranscodeMiddleware` applies :func:`transcode_response` to the
  responses of a wrapped WSGI application.  ``HEAD`` requests get the
  same header treatment without the body ever being iterated.
"""

import codecs

from webob.response import Response

__all__ = [
    "StreamTranscoder",
    "TranscodingAppIter",
    "transcode_response",
    "TranscodeMiddleware",
]


class StreamTranscoder:
    """
    Incrementally transcode a byte stream from one charset to another.

    ``errors`` is the error handling strategy (``"strict"``, ``"replace"``,
    ``"ignore"``, ...) used for both decoding and encoding; it is chosen
    by the caller, never guessed.
    """

    def __init__(self, from_charset, to_charset, errors="strict"):
        self.from_charset = from_charset
        self.to_charset = to_charset
        self.errors = errors
        self._decoder = codecs.getincrementaldecoder(from_charset)(errors)
        self._encoder = codecs.getincrementalencoder(to_charset)(errors)

    def transcode(self, data, final=False):
        """
        Transcode the next chunk of bytes.

        Pass ``final=True`` with the last chunk (possibly ``b""``) to flush
        the decoder and encoder state machines; this is what emits e.g. a
        replacement character for a truncated multi-byte sequence or the
        shift-back escape sequence of stateful codecs such as ISO-2022-JP.
        """
        return self._encoder.encode(self._decoder.decode(data, final), final)


class TranscodingAppIter:
    """
    A WSGI ``app_iter`` wrapper that transcodes its chunks on the fly.

    The wrapped iterable is only ever pulled from as needed (nothing is
    buffered beyond the incremental codec state) and its ``close()`` is
    called exactly once, including when iteration raises or the server
    closes the response early.
    """

    def __init__(self, app_iter, from_charset, to_charset, errors="strict"):
        self._app_iter = app_iter
        self._iterator = iter(app_iter)
        self._transcoder = StreamTranscoder(from_charset, to_charset, errors)
        self._closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self._closed:
            raise StopIteration

        while True:
            try:
                chunk = next(self._iterator)
            except StopIteration:
                # Source exhausted: flush the codecs, close the source and
                # emit whatever the final flush produced (if anything).
                try:
                    tail = self._transcoder.transcode(b"", final=True)
                except Exception:
                    self.close()
                    raise
                self.close()

                if tail:
                    return tail
                raise
            except Exception:
                self.close()
                raise

            try:
                output = self._transcoder.transcode(chunk)
            except Exception:
                self.close()
                raise

            if output:
                return output
            # The chunk was entirely absorbed by the incremental codecs
            # (e.g. part of a split multi-byte character); keep pulling.

    next = __next__

    def close(self):
        if not self._closed:
            self._closed = True
            close = getattr(self._app_iter, "close", None)

            if close is not None:
                close()


def transcode_response(response, to_charset, from_charset=None, errors="strict"):
    """
    Rewrite ``response`` so that its body is transcoded from
    ``from_charset`` to ``to_charset`` while it streams.

    ``from_charset`` defaults to the charset declared in the response's
    ``Content-Type``; if none is declared a ``ValueError`` is raised --
    the source charset is never guessed.  ``errors`` selects the codec
    error handling strategy for both directions.

    Responses carrying a ``Content-Encoding`` (gzip, deflate, ...) are
    rejected with a ``ValueError``; decode them first (e.g. with
    ``Response.decode_content()``).

    Transcoding changes the bytes on the wire, so ``Content-Length``,
    ``ETag`` and ``Content-MD5`` are dropped and the ``charset`` parameter
    of ``Content-Type`` is updated.  If the source and target charsets are
    the same, the response is returned untouched.
    """
    content_encoding = response.content_encoding

    if content_encoding and content_encoding.lower() != "identity":
        raise ValueError(
            "Cannot transcode a response with Content-Encoding: %r; "
            "decode the body first (e.g. response.decode_content())"
            % content_encoding
        )

    if from_charset is None:
        from_charset = response.charset

        if from_charset is None:
            raise ValueError(
                "No source charset was given and the response Content-Type "
                "does not declare one"
            )

    if codecs.lookup(from_charset) == codecs.lookup(to_charset):
        return response

    response.app_iter = TranscodingAppIter(
        response.app_iter, from_charset, to_charset, errors
    )
    # The original byte count and byte-level validators no longer apply.
    response.content_length = None
    response.etag = None
    response.content_md5 = None

    if response.content_type is not None:
        response.charset = to_charset

    return response


class TranscodeMiddleware:
    """
    WSGI middleware that transcodes the wrapped application's responses.

    ``from_charset`` defaults to the charset each response declares in its
    ``Content-Type`` header; responses that declare none cause a
    ``ValueError`` rather than a guess.  ``HEAD`` responses get the same
    header treatment but the body is never iterated to get there.
    """

    def __init__(self, app, to_charset, from_charset=None, errors="strict"):
        self.app = app
        self.to_charset = to_charset
        self.from_charset = from_charset
        self.errors = errors

    def __call__(self, environ, start_response):
        captured = []

        def capture_start_response(status, headers, exc_info=None):
            captured.append((status, headers, exc_info))

        app_iter = self.app(environ, capture_start_response)

        try:
            status, headers, exc_info = captured[0]

            response = Response(status=status, headerlist=headers, app_iter=app_iter)
            response = transcode_response(
                response, self.to_charset, self.from_charset, self.errors
            )
        except Exception:
            _iter_close(app_iter)
            raise

        start_response(response.status, response.headerlist, exc_info)

        if environ.get("REQUEST_METHOD") == "HEAD":
            # No body is sent for HEAD, so don't iterate it just to find
            # out how long it is; closing also releases the source.
            _iter_close(response.app_iter)

            return []

        return response.app_iter


def _iter_close(app_iter):
    close = getattr(app_iter, "close", None)

    if close is not None:
        close()
