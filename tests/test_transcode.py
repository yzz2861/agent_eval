import codecs

import pytest

from webob.request import Request, Transcoder
from webob.response import Response
from webob.transcode import (
    StreamTranscoder,
    TranscodeMiddleware,
    TranscodingAppIter,
    transcode_response,
)
from webob.util import text_

t1 = (
    b'--BOUNDARY\r\nContent-Disposition: form-data; name="a"\r\n\r\n\xea\xf3...'
    b"\r\n--BOUNDARY--"
)
t2 = (
    b'--BOUNDARY\r\nContent-Disposition: form-data; name="a"; filename="file"\r\n'
    b"\r\n\xea\xf3...\r\n--BOUNDARY--"
)
t3 = (
    b'--BOUNDARY\r\nContent-Disposition: form-data; name="a"; filename="\xea\xf3...'
    b'"\r\n\r\nfoo\r\n--BOUNDARY--'
)


def test_transcode():
    def tapp(env, sr):
        req = Request(env)
        req = req.decode()

        v = req.POST[req.query_string]

        if hasattr(v, "filename"):
            r = Response(text_(f"{v.filename}\n{v.value!r}"))
        else:
            r = Response(v)

        return r(env, sr)

    text = b"\xea\xf3...".decode("cp1251")

    def test(post):
        req = Request.blank("/?a", POST=post)
        req.environ["CONTENT_TYPE"] = (
            "multipart/form-data; charset=windows-1251; boundary=BOUNDARY"
        )

        return req.get_response(tapp)

    r = test(t1)
    assert r.text == text
    r = test(t2)
    assert r.text == "file\n%r" % text.encode("cp1251")
    r = test(t3)
    assert r.text == "{}\n{!r}".format(text, b"foo")


def test_transcode_query():
    req = Request.blank("/?%EF%F0%E8=%E2%E5%F2")
    req2 = req.decode("cp1251")
    assert req2.query_string == "%D0%BF%D1%80%D0%B8=%D0%B2%D0%B5%D1%82"


def test_transcode_non_multipart():
    req = Request.blank("/?a", POST="%EF%F0%E8=%E2%E5%F2")
    req._content_type_raw = "application/x-www-form-urlencoded"
    req2 = req.decode("cp1251")
    assert text_(req2.body) == "%D0%BF%D1%80%D0%B8=%D0%B2%D0%B5%D1%82"


def test_transcode_non_form():
    req = Request.blank("/?a", POST="%EF%F0%E8=%E2%E5%F2")
    req._content_type_raw = "application/x-foo"
    req2 = req.decode("cp1251")
    assert text_(req2.body) == "%EF%F0%E8=%E2%E5%F2"


def test_transcode_noop():
    req = Request.blank("/")
    assert req.decode() is req


def test_transcode_query_ascii():
    t = Transcoder("ascii")
    assert t.transcode_query("a") == "a"


class CloseTrackingIter:
    """A read-once byte iterator that records pulls and close() calls."""

    def __init__(self, chunks, error=None):
        self._chunks = chunks
        self._error = error
        self.pulled = 0
        self.close_count = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.pulled >= len(self._chunks):
            if self._error is not None:
                raise self._error
            raise StopIteration
        chunk = self._chunks[self.pulled]
        self.pulled += 1

        return chunk

    next = __next__

    def close(self):
        self.close_count += 1


def byte_chunks(data):
    return [data[i : i + 1] for i in range(len(data))]


def test_stream_transcoder_byte_by_byte():
    text = "\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440!"
    source = text.encode("cp1251")
    transcoder = StreamTranscoder("cp1251", "utf-8")
    out = [transcoder.transcode(chunk) for chunk in byte_chunks(source)]
    out.append(transcoder.transcode(b"", final=True))
    assert b"".join(out) == text.encode("utf-8")


def test_stream_transcoder_split_multibyte_and_bom():
    data = codecs.BOM_UTF8 + "h\u00e9llo".encode("utf-8")
    transcoder = StreamTranscoder("utf-8-sig", "utf-8")
    out = [transcoder.transcode(chunk) for chunk in byte_chunks(data)]
    out.append(transcoder.transcode(b"", final=True))
    assert b"".join(out) == "h\u00e9llo".encode("utf-8")


def test_stream_transcoder_utf16_bom():
    data = "\u043f\u0440\u0438\u0432\u0435\u0442".encode("utf-16")
    transcoder = StreamTranscoder("utf-16", "utf-8")
    out = [transcoder.transcode(chunk) for chunk in byte_chunks(data)]
    out.append(transcoder.transcode(b"", final=True))
    assert b"".join(out) == "\u043f\u0440\u0438\u0432\u0435\u0442".encode("utf-8")


def test_stream_transcoder_encoder_final_flush():
    transcoder = StreamTranscoder("utf-8", "iso2022jp")
    body = transcoder.transcode("\u3042".encode("utf-8"))
    tail = transcoder.transcode(b"", final=True)
    assert body + tail == "\u3042".encode("iso2022jp")
    assert tail == b"\x1b(B"


def test_stream_transcoder_decoder_flush_uses_error_strategy():
    transcoder = StreamTranscoder("utf-8", "utf-8", errors="replace")
    out = transcoder.transcode(b"abc\xc3")
    out += transcoder.transcode(b"", final=True)
    assert out == "abc\ufffd".encode("utf-8")


def test_stream_transcoder_strict_errors():
    transcoder = StreamTranscoder("utf-8", "utf-8")
    with pytest.raises(UnicodeDecodeError):
        transcoder.transcode(b"\xff")


def test_app_iter_transcodes_read_once_byte_by_byte():
    text = "\u041f\u0440\u0438\u0432\u0435\u0442"
    source = CloseTrackingIter(byte_chunks(text.encode("cp1251")))
    app_iter = TranscodingAppIter(source, "cp1251", "utf-8")
    assert not hasattr(app_iter, "__len__")
    assert b"".join(app_iter) == text.encode("utf-8")
    app_iter.close()
    app_iter.close()
    assert source.close_count == 1


def test_app_iter_is_lazy():
    source = CloseTrackingIter([b"ab", b"cd"], error=RuntimeError("boom"))
    app_iter = TranscodingAppIter(source, "cp1251", "utf-8")
    assert next(app_iter) == b"ab"
    assert source.pulled == 1


def test_app_iter_closes_source_once_on_error():
    source = CloseTrackingIter([b"ab", b"cd"], error=RuntimeError("boom"))
    app_iter = TranscodingAppIter(source, "cp1251", "utf-8")
    with pytest.raises(RuntimeError):
        list(app_iter)
    app_iter.close()
    assert source.close_count == 1


def test_app_iter_closes_source_once_on_decode_error():
    source = CloseTrackingIter([b"\xff"])
    app_iter = TranscodingAppIter(source, "utf-8", "utf-8")
    with pytest.raises(UnicodeDecodeError):
        next(app_iter)
    app_iter.close()
    assert source.close_count == 1


def test_app_iter_early_close_closes_source_once():
    body = "\u041f\u0440\u0438\u0432\u0435\u0442".encode("cp1251")
    source = CloseTrackingIter(byte_chunks(body))
    app_iter = TranscodingAppIter(source, "cp1251", "utf-8")
    next(app_iter)
    app_iter.close()
    app_iter.close()
    assert source.close_count == 1
    with pytest.raises(StopIteration):
        next(app_iter)


def test_transcode_response_streams_and_fixes_headers():
    text = "\u041f\u0440\u0438\u0432\u0435\u0442"
    body = text.encode("cp1251")
    response = Response(body=body, content_type="text/plain", charset="cp1251")
    response.etag = "some-tag"
    response.content_md5 = "deadbeef"
    assert response.content_length == len(body)

    response = transcode_response(response, "utf-8")

    assert response.charset == "utf-8"
    assert response.content_length is None
    assert response.etag is None
    assert response.content_md5 is None
    assert b"".join(response.app_iter) == text.encode("utf-8")


def test_transcode_response_refuses_content_encoded():
    response = Response(body=b"hello", content_type="text/plain")
    response.content_encoding = "gzip"
    with pytest.raises(ValueError):
        transcode_response(response, "utf-8")


def test_transcode_response_requires_known_source_charset():
    response = Response(body=b"\xff", content_type="application/octet-stream")
    with pytest.raises(ValueError):
        transcode_response(response, "utf-8")


def test_transcode_response_same_charset_is_noop():
    response = Response(body="h\u00e9llo", content_type="text/plain", charset="utf-8")
    response.etag = "tag"
    app_iter = response.app_iter
    response = transcode_response(response, "UTF-8")
    assert response.app_iter is app_iter
    assert response.etag == "tag"
    assert response.content_length is not None


def make_app(headers, chunks):
    def app(environ, start_response):
        start_response("200 OK", headers)

        return chunks

    return app


def call_wsgi(app, method="GET"):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    environ = Request.blank("/", method=method).environ
    app_iter = app(environ, start_response)

    try:
        body = b"".join(app_iter)
    finally:
        if hasattr(app_iter, "close"):
            app_iter.close()

    return captured, body


def test_middleware_transcodes_response():
    text = "\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440"
    body = text.encode("cp1251")
    tracker = CloseTrackingIter(byte_chunks(body))
    app = make_app(
        [
            ("Content-Type", "text/plain; charset=cp1251"),
            ("Content-Length", str(len(body))),
            ("ETag", '"abc"'),
            ("Content-MD5", "xyz"),
        ],
        tracker,
    )
    captured, result = call_wsgi(TranscodeMiddleware(app, "utf-8"))
    headers = dict(captured["headers"])
    assert result == text.encode("utf-8")
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    assert "Content-Length" not in headers
    assert "ETag" not in headers
    assert "Content-MD5" not in headers
    assert tracker.close_count == 1


def test_middleware_explicit_from_charset():
    body = "\u041f\u0440\u0438\u0432\u0435\u0442".encode("cp1251")
    tracker = CloseTrackingIter(byte_chunks(body))
    app = make_app([("Content-Type", "text/plain")], tracker)
    mw = TranscodeMiddleware(app, "utf-8", from_charset="cp1251")
    resp = Request.blank("/").get_response(mw)
    assert resp.text == "\u041f\u0440\u0438\u0432\u0435\u0442"


def test_middleware_head_does_not_iterate_body():
    body = "\u041f\u0440\u0438\u0432\u0435\u0442".encode("cp1251")
    tracker = CloseTrackingIter(byte_chunks(body))
    app = make_app(
        [
            ("Content-Type", "text/plain; charset=cp1251"),
            ("Content-Length", str(len(body))),
        ],
        tracker,
    )
    captured, result = call_wsgi(TranscodeMiddleware(app, "utf-8"), method="HEAD")
    headers = dict(captured["headers"])
    assert result == b""
    assert tracker.pulled == 0
    assert tracker.close_count == 1
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    assert "Content-Length" not in headers


def test_middleware_rejects_content_encoding_and_closes_once():
    tracker = CloseTrackingIter([b"data"])
    app = make_app(
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Encoding", "gzip"),
        ],
        tracker,
    )
    req = Request.blank("/")
    with pytest.raises(ValueError):
        req.get_response(TranscodeMiddleware(app, "utf-8"))
    assert tracker.close_count == 1
