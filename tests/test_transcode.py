import pytest

from webob.request import Request, Transcoder
from webob.response import Response, TranscodeAppIter, transcode_app_iter
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


class OneShotAppIter:
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = 0
        self.iter_count = 0
        self.chunks_read = 0

    def __iter__(self):
        if self.iter_count:
            raise RuntimeError("app_iter can only be iterated once")
        self.iter_count += 1

        def iterator():
            for chunk in self.chunks:
                self.chunks_read += 1
                yield chunk

        return iterator()

    def close(self):
        self.closed += 1


class FailingAppIter:
    def __init__(self):
        self.closed = 0

    def __iter__(self):
        return self

    def __next__(self):
        raise ValueError("boom")

    def close(self):
        self.closed += 1


def byte_chunks(data):
    return [bytes([byte]) for byte in data]


def test_transcode_app_iter_incrementally_handles_split_multibyte_characters():
    source = "世界，你好！"
    app_iter = OneShotAppIter(byte_chunks(source.encode("utf-8")))
    result = transcode_app_iter(app_iter, "utf-8", "utf-16")

    assert isinstance(result, TranscodeAppIter)
    assert b"".join(result).decode("utf-16") == source
    assert app_iter.iter_count == 1
    assert app_iter.chunks_read == len(byte_chunks(source.encode("utf-8")))

    result.close()
    assert app_iter.closed == 1


def test_transcode_app_iter_decodes_and_encodes_boms():
    source = b"\xef\xbb\xbf\xc3\xa9"
    result = transcode_app_iter(byte_chunks(source), "utf-8-sig", "utf-16")

    assert b"".join(result) == b"\xff\xfe\xe9\x00"


def test_transcode_app_iter_flushes_encoder_on_completion():
    result = transcode_app_iter([b"example", b".com"], "ascii", "idna")
    assert b"".join(result) == b"example.com"


def test_transcode_app_iter_error_policy_is_caller_selected():
    result = transcode_app_iter(byte_chunks(b"\xffok"), "cp1251", "ascii", "replace")

    assert b"".join(result) == b"?ok"


def test_transcode_app_iter_closes_once_on_error():
    app_iter = FailingAppIter()
    result = transcode_app_iter(app_iter, "ascii")

    with pytest.raises(ValueError):
        next(result)

    result.close()
    result.close()
    assert app_iter.closed == 1


def test_transcode_app_iter_closes_once_on_early_close():
    app_iter = OneShotAppIter([b"a", b"b"])
    result = transcode_app_iter(app_iter, "ascii")

    assert next(result) == b"a"
    result.close()
    result.close()

    assert app_iter.closed == 1
    with pytest.raises(StopIteration):
        next(result)


def test_response_transcode_does_not_consume_app_iter_or_buffer_chunks():
    app_iter = OneShotAppIter(byte_chunks(b"\xef\xf0\xe8\xe2\xe5\xf2"))
    response = Response(
        headerlist=[
            ("Content-Type", "text/plain; charset=windows-1251"),
            ("Content-Length", "6"),
            ("Content-MD5", "stale"),
            ("ETag", 'W/"weak"'),
        ],
        app_iter=app_iter,
    )

    result = response.transcode()

    assert result is None
    assert app_iter.iter_count == 1
    assert app_iter.chunks_read == 0
    assert response.content_length is None
    assert response.content_md5 is None
    assert response.etag == "weak"
    assert response.charset == "UTF-8"
    assert response.body == "привет".encode("utf-8")
    assert app_iter.closed == 1


def test_response_transcode_rejects_content_encoding():
    response = Response(app_iter=[b"abc"], content_encoding="gzip")

    with pytest.raises(ValueError):
        response.transcode("utf-8")


def test_response_transcode_rejects_identity_content_encoding():
    response = Response(app_iter=[b"abc"], content_encoding="identity")

    with pytest.raises(ValueError):
        response.transcode("utf-8")


def test_response_transcode_invalid_charset_closes_source_once():
    app_iter = OneShotAppIter([b"abc"])
    response = Response(
        headerlist=[
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", "3"),
        ],
        app_iter=app_iter,
    )

    with pytest.raises(LookupError):
        response.transcode("utf-8", "not-a-charset")

    assert app_iter.closed == 1
    assert response.content_length == 3


def test_response_transcode_head_does_not_iterate_body():
    app_iter = OneShotAppIter([b"\xef\xf0"])
    response = Response(
        headerlist=[("Content-Type", "text/plain; charset=windows-1251")],
        app_iter=app_iter,
    )
    response.transcode()

    result = Request.blank("/", method="HEAD").get_response(response)

    assert result.body == b""
    assert app_iter.iter_count == 1
    assert app_iter.chunks_read == 0
    assert app_iter.closed == 1
