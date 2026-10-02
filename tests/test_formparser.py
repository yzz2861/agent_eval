import io
import os
from os.path import dirname
from os.path import join

import pytest

from werkzeug import formparser
from werkzeug.datastructures import ImmutableMultiDict
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.formparser import FormDataParser
from werkzeug.formparser import parse_form_data
from werkzeug.test import Client
from werkzeug.test import create_environ
from werkzeug.wrappers import Request
from werkzeug.wrappers import Response


@Request.application
def form_data_consumer(request):
    result_object = request.args["object"]
    if result_object == "text":
        return Response(repr(request.form["text"]))
    f = request.files[result_object]
    return Response(
        b"\n".join(
            (
                repr(f.filename).encode("ascii"),
                repr(f.name).encode("ascii"),
                repr(f.content_type).encode("ascii"),
                f.stream.read(),
            )
        )
    )


def get_contents(filename):
    with open(filename, "rb") as f:
        return f.read()


class TestFormParser:
    def test_limiting(self):
        data = b"foo=Hello+World&bar=baz"
        req = Request.from_values(
            data=data,
            content_type="application/x-www-form-urlencoded",
            method="POST",
        )
        req.max_content_length = 400
        assert req.form["foo"] == "Hello World"

        input_stream = io.BytesIO(b"foo=123456")
        req = Request.from_values(
            input_stream=input_stream,
            content_type="application/x-www-form-urlencoded",
            method="POST",
        )
        req.max_content_length = 4
        pytest.raises(RequestEntityTooLarge, lambda: req.form["foo"])
        # content-length was set, so request could exit early without reading anything
        assert input_stream.read() == b"foo=123456"

        data = (
            b"--foo\r\nContent-Disposition: form-field; name=foo\r\n\r\n"
            b"Hello World\r\n"
            b"--foo\r\nContent-Disposition: form-field; name=bar\r\n\r\n"
            b"bar=baz\r\n--foo--"
        )

        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            req.max_content_length = 400
            assert req.form["foo"] == "Hello World"

        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            req.max_form_memory_size = 7
            pytest.raises(RequestEntityTooLarge, lambda: req.form["foo"])

        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            req.max_form_memory_size = 400
            assert req.form["foo"] == "Hello World"

        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            req.max_form_parts = 1
            pytest.raises(RequestEntityTooLarge, lambda: req.form["foo"])

    def test_urlencoded_no_max(self) -> None:
        r = Request.from_values(method="POST", data={"a": 1, "b": 2})
        r.max_form_parts = 1

        assert r.form["a"] == "1"
        assert r.form["b"] == "2"

    def test_urlencoded_silent_decode(self) -> None:
        r = Request.from_values(
            data=b"\x80",
            content_type="application/x-www-form-urlencoded",
            method="POST",
        )
        assert not r.form

    def test_missing_multipart_boundary(self):
        data = (
            b"--foo\r\nContent-Disposition: form-field; name=foo\r\n\r\n"
            b"Hello World\r\n"
            b"--foo\r\nContent-Disposition: form-field; name=bar\r\n\r\n"
            b"bar=baz\r\n--foo--"
        )
        with Request.from_values(
            data=data,
            content_type="multipart/form-data",
            method="POST",
        ) as req:
            assert req.form == {}

    def test_chunk_split_on_line_break_before_epilogue(self):
        data = b"".join(
            (
                # exactly 64 bytes of header
                b"--thirteenbytes\r\n",
                b"Content-Disposition: form-data; name=tx3065\r\n\r\n",
                # payload that fills 65535 bytes together with the header
                b"\n".join([b"\r" * 31] * 2045 + [b"y" * 31]),
                # This newline is split by the first chunk
                b"\r\n",
                # extra payload that also has the final newline split exactly
                # at the chunk size.
                b"\n".join([b"\r" * 31] * 2047 + [b"x" * 30]),
                b"\r\n--thirteenbytes--",
            )
        )

        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=thirteenbytes",
            method="POST",
        ) as req:
            assert len(req.form["tx3065"]) == (131072 - 64 - 1)
            assert req.form["tx3065"][-1] == "x"
            assert req.form["tx3065"][65470:65473] == "y\r\n"

    def test_parse_form_data_put_without_content(self):
        # A PUT without a Content-Type header returns empty data

        # Both rfc1945 and rfc2616 (1.0 and 1.1) say "Any HTTP/[1.0/1.1] message
        # containing an entity-body SHOULD include a Content-Type header field
        # defining the media type of that body."  In the case where either
        # headers are omitted, parse_form_data should still work.
        env = create_environ("/foo", "http://example.org/", method="PUT")

        stream, form, files, parts = formparser.parse_form_data(env)
        assert stream.read() == b""
        assert len(form) == 0
        assert len(files) == 0

    def test_parse_form_data_get_without_content(self):
        env = create_environ("/foo", "http://example.org/", method="GET")

        stream, form, files, parts = formparser.parse_form_data(env)
        assert stream.read() == b""
        assert len(form) == 0
        assert len(files) == 0

    def test_parse_form_post_data_trailing_CR(self):
        for k in [1, 2]:
            sample = b"\0" * 65535 + b"\x0d" * k
            with Request.from_values(
                data={"foo": (io.BytesIO(sample), "test.txt")}, method="POST"
            ) as req:
                assert req.files["foo"].read() == sample

    def test_parse_bad_content_type(self):
        parser = FormDataParser()
        assert parser.parse("", "bad-mime-type", 0) == (
            "",
            MultiDict([]),
            MultiDict([]),
            (),
        )

    def test_parse_from_environ(self):
        parser = FormDataParser()
        stream, _, _, _ = parser.parse_from_environ({"wsgi.input": ""})
        assert stream is not None


class TestMultiPart:
    def test_basic(self):
        resources = join(dirname(__file__), "multipart")
        client = Client(form_data_consumer)

        repository = [
            (
                "firefox3-2png1txt",
                "---------------------------186454651713519341951581030105",
                [
                    ("anchor.png", "file1", "image/png", "file1.png"),
                    ("application_edit.png", "file2", "image/png", "file2.png"),
                ],
                "example text",
            ),
            (
                "firefox3-2pnglongtext",
                "---------------------------14904044739787191031754711748",
                [
                    ("accept.png", "file1", "image/png", "file1.png"),
                    ("add.png", "file2", "image/png", "file2.png"),
                ],
                "--long text\r\n--with boundary\r\n--lookalikes--",
            ),
            (
                "opera8-2png1txt",
                "----------zEO9jQKmLc2Cq88c23Dx19",
                [
                    ("arrow_branch.png", "file1", "image/png", "file1.png"),
                    ("award_star_bronze_1.png", "file2", "image/png", "file2.png"),
                ],
                "blafasel öäü",
            ),
            (
                "webkit3-2png1txt",
                "----WebKitFormBoundaryjdSFhcARk8fyGNy6",
                [
                    ("gtk-apply.png", "file1", "image/png", "file1.png"),
                    ("gtk-no.png", "file2", "image/png", "file2.png"),
                ],
                "this is another text with ümläüts",
            ),
            (
                "ie6-2png1txt",
                "---------------------------7d91b03a20128",
                [
                    ("file1.png", "file1", "image/x-png", "file1.png"),
                    ("file2.png", "file2", "image/x-png", "file2.png"),
                ],
                "ie6 sucks :-/",
            ),
        ]

        for name, boundary, files, text in repository:
            folder = join(resources, name)
            data = get_contents(join(folder, "request.http"))
            for filename, field, content_type, fsname in files:
                with client.post(
                    f"/?object={field}",
                    data=data,
                    content_type=f'multipart/form-data; boundary="{boundary}"',
                    content_length=len(data),
                ) as response:
                    lines = response.get_data().split(b"\n", 3)
                    assert lines[0] == repr(filename).encode("ascii")
                    assert lines[1] == repr(field).encode("ascii")
                    assert lines[2] == repr(content_type).encode("ascii")
                    assert lines[3] == get_contents(join(folder, fsname))

            with client.post(
                "/?object=text",
                data=data,
                content_type=f'multipart/form-data; boundary="{boundary}"',
                content_length=len(data),
            ) as response:
                assert response.get_data() == repr(text).encode()

    def test_ie7_unc_path(self):
        client = Client(form_data_consumer)
        data_file = join(dirname(__file__), "multipart", "ie7_full_path_request.http")
        data = get_contents(data_file)
        boundary = "---------------------------7da36d1b4a0164"
        with client.post(
            "/?object=cb_file_upload_multiple",
            data=data,
            content_type=f'multipart/form-data; boundary="{boundary}"',
            content_length=len(data),
        ) as response:
            lines = response.get_data().split(b"\n", 3)
            assert lines[0] == b"'Sellersburg Town Council Meeting 02-22-2010doc.doc'"

    def test_premature_end_of_file(self):
        data = (
            b"--foo\r\n"
            b'Content-Disposition: form-data; name="test"; filename="test.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"file contents and no end"
        )
        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            assert not req.files
            assert not req.form

    def test_file_no_content_type(self):
        data = (
            b"--foo\r\n"
            b'Content-Disposition: form-data; name="test"; filename="test.txt"\r\n\r\n'
            b"file contents\r\n--foo--"
        )
        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as data:
            assert data.files["test"].filename == "test.txt"
            assert data.files["test"].read() == b"file contents"

    def test_extra_newline(self):
        # this test looks innocent but it was actually timing out in
        # the Werkzeug 0.5 release version (#394)
        data = (
            b"\r\n\r\n--foo\r\n"
            b'Content-Disposition: form-data; name="foo"\r\n\r\n'
            b"a string\r\n"
            b"--foo--"
        )
        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            assert not req.files
            assert req.form["foo"] == "a string"

    def test_headers(self):
        data = (
            b"--foo\r\n"
            b'Content-Disposition: form-data; name="foo"; filename="foo.txt"\r\n'
            b"X-Custom-Header: blah\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"file contents, just the contents\r\n"
            b"--foo--"
        )
        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            foo = req.files["foo"]
            assert foo.mimetype == "text/plain"
            assert foo.mimetype_params == {"charset": "utf-8"}
            assert foo.headers["Content-Type"] == foo.content_type
            assert foo.content_type == "text/plain; charset=utf-8"
            assert foo.headers["X-Custom-Header"] == "blah"

    @pytest.mark.parametrize("ending", [b"\n", b"\r", b"\r\n"])
    def test_nonstandard_line_endings(self, ending: bytes):
        data = ending.join(
            (
                b"--foo",
                b"Content-Disposition: form-data; name=foo",
                b"",
                b"this is just bar",
                b"--foo",
                b"Content-Disposition: form-data; name=bar",
                b"",
                b"blafasel",
                b"--foo--",
            )
        )
        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as req:
            assert req.form["foo"] == "this is just bar"
            assert req.form["bar"] == "blafasel"

    def test_failures(self):
        def parse_multipart(stream, boundary, content_length):
            parser = formparser.MultiPartParser(content_length)
            return parser.parse(stream, boundary, content_length)

        data = b"--foo\r\n\r\nHello World\r\n--foo--"
        pytest.raises(ValueError, parse_multipart, io.BytesIO(data), b"foo", len(data))

        data = (
            b"--foo\r\nContent-Disposition: form-field; name=foo\r\n\r\nHello World\r\n"
        )
        pytest.raises(ValueError, parse_multipart, io.BytesIO(data), b"foo", len(data))

    def test_empty_multipart(self):
        environ = {}
        data = b"--boundary--"
        environ["REQUEST_METHOD"] = "POST"
        environ["CONTENT_TYPE"] = "multipart/form-data; boundary=boundary"
        environ["CONTENT_LENGTH"] = str(len(data))
        environ["wsgi.input"] = io.BytesIO(data)
        stream, form, files, parts = parse_form_data(environ, silent=False)
        rv = stream.read()
        assert rv == b""
        assert form == ImmutableMultiDict()
        assert files == ImmutableMultiDict()
        assert parts == ()


class TestMultiPartParser:
    def test_file_rfc2231_filename_continuations(self):
        data = (
            b"--foo\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Disposition: form-data; name=rfc2231;\r\n"
            b"	filename*0*=ascii''a%20b%20;\r\n"
            b"	filename*1*=c%20d%20;\r\n"
            b'	filename*2="e f.txt"\r\n\r\n'
            b"file contents\r\n--foo--"
        )
        with Request.from_values(
            data=data,
            content_type="multipart/form-data; boundary=foo",
            method="POST",
        ) as request:
            assert request.files["rfc2231"].filename == "a b c d e f.txt"
            assert request.files["rfc2231"].read() == b"file contents"


def test_multipart_max_form_memory_size() -> None:
    """max_form_memory_size is tracked across multiple data events."""
    data = b"--bound\r\nContent-Disposition: form-field; name=a\r\n\r\n"
    data += b"a" * 15 + b"\r\n--bound--"
    # The buffer size is less than the max size, so multiple data events will be
    # returned. The field size is greater than the max.
    parser = formparser.MultiPartParser(max_form_memory_size=10, buffer_size=5)

    with pytest.raises(RequestEntityTooLarge):
        parser.parse(io.BytesIO(data), b"bound", None)


def _interleaved_multipart() -> tuple[bytes, str]:
    boundary = "b"
    data = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="note"\r\n\r\n'
        b"first description\r\n"
        b"--b\r\n"
        b'Content-Disposition: form-data; name="note"; filename="a.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n"
        b"first file\r\n"
        b"--b\r\n"
        b'Content-Disposition: form-data; name="note"\r\n\r\n'
        b"second description\r\n"
        b"--b\r\n"
        b'Content-Disposition: form-data; name="note"; filename="b.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n"
        b"second file\r\n--b--"
    )
    return data, f"multipart/form-data; boundary={boundary}"


class TestOrderedParts:
    def test_parts_preserve_interleaved_order(self) -> None:
        data, content_type = _interleaved_multipart()

        with Request.from_values(
            data=data, content_type=content_type, method="POST"
        ) as request:
            parts = request.parts

            assert [part.name for part in parts] == ["note"] * 4
            assert [part.text for part in parts[::2]] == [
                "first description",
                "second description",
            ]
            assert [part.file.filename for part in parts[1::2]] == [
                "a.txt",
                "b.txt",
            ]
            assert parts[0].headers["Content-Disposition"].startswith(
                "form-data"
            )
            assert parts[1].headers["Content-Type"] == "text/plain"

            # Same-named fields and files are not merged away.
            assert request.form.getlist("note") == [
                "first description",
                "second description",
            ]
            assert [f.filename for f in request.files.getlist("note")] == [
                "a.txt",
                "b.txt",
            ]

    @pytest.mark.parametrize("first", ["parts", "form", "files"])
    def test_parts_share_one_parse(self, first: str) -> None:
        data, content_type = _interleaved_multipart()
        reads = 0

        class TrackingInput:
            def read(self, size: int) -> bytes:
                nonlocal reads
                reads += 1
                return input_stream.read(size)

        input_stream = io.BytesIO(data)
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(len(data)),
            "wsgi.input": TrackingInput(),
        }
        request = Request(environ)

        getattr(request, first)
        reads_after_first = reads

        assert request.form.getlist("note") == [
            "first description",
            "second description",
        ]
        file_parts = [part.file for part in request.parts if part.file]
        assert file_parts == request.files.getlist("note")
        assert [file_part.read() for file_part in file_parts] == [
            b"first file",
            b"second file",
        ]
        # The streams are shared, not copied: reading through parts moved the
        # cursor seen through files.
        assert [f.read() for f in request.files.getlist("note")] == [b"", b""]
        assert reads == reads_after_first
        request.close()

    def test_parts_share_file_objects_without_copy(self) -> None:
        data, content_type = _interleaved_multipart()

        with Request.from_values(
            data=data, content_type=content_type, method="POST"
        ) as request:
            files = request.files.getlist("note")
            file_parts = [part.file for part in request.parts if part.file]

            assert file_parts == files
            assert [part_file.stream for part_file in file_parts] == [
                file.stream for file in files
            ]
            # Reading from the parts view does not consume a separate copy.
            assert file_parts[0].read() == b"first file"
            assert files[0].read() == b""
            files[0].seek(0)
            assert files[0].read() == b"first file"

    def test_disk_file_is_shared_and_closed_once(self) -> None:
        payload = b"x" * 1024
        data = (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="note"\r\n\r\n'
            b"description\r\n"
            b"--b\r\n"
            b'Content-Disposition: form-data; name="note"; filename="big"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + payload
            + b"\r\n--b--"
        )

        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": "multipart/form-data; boundary=b",
            "CONTENT_LENGTH": str(len(data)),
            "wsgi.input": io.BytesIO(data),
        }
        request = Request(environ)

        # Files go through the parser stream factory, which spools to disk
        # independently of the text-field memory limit.
        from werkzeug.formparser import FormDataParser
        from werkzeug.formparser import _make_stream_factory

        parser = FormDataParser(stream_factory=_make_stream_factory(128))
        request._parse_form_data = lambda stream, _parser=parser: _parser.parse(
            stream,
            mimetype=request.mimetype,
            content_length=request.content_length,
            options=request.mimetype_params,
        )[1:]

        with request:
            file_part = next(part for part in request.parts if part.file)

            assert file_part.file is request.files["note"]
            assert file_part.file.read() == payload
            assert file_part.file.stream._rolled
            temp_name = file_part.file.stream.name

        assert not os.path.exists(temp_name)

    def test_limits_apply_to_parts(self) -> None:
        data, content_type = _interleaved_multipart()

        with Request.from_values(
            data=data, content_type=content_type, method="POST"
        ) as request:
            request.max_form_parts = 2

            with pytest.raises(RequestEntityTooLarge):
                request.parts

        oversized_field = (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="note"\r\n\r\n'
            + b"y" * 100
            + b"\r\n--b--"
        )

        with Request.from_values(
            data=oversized_field,
            content_type="multipart/form-data; boundary=b",
            method="POST",
        ) as request:
            request.max_form_memory_size = 10

            with pytest.raises(RequestEntityTooLarge):
                request.parts

    def test_urlencoded_and_unknown_types_have_no_parts(self) -> None:
        request = Request.from_values(
            data=b"a=1",
            content_type="application/x-www-form-urlencoded",
            method="POST",
        )
        assert request.parts == ()
        assert request.form["a"] == "1"

        request = Request.from_values(
            data=b"raw", content_type="text/plain", method="POST"
        )
        assert request.parts == ()

    def test_parse_form_data_returns_parts(self) -> None:
        data, content_type = _interleaved_multipart()
        environ = create_environ(
            method="POST", content_type=content_type, data=data
        )

        try:
            _, form, files, parts = parse_form_data(environ)
            assert form.getlist("note") == [
                "first description",
                "second description",
            ]
            assert len(files.getlist("note")) == 2
            assert [type(part).__name__ for part in parts] == [
                "FormPart"
            ] * 4
        finally:
            for values in files.listvalues():
                for file in values:
                    file.close()


class TestMultiPartCleanup:
    def test_silent_parse_failure_closes_temp_files(self) -> None:
        from tempfile import SpooledTemporaryFile

        rolled_names: list[str] = []

        class TrackingSpooledFile(SpooledTemporaryFile):
            def write(self, data: bytes) -> int:
                result = super().write(data)

                if self._rolled and not rolled_names:
                    rolled_names.append(self.name)

                return result

        def stream_factory(
            total_content_length, content_type, filename, content_length=0
        ):
            return TrackingSpooledFile(max_size=16, mode="rb+")

        data = (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="f"; filename="big"\r\n\r\n'
            + b"z" * 100
            + b"\r\n--b\r\n"
            b'Content-Disposition: form-data; name="t"\r\n\r\n'
            b"truncated"
        )
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": "multipart/form-data; boundary=b",
            "CONTENT_LENGTH": str(len(data)),
            "wsgi.input": io.BytesIO(data),
        }
        parser = FormDataParser(stream_factory=stream_factory, silent=True)
        stream, form, files, parts = parser.parse_from_environ(environ)

        assert not form
        assert not files
        assert parts == ()
        assert len(rolled_names) == 1
        assert not os.path.exists(rolled_names[0])

    def test_size_limit_failure_closes_temp_files(self) -> None:
        from tempfile import SpooledTemporaryFile

        rolled_names: list[str] = []

        class TrackingSpooledFile(SpooledTemporaryFile):
            def write(self, data: bytes) -> int:
                result = super().write(data)

                if self._rolled and not rolled_names:
                    rolled_names.append(self.name)

                return result

        data = (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="f"; filename="big"\r\n\r\n'
            + b"z" * 100
            + b"\r\n--b\r\n"
            b'Content-Disposition: form-data; name="t"\r\n\r\n'
            + b"y" * 200
            + b"\r\n--b--"
        )
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": "multipart/form-data; boundary=b",
            "CONTENT_LENGTH": str(len(data)),
            "wsgi.input": io.BytesIO(data),
        }
        parser = formparser.MultiPartParser(
            stream_factory=lambda *a, **k: TrackingSpooledFile(
                max_size=16, mode="rb+"
            ),
            max_form_memory_size=120,
            buffer_size=32,
        )

        with pytest.raises(RequestEntityTooLarge):
            parser.parse(
                environ["wsgi.input"], b"b", int(environ["CONTENT_LENGTH"])
            )

        assert len(rolled_names) == 1
        assert not os.path.exists(rolled_names[0])

    def test_temp_files_closed_on_corrupt_request(self) -> None:
        from tempfile import SpooledTemporaryFile

        rolled_names: list[str] = []

        class TrackingSpooledFile(SpooledTemporaryFile):
            def write(self, data: bytes) -> int:
                result = super().write(data)

                if self._rolled and not rolled_names:
                    rolled_names.append(self.name)

                return result

        def stream_factory(
            total_content_length, content_type, filename, content_length=0
        ):
            return TrackingSpooledFile(max_size=16, mode="rb+")

        # First part is a file large enough to roll to disk. The body is then
        # truncated before the closing boundary, which is a parse failure.
        data = (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="f"; filename="big"\r\n\r\n'
            + b"z" * 100
            + b"\r\n--b\r\n"
            b'Content-Disposition: form-data; name="t"\r\n\r\n'
            b"truncated without closing boundary"
        )
        parser = formparser.MultiPartParser(
            stream_factory=stream_factory, buffer_size=32
        )

        with parser, pytest.raises(ValueError):
            parser.parse(io.BytesIO(data), b"b", len(data))

        assert len(rolled_names) == 1
        assert not os.path.exists(rolled_names[0])
