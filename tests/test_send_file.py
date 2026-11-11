from __future__ import annotations

import datetime as dt
import io
import pathlib
import typing as t

import pytest
from werkzeug.exceptions import NotFound
from werkzeug.http import http_date
from werkzeug.http import parse_options_header
from werkzeug.test import create_environ
from werkzeug.utils import DownloadNamePolicy
from werkzeug.utils import send_file
from werkzeug.utils import send_from_directory
from werkzeug.utils import UnsafeDownloadName
from werkzeug.utils import UnsafeDownloadNameReason
from werkzeug.wrappers import Response

res_path = pathlib.Path(__file__).parent / "res"
html_path = res_path / "index.html"
txt_path = res_path / "test.txt"
environ = create_environ()


@pytest.mark.parametrize("path", [html_path, str(html_path)])
def test_path(path):
    with send_file(path, environ) as rv:
        assert rv.mimetype == "text/html"
        assert rv.direct_passthrough
        rv.direct_passthrough = False
        assert rv.data == html_path.read_bytes()


def test_x_sendfile() -> None:
    with send_file(html_path, environ, use_x_sendfile=True) as response:
        assert response.headers["X-Sendfile"] == str(html_path)
        assert not response.response


def test_last_modified():
    last_modified = dt.datetime(1999, 1, 1, tzinfo=dt.UTC)

    with send_file(txt_path, environ, last_modified=last_modified) as rv:
        assert rv.last_modified == last_modified


def test_file() -> None:
    with txt_path.open("rb") as f, send_file(f, environ) as response:
        assert "filename=test.txt" in response.headers["Content-Disposition"]
        assert response.mimetype == "text/plain"
        assert response.content_length == 6
        assert response.last_modified is not None


def test_object() -> None:
    with send_file(io.BytesIO(b"test"), environ) as response:
        assert "Content-Disposition" not in response.headers
        assert response.mimetype == "application/octet-stream"
        assert response.content_length == 4
        assert response.last_modified is None


def test_object_mimetype_from_name() -> None:
    with send_file(io.BytesIO(b"test"), environ, download_name="test.html") as response:
        assert response.mimetype == "text/html"


@pytest.mark.parametrize(
    "file_factory", [lambda: txt_path.open(), lambda: io.StringIO("test")]
)
def test_text_mode_fails(file_factory: t.Callable[[], t.IO[t.Any]]):
    with file_factory() as f, pytest.raises(ValueError):
        send_file(f, environ, mimetype="text/plain")


@pytest.mark.parametrize(
    ("as_attachment", "value"), [(False, "inline"), (True, "attachment")]
)
def test_disposition_name(as_attachment, value):
    with send_file(txt_path, environ, as_attachment=as_attachment) as rv:
        assert rv.headers["Content-Disposition"] == f"{value}; filename=test.txt"


def test_object_attachment_requires_name():
    with pytest.raises(TypeError, match="attachment"):
        send_file(
            io.BytesIO(b"test"), environ, mimetype="text/plain", as_attachment=True
        )

    with send_file(
        io.BytesIO(b"test"), environ, as_attachment=True, download_name="test.txt"
    ) as rv:
        assert rv.headers["Content-Disposition"] == "attachment; filename=test.txt"


@pytest.mark.parametrize(
    ("name", "ascii", "utf8"),
    (
        ("index.html", "index.html", None),
        (
            "Ñandú／pingüino.txt",
            '"Nandu/pinguino.txt"',
            "%C3%91and%C3%BA%EF%BC%8Fping%C3%BCino.txt",
        ),
        # latin-1 isn't ascii, should be quoted
        ("Vögel.txt", "Vogel.txt", "V%C3%B6gel.txt"),
        # ":/" are not safe in filename* value
        ("те:/ст", '":/"', "%D1%82%D0%B5%3A%2F%D1%81%D1%82"),
        # general test of extended parameter (non-quoted)
        ("(тест.txt", '"(.txt"', "%28%D1%82%D0%B5%D1%81%D1%82.txt"),
        ("(test.txt", '"(test.txt"', None),
    ),
)
def test_non_ascii_name(name, ascii, utf8):
    with send_file(html_path, environ, as_attachment=True, download_name=name) as rv:
        content_disposition = rv.headers["Content-Disposition"]

    assert f"filename={ascii}" in content_disposition

    if utf8:
        assert f"filename*=UTF-8''{utf8}" in content_disposition
    else:
        assert "filename*=UTF-8''" not in content_disposition


def test_no_cache_conditional_default():
    with send_file(
        txt_path,
        create_environ(
            headers={"If-Modified-Since": http_date(dt.datetime(2020, 7, 12))}
        ),
        last_modified=dt.datetime(2020, 7, 11),
    ) as rv:
        assert "no-cache" in rv.headers["Cache-Control"]
        assert not rv.cache_control.public
        assert not rv.cache_control.max_age
        assert not rv.expires
        assert rv.status_code == 304


@pytest.mark.parametrize(("value", "public"), [(0, False), (60, True)])
def test_max_age(value, public):
    with send_file(txt_path, environ, max_age=value) as rv:
        assert ("no-cache" in rv.headers["Cache-Control"]) != public
        assert rv.cache_control.public == public
        assert rv.cache_control.max_age == value
        assert rv.expires
        assert rv.status_code == 200


def test_etag() -> None:
    with send_file(txt_path, environ) as rv:
        assert rv.headers["ETag"].count("-") == 1

    with send_file(txt_path, environ, etag=False) as rv:
        assert "ETag" not in rv.headers

    with send_file(txt_path, environ, etag="unique") as rv:
        assert rv.headers["ETag"] == '"unique"'


@pytest.mark.parametrize("as_attachment", (True, False))
def test_content_encoding(as_attachment):
    with send_file(
        txt_path, environ, download_name="logo.svgz", as_attachment=as_attachment
    ) as rv:
        assert rv.mimetype == "image/svg+xml"
        assert rv.content_encoding == ("gzip" if not as_attachment else None)


@pytest.mark.parametrize(
    ("directory", "path"),
    [(str(res_path), "test.txt"), (res_path, pathlib.Path("test.txt"))],
)
def test_from_directory(directory, path):
    with send_from_directory(directory, path, environ) as rv:
        rv.direct_passthrough = False
        assert rv.data.strip() == b"FOUND"


@pytest.mark.parametrize("path", ["../res/test.txt", "nothing.txt", "null\x00.txt"])
def test_from_directory_not_found(path):
    with pytest.raises(NotFound):
        send_from_directory(res_path, path, environ)


def test_root_path(tmp_path):
    # This is a private API, it should only be used by Flask.
    d = tmp_path / "d"
    d.mkdir()
    (d / "test.txt").write_bytes(b"test")

    with send_file("d/test.txt", environ, _root_path=tmp_path) as rv:
        rv.direct_passthrough = False
        assert rv.data == b"test"

    with send_from_directory("d", "test.txt", environ, _root_path=tmp_path) as rv:
        rv.direct_passthrough = False
        assert rv.data == b"test"


def test_max_age_callable():
    # This is a private API, it should only be used by Flask.
    with send_file(txt_path, environ, max_age=lambda p: 10) as rv:
        assert rv.cache_control.max_age == 10


class ExplodingResponse(Response):
    def __init__(self, *args, **kwargs):
        raise AssertionError("response object must not be created")


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("report\x00.txt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("report\r.txt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("report\n.txt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("report\r\n.txt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("report\ttxt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("report\x1f.txt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("report\x7f.txt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("report\x9f.txt", UnsafeDownloadNameReason.CONTROL_CHARACTER),
        ("..\\..\\季度报表\u202eexe.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("report\u202a.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("report\u202e.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("report\u2066.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("report\u2069.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("report\u200e.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("report\u200f.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("report\u061c.txt", UnsafeDownloadNameReason.BIDI_CHARACTER),
        ("../report.txt", UnsafeDownloadNameReason.PATH_SEPARATOR),
        ("..\\report.txt", UnsafeDownloadNameReason.PATH_SEPARATOR),
        ("a/b.txt", UnsafeDownloadNameReason.PATH_SEPARATOR),
        ("a\\b.txt", UnsafeDownloadNameReason.PATH_SEPARATOR),
        (".", UnsafeDownloadNameReason.PATH_SEGMENT),
        ("..", UnsafeDownloadNameReason.PATH_SEGMENT),
        (" report.txt", UnsafeDownloadNameReason.SURROUNDING_WHITESPACE),
        ("report.txt ", UnsafeDownloadNameReason.SURROUNDING_WHITESPACE),
        ("report.", UnsafeDownloadNameReason.TRAILING_DOT),
        ("CON", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("con.txt", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("PRN.", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("aux ", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("NUL", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("COM1", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("com9.dat", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("LPT7", UnsafeDownloadNameReason.WINDOWS_DEVICE_NAME),
        ("x" * 256, UnsafeDownloadNameReason.TOO_LONG),
    ],
)
def test_send_file_strict_policy_rejects(name, reason):
    policy = DownloadNamePolicy()

    with pytest.raises(UnsafeDownloadName) as exc_info:
        send_file(
            io.BytesIO(b"data"),
            environ,
            as_attachment=True,
            download_name=name,
            download_name_policy=policy,
        )

    error = exc_info.value
    assert isinstance(error, ValueError)
    assert error.reason is reason
    assert error.download_name == name


@pytest.mark.parametrize("name", [".", "..", "CON", "report\r\n.txt"])
def test_send_file_strict_policy_before_response(name):
    # The response class would raise if the response was constructed.
    with pytest.raises(UnsafeDownloadName):
        send_file(
            io.BytesIO(b"data"),
            environ,
            as_attachment=True,
            download_name=name,
            download_name_policy=DownloadNamePolicy(),
            response_class=ExplodingResponse,
        )


def test_send_file_strict_policy_validates_default_name():
    # A name derived from the path is validated too.
    with pytest.raises(UnsafeDownloadName):
        send_file(
            txt_path,
            environ,
            download_name="../test.txt",
            download_name_policy=DownloadNamePolicy(),
        )


def test_send_file_strict_policy_custom_length():
    policy = DownloadNamePolicy(max_length=5)

    with send_file(
        io.BytesIO(b"data"),
        environ,
        as_attachment=True,
        download_name="a.txt",
        download_name_policy=policy,
    ) as rv:
        assert "filename=a.txt" in rv.headers["Content-Disposition"]

    with pytest.raises(UnsafeDownloadName) as exc_info:
        send_file(
            io.BytesIO(b"data"),
            environ,
            as_attachment=True,
            download_name="longer.txt",
            download_name_policy=policy,
        )

    assert exc_info.value.reason is UnsafeDownloadNameReason.TOO_LONG


def test_send_file_strict_policy_non_ascii_disallowed():
    policy = DownloadNamePolicy(allow_non_ascii=False)

    with pytest.raises(UnsafeDownloadName) as exc_info:
        send_file(
            io.BytesIO(b"data"),
            environ,
            as_attachment=True,
            download_name="季度报表.txt",
            download_name_policy=policy,
        )

    assert exc_info.value.reason is UnsafeDownloadNameReason.NON_ASCII


def test_send_file_strict_policy_device_names_allowed():
    policy = DownloadNamePolicy(reject_windows_device_names=False)

    with send_file(
        io.BytesIO(b"data"),
        environ,
        as_attachment=True,
        download_name="CON",
        download_name_policy=policy,
    ) as rv:
        assert rv.headers["Content-Disposition"] == "attachment; filename=CON"


def test_send_file_strict_policy_unicode_roundtrip():
    name = "季度报表.txt"

    with send_file(
        io.BytesIO(b"data"),
        environ,
        as_attachment=True,
        download_name=name,
        download_name_policy=DownloadNamePolicy(),
    ) as rv:
        content_disposition = rv.headers["Content-Disposition"]
        value, options = parse_options_header(content_disposition)

    assert value == "attachment"
    assert "filename*=UTF-8''" in content_disposition
    # RFC 5987 value decodes back to the original name.
    assert options["filename"] == name
    # The ASCII fallback is present and non-empty.
    assert "filename=.txt" in content_disposition


def test_send_file_strict_policy_ascii_fallback_not_empty():
    with pytest.raises(UnsafeDownloadName) as exc_info:
        send_file(
            io.BytesIO(b"data"),
            environ,
            as_attachment=True,
            download_name="中文",
            download_name_policy=DownloadNamePolicy(),
        )

    assert exc_info.value.reason is UnsafeDownloadNameReason.ASCII_FALLBACK_EMPTY


def test_send_file_strict_policy_encoded_header_is_safe():
    # Even though quote() percent-encodes, assert no raw CR/LF or quote can
    # appear in the generated header for a policy-accepted name.
    with send_file(
        io.BytesIO(b"data"),
        environ,
        as_attachment=True,
        download_name="季度 报表.txt",
        download_name_policy=DownloadNamePolicy(),
    ) as rv:
        content_disposition = rv.headers["Content-Disposition"]

    assert "\r" not in content_disposition
    assert "\n" not in content_disposition
    assert content_disposition.count('"') == 2


def test_send_file_no_policy_keeps_existing_behavior():
    # Without a policy, names the strict policy would reject are still sent.
    with send_file(
        io.BytesIO(b"data"),
        environ,
        as_attachment=True,
        download_name="../季度报表.txt",
    ) as rv:
        content_disposition = rv.headers["Content-Disposition"]

    assert content_disposition.startswith("attachment;")
    assert "filename*=UTF-8''" in content_disposition
