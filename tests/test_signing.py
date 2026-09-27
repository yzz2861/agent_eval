import pytest

from flask import abort
from flask import Blueprint
from flask.signing import generate_signed_url
from flask.signing import signed_url_required
from flask.signing import verify_signed_url


@pytest.fixture
def signed_app(app):
    @app.route("/download/<name>", methods=["GET", "POST"])
    def download(name):
        if not verify_signed_url("download"):
            abort(403)
        return "ok"

    @app.route("/protected")
    @signed_url_required("protected")
    def protected():
        return "protected ok"

    @app.route("/files/<path:name>")
    def files(name):
        if not verify_signed_url("files"):
            abort(403)
        return "file ok"

    return app


def make_url(app, **kwargs):
    with app.test_request_context():
        return generate_signed_url(**kwargs)


def test_roundtrip(signed_app):
    url = make_url(
        signed_app, endpoint="download", purpose="download", name="report.pdf"
    )
    assert signed_app.test_client().get(url).status_code == 200


def test_unsigned_request_rejected(signed_app):
    assert signed_app.test_client().get("/download/report.pdf").status_code == 403


def test_method_enforced(signed_app):
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        method="POST",
        name="report.pdf",
    )
    client = signed_app.test_client()
    assert client.get(url).status_code == 403
    assert client.post(url).status_code == 200


def test_purpose_enforced(signed_app):
    url = make_url(signed_app, endpoint="download", purpose="other", name="report.pdf")
    assert signed_app.test_client().get(url).status_code == 403


def test_expired(signed_app):
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        max_age=-1,
        name="report.pdf",
    )
    assert signed_app.test_client().get(url).status_code == 403


def test_not_expired(signed_app):
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        max_age=3600,
        name="report.pdf",
    )
    assert signed_app.test_client().get(url).status_code == 200


def test_tampered_query_value(signed_app):
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        name="report.pdf",
        tag="a",
    )
    client = signed_app.test_client()
    assert client.get(url).status_code == 200
    assert client.get(url.replace("tag=a", "tag=b")).status_code == 403
    assert client.get(url.replace("tag=a", "tag=a&extra=1")).status_code == 403
    assert client.get(url.replace("tag=a&", "")).status_code == 403


def test_query_order_and_repeated_values(signed_app):
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        name="report.pdf",
        tag=["a", "b"],
        q="x",
    )
    client = signed_app.test_client()
    assert client.get(url).status_code == 200

    # Reordering the same parameters still verifies.
    sig = url.split("_sig=")[1]
    reordered = f"/download/report.pdf?tag=b&q=x&tag=a&_sig={sig}"
    assert client.get(reordered).status_code == 200

    # Changing one value of a repeated parameter fails.
    changed = f"/download/report.pdf?tag=a&q=x&tag=c&_sig={sig}"
    assert client.get(changed).status_code == 403


def test_empty_value_and_bare_key(signed_app):
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        name="report.pdf",
        empty="",
    )
    client = signed_app.test_client()
    assert "empty=" in url
    assert client.get(url).status_code == 200
    # A bare key normalizes to the same empty value.
    assert client.get(url.replace("empty=", "empty")).status_code == 200
    # A non-empty value does not.
    assert client.get(url.replace("empty=", "empty=1")).status_code == 403


def test_unicode_path_and_query(signed_app):
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        name="r\u00e9sum\u00e9.pdf",
        q="\u65e5\u672c\u8a9e",
    )
    client = signed_app.test_client()
    assert client.get(url).status_code == 200
    # Percent-encoding hex case does not matter.
    lowered = url.replace("%C3%A9", "%c3%a9")
    assert lowered != url
    assert client.get(lowered).status_code == 200


def test_encoded_path(signed_app):
    url = make_url(
        signed_app,
        endpoint="files",
        purpose="files",
        name="a b/c d",
    )
    assert "%20" in url
    assert signed_app.test_client().get(url).status_code == 200


def test_signature_param_not_injectable(signed_app):
    # A user-supplied _sig value is stripped when generating.
    url = make_url(
        signed_app,
        endpoint="download",
        purpose="download",
        name="report.pdf",
        _sig="evil",
    )
    assert url.count("_sig=") == 1
    client = signed_app.test_client()
    assert client.get(url).status_code == 200
    # A duplicated _sig parameter is rejected.
    assert client.get(f"{url}&_sig=evil").status_code == 403


def test_key_rotation(signed_app):
    signed_app.config["SECRET_KEY"] = "old-key"
    old_url = make_url(
        signed_app, endpoint="download", purpose="download", name="a.txt"
    )

    # Rotate: new key signs, old key only verifies.
    signed_app.config["SECRET_KEY"] = "new-key"
    signed_app.config["SIGNED_URL_SECRET_KEY_FALLBACKS"] = ["old-key"]
    client = signed_app.test_client()
    assert client.get(old_url).status_code == 200

    new_url = make_url(
        signed_app, endpoint="download", purpose="download", name="a.txt"
    )
    assert new_url != old_url
    assert client.get(new_url).status_code == 200

    # Once the fallback is removed, old links stop working.
    signed_app.config["SIGNED_URL_SECRET_KEY_FALLBACKS"] = None
    assert client.get(old_url).status_code == 403
    assert client.get(new_url).status_code == 200


def test_host_signed_with_server_name(signed_app):
    signed_app.config["SERVER_NAME"] = "example.com"
    signed_app.config["SIGNED_URL_INCLUDE_HOST"] = True
    url = make_url(signed_app, endpoint="download", purpose="download", name="a.txt")
    assert url.startswith("http://example.com/")
    client = signed_app.test_client()
    assert client.get(url).status_code == 200
    # An arbitrary Host header does not affect verification because the
    # configured SERVER_NAME is what gets signed.
    assert client.get(url, headers={"Host": "evil.example.com"}).status_code == 200


def test_host_signed_with_trusted_hosts(signed_app):
    signed_app.config["SIGNED_URL_INCLUDE_HOST"] = True
    signed_app.config["TRUSTED_HOSTS"] = ["a.example.com", "b.example.com"]

    with signed_app.test_request_context(base_url="http://a.example.com"):
        url = generate_signed_url("download", purpose="download", name="a.txt")

    client = signed_app.test_client()
    assert client.get(url).status_code == 200
    # The same link requested at a different (still trusted) host fails.
    other = url.replace("a.example.com", "b.example.com")
    assert client.get(other).status_code == 403


def test_host_not_signed_by_default(signed_app):
    url = make_url(signed_app, endpoint="download", purpose="download", name="a.txt")
    client = signed_app.test_client()
    assert client.get(url).status_code == 200
    assert client.get(url, headers={"Host": "other.example.com"}).status_code == 200


def test_signature_not_valid_on_other_route(signed_app):
    url = make_url(signed_app, endpoint="download", purpose="download", name="a.txt")
    sig = url.split("_sig=")[1]
    # The same signature token transplanted to another route fails.
    assert signed_app.test_client().get(f"/files/a.txt?_sig={sig}").status_code == 403


def test_decorator(signed_app):
    url = make_url(signed_app, endpoint="protected", purpose="protected")
    client = signed_app.test_client()
    assert client.get(url).status_code == 200
    assert client.get("/protected").status_code == 403


def test_relative_endpoint(app):
    bp = Blueprint("bp", __name__)

    @bp.route("/thing")
    def thing():
        if not verify_signed_url("thing"):
            abort(403)
        return "ok"

    app.register_blueprint(bp, url_prefix="/bp")

    with app.test_request_context("/bp/thing"):
        url = generate_signed_url(".thing", purpose="thing")

    assert app.test_client().get(url).status_code == 200


def test_secret_key_required(signed_app):
    signed_app.config["SECRET_KEY"] = None
    with (
        signed_app.test_request_context(),
        pytest.raises(RuntimeError, match="SECRET_KEY"),
    ):
        generate_signed_url("download", purpose="download", name="a.txt")
