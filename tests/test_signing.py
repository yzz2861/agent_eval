from __future__ import annotations

from datetime import timedelta
from urllib.parse import parse_qsl
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import pytest

from flask import ExpiredSignedLink
from flask import InvalidSignedLink
from flask import signed_url_for
from flask import signed_url_required
from flask import verify_signed_url


def _rewrite_query(url, func):
    """Apply "func" to the list of query pairs of "url" and rebuild it."""
    parts = urlsplit(url)
    pairs = func(parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(pairs),
            parts.fragment,
        )
    )


@pytest.fixture
def signed_app(app):
    @app.route("/unsubscribe/<int:user_id>", methods=["GET", "POST"])
    @signed_url_required("unsubscribe")
    def unsubscribe(user_id):
        return f"unsubscribed {user_id}"

    @app.route("/confirm/<int:user_id>")
    @signed_url_required("confirm")
    def confirm(user_id):
        return f"confirmed {user_id}"

    return app


def test_valid_link(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for(
            "unsubscribe", purpose="unsubscribe", user_id=1, max_age=60
        )

    response = client.get(url)
    assert response.status_code == 200
    assert response.text == "unsubscribed 1"


def test_wrong_purpose(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="confirm", user_id=1, max_age=60)

    assert client.get(url).status_code == 403


def test_wrong_method(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for(
            "unsubscribe", purpose="unsubscribe", method="POST", user_id=1
        )

    assert client.get(url).status_code == 403
    assert client.post(url).status_code == 200


def test_moved_to_other_route(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    # Present the signed query string to a different route.
    other = url.replace("/unsubscribe/", "/confirm/")
    assert client.get(other).status_code == 403


def test_tampered_path(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    assert client.get(url.replace("/1?", "/2?")).status_code == 403


def test_expired_link(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for(
            "unsubscribe", purpose="unsubscribe", user_id=1, max_age=-1
        )

    assert client.get(url).status_code == 403

    with signed_app.test_request_context(url):
        with pytest.raises(ExpiredSignedLink):
            verify_signed_url(purpose="unsubscribe")


def test_timedelta_max_age(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for(
            "unsubscribe",
            purpose="unsubscribe",
            user_id=1,
            max_age=timedelta(minutes=5),
        )

    assert "_sig_exp=" in url
    assert client.get(url).status_code == 200


def test_link_without_expiry(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    assert "_sig_exp" not in url
    assert client.get(url).status_code == 200


def test_query_order_does_not_matter(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for(
            "unsubscribe",
            purpose="unsubscribe",
            user_id=1,
            tag=["a", "b"],
            q="x",
        )

    reordered = _rewrite_query(url, lambda pairs: list(reversed(pairs)))
    assert client.get(reordered).status_code == 200


def test_changed_repeated_value_fails(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for(
            "unsubscribe",
            purpose="unsubscribe",
            user_id=1,
            tag=["a", "b"],
        )

    def change_one(pairs):
        return [
            (key, "c" if (key, value) == ("tag", "a") else value)
            for key, value in pairs
        ]

    assert client.get(_rewrite_query(url, change_one)).status_code == 403


def test_removed_and_added_params_fail(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1, a="1")

    removed = _rewrite_query(url, lambda pairs: [p for p in pairs if p != ("a", "1")])
    assert client.get(removed).status_code == 403
    assert client.get(f"{url}&b=2").status_code == 403


def test_empty_and_unicode_values(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for(
            "unsubscribe",
            purpose="unsubscribe",
            user_id=1,
            empty="",
            name="中文 用户",
        )

    assert client.get(url).status_code == 200


def test_unicode_and_encoded_path(app, client):
    @app.route("/file/<path:name>")
    def send(name):
        verify_signed_url(purpose="download")
        return name

    with app.test_request_context():
        url = signed_url_for("send", purpose="download", name="a b/中.txt")

    assert "%" in url
    assert client.get(url).status_code == 200

    # Equivalent encodings of the same path still verify.
    parts = urlsplit(url)
    lower_hex = urlunsplit(
        (parts.scheme, parts.netloc, parts.path.lower(), parts.query, "")
    )
    assert client.get(lower_hex).status_code == 200


def test_signature_param_not_duplicated(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    parts = urlsplit(url)
    sig = dict(parse_qsl(parts.query))["_sig"]

    assert client.get(f"{url}&_sig={sig}").status_code == 403
    assert client.get(f"{url}&_sig=forged").status_code == 403
    assert client.get(f"{url}&_sig_exp=1&_sig_exp=2").status_code == 403

    # Removing the signature entirely is also rejected.
    unsigned = _rewrite_query(url, lambda pairs: [p for p in pairs if p[0] != "_sig"])
    assert client.get(unsigned).status_code == 403


def test_reserved_params_rejected(signed_app):
    with signed_app.test_request_context():
        with pytest.raises(ValueError, match="reserved"):
            signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1, _sig="x")

        with pytest.raises(ValueError, match="reserved"):
            signed_url_for(
                "unsubscribe", purpose="unsubscribe", user_id=1, _sig_exp="1"
            )


def test_invalid_signature_value(signed_app, client):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    forged = _rewrite_query(
        url,
        lambda pairs: [
            (key, "forged" if key == "_sig" else value) for key, value in pairs
        ],
    )
    assert client.get(forged).status_code == 403

    with signed_app.test_request_context(forged):
        with pytest.raises(InvalidSignedLink):
            verify_signed_url(purpose="unsubscribe")


def test_key_rotation(signed_app, client):
    with signed_app.test_request_context():
        old_url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    # Rotate: the old key becomes a fallback, new links use the new key.
    signed_app.config["SECRET_KEY_FALLBACKS"] = ["test key"]
    signed_app.secret_key = "new key"

    with signed_app.test_request_context():
        new_url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    # Old links still verify, and the signature changed.
    assert old_url != new_url
    assert client.get(old_url).status_code == 200
    assert client.get(new_url).status_code == 200

    # Once the old key is retired, old links stop verifying.
    signed_app.config["SECRET_KEY_FALLBACKS"] = None
    assert client.get(old_url).status_code == 403
    assert client.get(new_url).status_code == 200


def test_host_not_signed_by_default(signed_app, client):
    with signed_app.test_request_context(base_url="http://example.com"):
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    assert client.get(url, base_url="http://example.com").status_code == 200
    # The Host header is attacker-controlled, so it is ignored unless
    # SIGNED_URL_INCLUDE_HOST is enabled.
    assert client.get(url, base_url="http://evil.example").status_code == 200


def test_host_signed_when_configured(signed_app, client):
    signed_app.config["SIGNED_URL_INCLUDE_HOST"] = True

    with signed_app.test_request_context(base_url="http://example.com"):
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    assert client.get(url, base_url="http://example.com").status_code == 200
    assert client.get(url, base_url="http://evil.example").status_code == 403


def test_host_signed_outside_request(app):
    app.config["SIGNED_URL_INCLUDE_HOST"] = True
    app.config["SERVER_NAME"] = "example.com"

    @app.route("/a")
    def a():
        return ""

    with app.app_context():
        url = signed_url_for("a", purpose="p")

    assert url.startswith("http://example.com/a?")
    assert app.test_client().get(url).status_code == 200


def test_secret_key_required(app):
    app.secret_key = None

    @app.route("/a")
    def a():
        return ""

    with app.test_request_context():
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            signed_url_for("a", purpose="p")


def test_verify_returns_true(signed_app):
    with signed_app.test_request_context():
        url = signed_url_for("unsubscribe", purpose="unsubscribe", user_id=1)

    with signed_app.test_request_context(url):
        assert verify_signed_url(purpose="unsubscribe") is True


def test_blueprint_relative_endpoint(app, client):
    from flask import Blueprint

    bp = Blueprint("bp", __name__, url_prefix="/bp")

    @bp.route("/action")
    @signed_url_required("action")
    def action():
        return "done"

    app.register_blueprint(bp)

    with app.test_request_context("/bp/action"):
        url = signed_url_for(".action", purpose="action")

    assert client.get(url).status_code == 200
