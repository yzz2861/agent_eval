"""
Unit tests for auth classes.

Integration tests also exist in tests/client/test_auth.py
"""

from urllib.request import parse_keqv_list

import pytest

import httpx


def test_basic_auth():
    auth = httpx.BasicAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should include a basic auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert request.headers["Authorization"].startswith("Basic")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_qop_auth_int(monkeypatch):
    # The 'auth-int' quality of protection includes a hash of the
    # request entity body in the digest, following RFC 7616 section 3.4.3.

    def mock_get_client_nonce(nonce_count: int, nonce: bytes) -> bytes:
        return "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".encode()

    auth = httpx.DigestAuth(username="Mufasa", password="Circle of Life")
    monkeypatch.setattr(auth, "_get_client_nonce", mock_get_client_nonce)

    request = httpx.Request(
        "POST", "https://www.example.com/dir/index.html", content=b"Hello, world!"
    )

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": (
            'Digest realm="http-auth@example.org", '
            'qop="auth-int", '
            "algorithm=SHA-256, "
            'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
            'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert 'username="Mufasa"' in request.headers["Authorization"]
    assert 'realm="http-auth@example.org"' in request.headers["Authorization"]
    assert 'uri="/dir/index.html"' in request.headers["Authorization"]
    assert "algorithm=SHA-256" in request.headers["Authorization"]
    assert (
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"'
        in request.headers["Authorization"]
    )
    assert "nc=00000001" in request.headers["Authorization"]
    assert (
        'cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"'
        in request.headers["Authorization"]
    )
    assert "qop=auth-int" in request.headers["Authorization"]
    assert (
        'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        in request.headers["Authorization"]
    )
    # Independently computed from the RFC 7616 section 3.4.3 formula,
    # using SHA-256 of the request entity body b"Hello, world!".
    assert (
        'response="c061051d755c6bf3b7271a6c90b58bed403a7315a7ba44ec43bff073bf7dc394"'
        in request.headers["Authorization"]
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_qop_auth_int_empty_body(monkeypatch):
    # Requests without a body use the hash of the empty byte string
    # as the entity hash.

    def mock_get_client_nonce(nonce_count: int, nonce: bytes) -> bytes:
        return "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".encode()

    auth = httpx.DigestAuth(username="Mufasa", password="Circle of Life")
    monkeypatch.setattr(auth, "_get_client_nonce", mock_get_client_nonce)

    request = httpx.Request("GET", "https://www.example.com/dir/index.html")

    flow = auth.sync_auth_flow(request)
    request = next(flow)

    headers = {
        "WWW-Authenticate": (
            'Digest realm="http-auth@example.org", '
            'qop="auth-int", '
            "algorithm=SHA-256, "
            'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert "qop=auth-int" in request.headers["Authorization"]
    # Independently computed using SHA-256 of the empty entity body b"".
    assert (
        'response="8bdf6f15638e260831e905028de5450562816d093c9bfc5c13d3a46adcdde940"'
        in request.headers["Authorization"]
    )

    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_prefers_auth_when_server_offers_auth_and_auth_int():
    # If the server offers both 'auth' and 'auth-int', then 'auth' is used.
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    flow = auth.sync_auth_flow(request)
    request = next(flow)

    headers = {
        "WWW-Authenticate": (
            'Digest realm="...", qop="auth,auth-int", nonce="...", opaque="..."'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert "qop=auth," in request.headers["Authorization"]

    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


@pytest.mark.parametrize("qop", ["auth-int", "auth"])
def test_digest_auth_non_replayable_body_raises(qop: str):
    # A request body that is a non-replayable stream cannot be resent
    # as part of the digest authentication flow. A dedicated error is
    # raised, rather than silently resending an empty body.
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request(
        "POST", "https://www.example.com", content=iter([b"Hello, world!"])
    )

    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # The initial anonymous request consumes the request body stream.
    assert b"".join(request.stream) == b"Hello, world!"

    headers = {
        "WWW-Authenticate": f'Digest realm="...", qop="{qop}", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    with pytest.raises(httpx.UnrewindableBodyError):
        flow.send(response)


def test_digest_auth_int_non_replayable_body_with_cached_challenge():
    # If a challenge is already cached, then the very first request is
    # authenticated. With 'auth-int' the entity hash is required up front,
    # so a non-replayable body raises immediately, before anything is sent.
    auth = httpx.DigestAuth(username="user", password="pass")

    # Establish a cached 'auth-int' challenge.
    initial = httpx.Request("GET", "https://www.example.com")
    flow = auth.sync_auth_flow(initial)
    next(flow)
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth-int", nonce="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=initial
    )
    flow.send(response)

    # A subsequent request with a non-replayable body cannot be authenticated.
    request = httpx.Request(
        "POST", "https://www.example.com", content=iter([b"Hello, world!"])
    )
    flow = auth.sync_auth_flow(request)
    with pytest.raises(httpx.UnrewindableBodyError):
        next(flow)


def test_digest_auth_with_200():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 200 response is returned, then no other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401_nonce_counting():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    first_request = flow.send(response)
    assert first_request.headers["Authorization"].startswith("Digest")

    # Each subsequent request contains the digest header by default...
    request = httpx.Request("GET", "https://www.example.com")
    flow = auth.sync_auth_flow(request)
    second_request = next(flow)
    assert second_request.headers["Authorization"].startswith("Digest")

    # ... and the client nonce count (nc) is increased
    first_nc = parse_keqv_list(first_request.headers["Authorization"].split(", "))["nc"]
    second_nc = parse_keqv_list(second_request.headers["Authorization"].split(", "))[
        "nc"
    ]
    assert int(first_nc, 16) + 1 == int(second_nc, 16)

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def set_cookies(request: httpx.Request) -> httpx.Response:
    headers = {
        "Set-Cookie": "session=.session_value...",
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."',
    }
    if request.url.path == "/auth":
        return httpx.Response(
            content=b"Auth required", status_code=401, headers=headers
        )
    else:
        raise NotImplementedError()  # pragma: no cover


def test_digest_auth_setting_cookie_in_request():
    url = "https://www.example.com/auth"
    client = httpx.Client(transport=httpx.MockTransport(set_cookies))
    request = client.build_request("GET", url)

    auth = httpx.DigestAuth(username="user", password="pass")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    response = client.get(url)
    assert len(response.cookies) > 0
    assert response.cookies["session"] == ".session_value..."

    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert request.headers["Cookie"] == "session=.session_value..."

    # No other requests are made.
    response = httpx.Response(
        content=b"Hello, world!", status_code=200, request=request
    )
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_rfc_2069():
    # Example from https://datatracker.ietf.org/doc/html/rfc2069#section-2.4
    # with corrected response from https://www.rfc-editor.org/errata/eid749

    auth = httpx.DigestAuth(username="Mufasa", password="CircleOfLife")
    request = httpx.Request("GET", "https://www.example.com/dir/index.html")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": (
            'Digest realm="testrealm@host.com", '
            'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
            'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert 'username="Mufasa"' in request.headers["Authorization"]
    assert 'realm="testrealm@host.com"' in request.headers["Authorization"]
    assert (
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"' in request.headers["Authorization"]
    )
    assert 'uri="/dir/index.html"' in request.headers["Authorization"]
    assert (
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"' in request.headers["Authorization"]
    )
    assert (
        'response="1949323746fe6a43ef61f9606e7febea"'
        in request.headers["Authorization"]
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_rfc_7616_md5(monkeypatch):
    # Example from https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.1

    def mock_get_client_nonce(nonce_count: int, nonce: bytes) -> bytes:
        return "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".encode()

    auth = httpx.DigestAuth(username="Mufasa", password="Circle of Life")
    monkeypatch.setattr(auth, "_get_client_nonce", mock_get_client_nonce)

    request = httpx.Request("GET", "https://www.example.com/dir/index.html")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": (
            'Digest realm="http-auth@example.org", '
            'qop="auth, auth-int", '
            "algorithm=MD5, "
            'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
            'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert 'username="Mufasa"' in request.headers["Authorization"]
    assert 'realm="http-auth@example.org"' in request.headers["Authorization"]
    assert 'uri="/dir/index.html"' in request.headers["Authorization"]
    assert "algorithm=MD5" in request.headers["Authorization"]
    assert (
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"'
        in request.headers["Authorization"]
    )
    assert "nc=00000001" in request.headers["Authorization"]
    assert (
        'cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"'
        in request.headers["Authorization"]
    )
    assert "qop=auth" in request.headers["Authorization"]
    assert (
        'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        in request.headers["Authorization"]
    )
    assert (
        'response="8ca523f5e9506fed4657c9700eebdbec"'
        in request.headers["Authorization"]
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_rfc_7616_sha_256(monkeypatch):
    # Example from https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.1

    def mock_get_client_nonce(nonce_count: int, nonce: bytes) -> bytes:
        return "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".encode()

    auth = httpx.DigestAuth(username="Mufasa", password="Circle of Life")
    monkeypatch.setattr(auth, "_get_client_nonce", mock_get_client_nonce)

    request = httpx.Request("GET", "https://www.example.com/dir/index.html")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": (
            'Digest realm="http-auth@example.org", '
            'qop="auth, auth-int", '
            "algorithm=SHA-256, "
            'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
            'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert 'username="Mufasa"' in request.headers["Authorization"]
    assert 'realm="http-auth@example.org"' in request.headers["Authorization"]
    assert 'uri="/dir/index.html"' in request.headers["Authorization"]
    assert "algorithm=SHA-256" in request.headers["Authorization"]
    assert (
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"'
        in request.headers["Authorization"]
    )
    assert "nc=00000001" in request.headers["Authorization"]
    assert (
        'cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"'
        in request.headers["Authorization"]
    )
    assert "qop=auth" in request.headers["Authorization"]
    assert (
        'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        in request.headers["Authorization"]
    )
    assert (
        'response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"'
        in request.headers["Authorization"]
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)
