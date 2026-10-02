import pytest

from werkzeug.datastructures import Headers
from werkzeug.http_signatures import build_signature_base
from werkzeug.http_signatures import Component
from werkzeug.http_signatures import RequestContext
from werkzeug.http_signatures import ResponseContext
from werkzeug.http_signatures import SignatureBaseError

CONTENT_DIGEST = (
    "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm"
    "+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
)

RFC_HEADERS = [
    ("Host", "example.com"),
    ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
    ("Content-Type", "application/json"),
    ("Content-Digest", CONTENT_DIGEST),
    ("Content-Length", "18"),
]


def rfc_request():
    return RequestContext(
        method="POST", target="/foo?param=Value&Pet=dog", headers=RFC_HEADERS
    )


def test_rfc9421_section_2_5_signature_base():
    base = build_signature_base(
        [
            "@method",
            "@authority",
            "@path",
            "content-digest",
            "content-length",
            "content-type",
        ],
        request=rfc_request(),
        params={"created": 1618884473, "keyid": "test-key-rsa-pss"},
    )
    expected = (
        '"@method": POST\n'
        '"@authority": example.com\n'
        '"@path": /foo\n'
        f'"content-digest": {CONTENT_DIGEST}\n'
        '"content-length": 18\n'
        '"content-type": application/json\n'
        '"@signature-params": ("@method" "@authority" "@path" '
        '"content-digest" "content-length" "content-type")'
        ';created=1618884473;keyid="test-key-rsa-pss"'
    )
    assert base == expected.encode()


def test_rfc9421_appendix_b_1_1_minimal():
    base = build_signature_base(
        [],
        request=rfc_request(),
        params={
            "created": 1618884473,
            "keyid": "test-key-rsa-pss",
            "nonce": "b3k2pp5k7z-50gnwp.yemd",
        },
    )
    assert base == (
        b'"@signature-params": ();created=1618884473;'
        b'keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"'
    )


def test_rfc9421_appendix_b_1_2_selective():
    base = build_signature_base(
        ["@authority", "content-digest", ("@query-param", {"name": "Pet"})],
        request=rfc_request(),
        params={
            "created": 1618884473,
            "keyid": "test-key-rsa-pss",
            "tag": "header-example",
        },
    )
    expected = (
        '"@authority": example.com\n'
        f'"content-digest": {CONTENT_DIGEST}\n'
        '"@query-param";name="Pet": dog\n'
        '"@signature-params": ("@authority" "content-digest" '
        '"@query-param";name="Pet")'
        ';created=1618884473;keyid="test-key-rsa-pss";tag="header-example"'
    )
    assert base == expected.encode()


def test_rfc9421_appendix_b_1_3_full_coverage():
    base = build_signature_base(
        [
            "date",
            "@method",
            "@path",
            "@query",
            "@authority",
            "content-type",
            "content-digest",
            "content-length",
        ],
        request=rfc_request(),
        params={"created": 1618884473, "keyid": "test-key-rsa-pss"},
    )
    expected = (
        '"date": Tue, 20 Apr 2021 02:07:55 GMT\n'
        '"@method": POST\n'
        '"@path": /foo\n'
        '"@query": param=Value&Pet=dog\n'
        '"@authority": example.com\n'
        '"content-type": application/json\n'
        f'"content-digest": {CONTENT_DIGEST}\n'
        '"content-length": 18\n'
        '"@signature-params": ("date" "@method" "@path" "@query" "@authority" '
        '"content-type" "content-digest" "content-length")'
        ';created=1618884473;keyid="test-key-rsa-pss"'
    )
    assert base == expected.encode()


def test_response_signature_with_req_components():
    request = RequestContext(
        method="POST",
        target="/foo?param=Value&Pet=dog",
        headers=[("Host", "example.com"), ("Date", "Tue, 20 Apr 2021 02:07:55 GMT")],
    )
    response = ResponseContext(
        status=200,
        headers=[
            ("Date", "Tue, 20 Apr 2021 02:07:56 GMT"),
            ("Content-Type", "application/json"),
        ],
    )
    base = build_signature_base(
        [
            "@status",
            Component("@method", (("req", True),)),
            ("date", {"req": True}),
            "content-type",
        ],
        request=request,
        response=response,
        params={"created": 1618884473, "keyid": "test-key-ecc-p256"},
    )
    expected = (
        '"@status": 200\n'
        '"@method";req: POST\n'
        '"date";req: Tue, 20 Apr 2021 02:07:55 GMT\n'
        '"content-type": application/json\n'
        '"@signature-params": ("@status" "@method";req "date";req "content-type")'
        ';created=1618884473;keyid="test-key-ecc-p256"'
    )
    assert base == expected.encode()


def test_repeated_headers_combined():
    request = RequestContext(
        method="GET",
        target="/",
        headers=Headers([("X-Header", "a"), ("x-header", " b "), ("X-Other", "c")]),
    )
    base = build_signature_base(["x-header"], request=request)
    assert base.split(b"\n")[0] == b'"x-header": a, b'


def test_header_name_case_insensitive():
    base = build_signature_base(
        ["DATE"], request=RequestContext("GET", "/", [("dAtE", "tomorrow")])
    )
    assert base.split(b"\n")[0] == b'"date": tomorrow'


def test_headers_mapping_accepted():
    base = build_signature_base(
        ["date"], request=RequestContext("GET", "/", {"Date": "today"})
    )
    assert base.split(b"\n")[0] == b'"date": today'


@pytest.mark.parametrize("target", ["/foo", "/foo?"])
def test_empty_query(target):
    base = build_signature_base(["@query"], request=RequestContext("GET", target))
    assert base.split(b"\n")[0] == b'"@query": '


def test_empty_path_is_slash():
    base = build_signature_base(
        ["@path"], request=RequestContext("GET", "http://example.com")
    )
    assert base.split(b"\n")[0] == b'"@path": /'


def test_percent_encoding_preserved_byte_for_byte():
    request = RequestContext(
        "GET", "/foo%2Fbar?x=%41&y=a%20b", [("Host", "Example.com")]
    )
    base = build_signature_base(["@target-uri", "@path", "@query"], request=request)
    lines = base.split(b"\n")
    assert lines[0] == b'"@target-uri": http://Example.com/foo%2Fbar?x=%41&y=a%20b'
    assert lines[1] == b'"@path": /foo%2Fbar'
    assert lines[2] == b'"@query": x=%41&y=a%20b'


def test_encoding_only_difference_changes_bytes():
    components = ["@path", "@query"]
    lower = build_signature_base(
        components, request=RequestContext("GET", "/a%2fb?x=%41")
    )
    upper = build_signature_base(
        components, request=RequestContext("GET", "/a%2Fb?x=A")
    )
    assert lower != upper


def test_query_param_percent_decoded():
    request = RequestContext("GET", "/?x=%41%42&%6Eame=v%20w&empty=&flag")
    base = build_signature_base(
        [
            ("@query-param", {"name": "x"}),
            ("@query-param", {"name": "name"}),
            ("@query-param", {"name": "empty"}),
            ("@query-param", {"name": "flag"}),
        ],
        request=request,
    )
    lines = base.split(b"\n")
    assert lines[0] == b'"@query-param";name="x": AB'
    assert lines[1] == b'"@query-param";name="name": v w'
    assert lines[2] == b'"@query-param";name="empty": '
    assert lines[3] == b'"@query-param";name="flag": '


def test_query_param_first_occurrence_wins():
    base = build_signature_base(
        [("@query-param", {"name": "a"})],
        request=RequestContext("GET", "/?a=1&a=2"),
    )
    assert base.split(b"\n")[0] == b'"@query-param";name="a": 1'


def test_absolute_form_target_used_as_is():
    target = "https://Example.COM:8443/a%2Fb?x=1"
    request = RequestContext("GET", target, [("Host", "ignored.example")])
    base = build_signature_base(
        ["@target-uri", "@authority", "@path", "@query"], request=request
    )
    lines = base.split(b"\n")
    assert lines[0] == f'"@target-uri": {target}'.encode()
    assert lines[1] == b'"@authority": example.com:8443'
    assert lines[2] == b'"@path": /a%2Fb'
    assert lines[3] == b'"@query": x=1'


def test_authority_lowercased_from_host():
    base = build_signature_base(
        ["@authority"],
        request=RequestContext("GET", "/", [("Host", "EXAMPLE.com:8080")]),
    )
    assert base.split(b"\n")[0] == b'"@authority": example.com:8080'


def test_method_uppercased():
    base = build_signature_base(["@method"], request=RequestContext("post", "/"))
    assert base.split(b"\n")[0] == b'"@method": POST'


def test_forwarded_headers_never_trusted():
    request = RequestContext(
        "GET",
        "/real",
        [
            ("Host", "internal.example"),
            ("X-Forwarded-Host", "evil.example"),
            ("Forwarded", "host=evil.example"),
        ],
        scheme="https",
    )
    base = build_signature_base(["@target-uri", "@authority"], request=request)
    lines = base.split(b"\n")
    assert lines[0] == b'"@target-uri": https://internal.example/real'
    assert lines[1] == b'"@authority": internal.example'


def test_signature_params_order_preserved():
    base = build_signature_base(
        ["@method"],
        request=RequestContext("GET", "/"),
        params=[("nonce", "abc"), ("keyid", "k"), ("created", 1)],
    )
    assert base.split(b"\n")[-1] == (
        b'"@signature-params": ("@method");nonce="abc";keyid="k";created=1'
    )


def test_signature_param_string_escaped():
    base = build_signature_base(
        [], request=RequestContext("GET", "/"), params={"keyid": 'a"b'}
    )
    assert base.endswith(b';keyid="a\\"b"')


@pytest.mark.parametrize(
    ("components", "kwargs"),
    [
        (["x-missing"], {"request": RequestContext("GET", "/")}),
        (["@unknown"], {"request": RequestContext("GET", "/")}),
        (["@Method"], {"request": RequestContext("GET", "/")}),
        (
            [("date", {"sf": True})],
            {"request": RequestContext("GET", "/", [("Date", "x")])},
        ),
        (["@query-param"], {"request": RequestContext("GET", "/?a=1")}),
        (
            [("@query-param", {"name": "missing"})],
            {"request": RequestContext("GET", "/?a=1")},
        ),
        (
            [("@query-param", {"name": "a"})],
            {"request": RequestContext("GET", "/")},
        ),
        (["@status"], {"request": RequestContext("GET", "/")}),
        (["@method"], {"response": ResponseContext(200)}),
        ([("@method", {"req": True})], {"response": ResponseContext(200)}),
        ([("@method", {"req": True})], {"request": RequestContext("GET", "/")}),
        (["@target-uri"], {"request": RequestContext("GET", "/")}),
        ([], {}),
    ],
)
def test_missing_or_unsupported_never_skipped(components, kwargs):
    with pytest.raises(SignatureBaseError):
        build_signature_base(components, **kwargs)
