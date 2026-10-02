import pytest

from werkzeug.datastructures.headers import Headers
from werkzeug.http_signatures import build_signature_base
from werkzeug.http_signatures import Component
from werkzeug.http_signatures import RequestContext
from werkzeug.http_signatures import ResponseContext
from werkzeug.http_signatures import SignatureComponentError

# The request message from RFC 9421, Appendix B.2.
#
# POST /foo?param=Value&Pet=dog HTTP/1.1
# Host: example.com
# Date: Tue, 20 Apr 2021 02:07:55 GMT
# Content-Type: application/json
# Content-Digest: sha-512=:WZDP...wew==:
# Content-Length: 18
#
# {"hello": "world"}
REQ = RequestContext(
    method="POST",
    target_uri="http://example.com/foo?param=Value&Pet=dog",
    headers=Headers(
        [
            ("Host", "example.com"),
            ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("Content-Type", "application/json"),
            (
                "Content-Digest",
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm"
                "+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            ),
            ("Content-Length", "18"),
        ]
    ),
)

# The response message from RFC 9421, Appendix B.2.4. The content
# digest is sha-512 of the 62-byte body
# {"busy": true, "message": "Your call is very important to us"}.
RESP = ResponseContext(
    status=503,
    headers=Headers(
        [
            ("Date", "Tue, 20 Apr 2021 02:07:56 GMT"),
            ("Content-Type", "application/json"),
            (
                "Content-Digest",
                "sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJ"
                "DbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:",
            ),
            ("Content-Length", "62"),
        ]
    ),
)


def test_rfc9421_b_2_1_minimal() -> None:
    base = build_signature_base(
        [],
        request=REQ,
        signature_params={
            "created": 1618884473,
            "keyid": "test-key-rsa-pss",
            "nonce": "b3k2pp5k7z-50ndwpnoq00d5",
        },
    )
    assert base == (
        b'"@signature-params": ();created=1618884473;'
        b'keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50ndwpnoq00d5"'
    )


def test_rfc9421_b_2_2_selective_components() -> None:
    base = build_signature_base(
        ["@authority", "content-digest", Component("@query-param", {"name": "Pet"})],
        request=REQ,
        signature_params={
            "created": 1618884473,
            "keyid": "test-key-rsa-pss",
            "tag": "header-example",
        },
    )
    assert base == (
        b'"@authority": example.com\n'
        b'"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX'
        b"+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"
        b'"@query-param";name="Pet": dog\n'
        b'"@signature-params": ("@authority" "content-digest"'
        b' "@query-param";name="Pet");created=1618884473;'
        b'keyid="test-key-rsa-pss";tag="header-example"'
    )


def test_rfc9421_b_2_3_full_coverage() -> None:
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
        request=REQ,
        signature_params={"created": 1618884473, "keyid": "test-key-rsa-pss"},
    )
    assert base == (
        b'"date": Tue, 20 Apr 2021 02:07:55 GMT\n'
        b'"@method": POST\n'
        b'"@path": /foo\n'
        b'"@query": param=Value&Pet=dog\n'
        b'"@authority": example.com\n'
        b'"content-type": application/json\n'
        b'"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX'
        b"+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"
        b'"content-length": 18\n'
        b'"@signature-params": ("date" "@method" "@path" "@query" "@authority"'
        b' "content-type" "content-digest" "content-length");'
        b'created=1618884473;keyid="test-key-rsa-pss"'
    )


def test_rfc9421_b_2_4_response() -> None:
    base = build_signature_base(
        ["@status", "content-type", "content-digest", "content-length"],
        response=RESP,
        signature_params={"created": 1618884473, "keyid": "test-key-ecc-p256"},
    )
    assert base == (
        b'"@status": 503\n'
        b'"content-type": application/json\n'
        b'"content-digest": sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObf'
        b"wnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:\n"
        b'"content-length": 62\n'
        b'"@signature-params": ("@status" "content-type" "content-digest"'
        b' "content-length");created=1618884473;keyid="test-key-ecc-p256"'
    )


def test_component_and_param_order_is_attested() -> None:
    # The same components and parameters in a different order must
    # produce different bytes; the last line binds the original order.
    params = {"tag": "t", "created": 1618884473, "keyid": "k"}
    base_a = build_signature_base(
        ["@method", "date"], request=REQ, signature_params=params
    )
    base_b = build_signature_base(
        ["date", "@method"], request=REQ, signature_params=params
    )
    base_c = build_signature_base(
        ["@method", "date"],
        request=REQ,
        signature_params={"created": 1618884473, "keyid": "k", "tag": "t"},
    )
    assert base_a != base_b
    assert base_a != base_c
    assert base_a.endswith(
        b'"@signature-params": ("@method" "date");tag="t";'
        b'created=1618884473;keyid="k"'
    )


def test_multiple_same_name_headers() -> None:
    request = RequestContext(
        method="GET",
        target_uri="https://example.com/",
        headers=Headers(
            [("X-Test", "one"), ("x-test", "  two  "), ("X-TEST", "three")]
        ),
    )
    base = build_signature_base(["x-test"], request=request)
    assert base.split(b"\n")[0] == b'"x-test": one, two, three'


def test_raw_target_uri_is_used_verbatim() -> None:
    # URLs that differ only in encoding form must produce different
    # bytes; the target is never decoded and rebuilt.
    encoded = RequestContext("GET", "https://example.com/foo%2Fbar?x=%2f&y=%41")
    decoded = RequestContext("GET", "https://example.com/foo/bar?x=/&y=A")
    components = ["@target-uri", "@path", "@query"]
    base_encoded = build_signature_base(components, request=encoded)
    base_decoded = build_signature_base(components, request=decoded)
    assert base_encoded != base_decoded
    assert base_encoded.split(b"\n")[:3] == [
        b'"@target-uri": https://example.com/foo%2Fbar?x=%2f&y=%41',
        b'"@path": /foo%2Fbar',
        b'"@query": x=%2f&y=%41',
    ]


def test_query_param_value_keeps_percent_encoding() -> None:
    request = RequestContext("GET", "https://example.com/?a=%2F&b=&c")
    base = build_signature_base(
        [
            Component("@query-param", {"name": "a"}),
            Component("@query-param", {"name": "b"}),
            Component("@query-param", {"name": "c"}),
        ],
        request=request,
    )
    assert base.split(b"\n")[:3] == [
        b'"@query-param";name="a": %2F',
        b'"@query-param";name="b": ',
        b'"@query-param";name="c": ',
    ]


def test_empty_path_and_query() -> None:
    request = RequestContext("GET", "https://example.com")
    base = build_signature_base(["@path", "@query"], request=request)
    assert base.split(b"\n")[:2] == [b'"@path": /', b'"@query": ']

    # An empty query ("?") and an absent query both yield an empty value.
    with_q = RequestContext("GET", "https://example.com/p?")
    base = build_signature_base(["@query"], request=with_q)
    assert base.split(b"\n")[0] == b'"@query": '


def test_authority_normalization() -> None:
    request = RequestContext("GET", "HTTPS://EXAMPLE.COM:8443/p")
    base = build_signature_base(["@authority"], request=request)
    assert base.split(b"\n")[0] == b'"@authority": example.com:8443'

    ipv6 = RequestContext("GET", "http://[2001:db8::1]:8080/p")
    base = build_signature_base(["@authority"], request=ipv6)
    assert base.split(b"\n")[0] == b'"@authority": [2001:db8::1]:8080'


def test_origin_form_target_for_path_and_query() -> None:
    request = RequestContext("GET", "/foo?a=1")
    base = build_signature_base(["@path", "@query"], request=request)
    assert base.split(b"\n")[:2] == [b'"@path": /foo', b'"@query": a=1']


def test_response_req_parameter_uses_explicit_request() -> None:
    response = ResponseContext(
        status=200,
        headers=Headers([("Content-Type", "application/json")]),
        request=REQ,
    )
    base = build_signature_base(
        [
            "@status",
            "content-type",
            Component("@method", {"req": True}),
            Component("@authority", {"req": True}),
        ],
        response=response,
        signature_params={"created": 1618884473, "keyid": "test-key"},
    )
    assert base == (
        b'"@status": 200\n'
        b'"content-type": application/json\n'
        b'"@method";req: POST\n'
        b'"@authority";req: example.com\n'
        b'"@signature-params": ("@status" "content-type" "@method";req'
        b' "@authority";req);created=1618884473;keyid="test-key"'
    )


def test_response_req_parameter_request_argument() -> None:
    # The related request can also be passed directly.
    base = build_signature_base(
        [Component("@path", {"req": True})],
        request=REQ,
        response=ResponseContext(status=200),
    )
    assert base.split(b"\n")[0] == b'"@path";req: /foo'


def test_header_names_are_case_insensitive() -> None:
    base = build_signature_base(["Content-Type", "DATE"], request=REQ)
    assert base.split(b"\n")[:2] == [
        b'"content-type": application/json',
        b'"date": Tue, 20 Apr 2021 02:07:55 GMT',
    ]


@pytest.mark.parametrize(
    "components",
    [
        ["x-absent"],  # missing header field
        ["@scheme"],  # unsupported derived component
        [("date", {"sf": True})],  # unsupported parameter
        [("@query-param",)],  # missing required name parameter
        [("@method", {"name": "x"})],  # name on wrong component
        [("@query-param", {"name": "missing"})],  # absent parameter
        ["@status"],  # response-only component on a request
    ],
)
def test_unresolvable_components_raise(components: list) -> None:
    with pytest.raises(SignatureComponentError):
        built = [
            Component(*item) if isinstance(item, tuple) else item
            for item in components
        ]
        build_signature_base(built, request=REQ)


def test_duplicate_query_param_raises() -> None:
    request = RequestContext("GET", "https://example.com/?a=1&a=2")
    with pytest.raises(SignatureComponentError, match="multiple"):
        build_signature_base(
            [Component("@query-param", {"name": "a"})], request=request
        )


def test_derived_request_component_on_response_raises() -> None:
    with pytest.raises(SignatureComponentError, match="only valid for requests"):
        build_signature_base(["@method"], response=RESP)


def test_req_parameter_without_request_raises() -> None:
    with pytest.raises(SignatureComponentError, match="related request"):
        build_signature_base(
            [Component("@method", {"req": True})],
            response=ResponseContext(status=200),
        )


def test_status_with_req_parameter_raises() -> None:
    with pytest.raises(SignatureComponentError, match="@status"):
        build_signature_base(
            [Component("@status", {"req": True})],
            response=ResponseContext(status=200, request=REQ),
        )


def test_target_uri_requires_absolute_uri() -> None:
    request = RequestContext("GET", "/foo?a=1")
    with pytest.raises(SignatureComponentError, match="absolute"):
        build_signature_base(["@target-uri"], request=request)
    with pytest.raises(SignatureComponentError, match="absolute"):
        build_signature_base(["@authority"], request=request)


def test_userinfo_in_target_uri_raises() -> None:
    request = RequestContext("GET", "https://user@example.com/")
    with pytest.raises(SignatureComponentError, match="userinfo"):
        build_signature_base(["@authority"], request=request)


def test_no_context_raises() -> None:
    with pytest.raises(SignatureComponentError, match="context"):
        build_signature_base(["@method"])


def test_invalid_component_name_raises() -> None:
    with pytest.raises(SignatureComponentError, match="Invalid header"):
        Component("bad name")
    with pytest.raises(SignatureComponentError, match="Invalid derived"):
        Component("@bad_name")
    with pytest.raises(SignatureComponentError, match="not supported"):
        Component("@scheme")


def test_signature_param_string_escaping() -> None:
    base = build_signature_base(
        [], request=REQ, signature_params={"keyid": 'a"b\\c'}
    )
    assert base == b'"@signature-params": ();keyid="a\\"b\\\\c"'


def test_req_false_is_equivalent_to_absent() -> None:
    base = build_signature_base(
        [Component("@method", {"req": False})], request=REQ
    )
    assert base.split(b"\n")[0] == b'"@method": POST'
