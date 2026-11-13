from __future__ import annotations

from datetime import datetime, timezone

import pytest

from secure import SameSite, SetCookie
from secure.cookies.set_cookie import MAX_COOKIE_PAYLOAD_BYTES

from ._rfc6265 import parse_set_cookie


class TestBasicSerialization:
    def test_header_name_is_set_cookie(self) -> None:
        cookie = SetCookie("session", "abc")
        assert cookie.header_name == "Set-Cookie"

    def test_minimal_cookie_serializes_name_value_only(self) -> None:
        cookie = SetCookie("session", "abc")
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.name == "session"
        assert parsed.value == "abc"
        assert parsed.attributes == {}
        assert str(cookie) == cookie.header_value

    def test_empty_value_is_allowed(self) -> None:
        cookie = SetCookie("cleared", "")
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.name == "cleared"
        assert parsed.value == ""

    def test_full_attribute_set_round_trips_through_rfc_parser(self) -> None:
        cookie = SetCookie(
            "session",
            "abc123",
            path="/",
            domain="example.com",
            max_age=3600,
            same_site=SameSite.LAX,
            secure=True,
            http_only=True,
        )
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attribute_names() == {"path", "domain", "max-age", "samesite", "secure", "httponly"}
        assert parsed.attributes["path"] == "/"
        assert parsed.attributes["domain"] == "example.com"
        assert parsed.attributes["max-age"] == "3600"
        assert parsed.attributes["samesite"] == "Lax"
        assert parsed.attributes["secure"] is True
        assert parsed.attributes["httponly"] is True

    def test_header_items_returns_single_set_cookie_pair(self) -> None:
        cookie = SetCookie("session", "abc", secure=True)
        assert cookie.header_items() == (("Set-Cookie", cookie.header_value),)


class TestHostPrefix:
    def test_host_prefix_requires_path_slash(self) -> None:
        with pytest.raises(ValueError, match="__Host- prefix requires Path=/"):
            SetCookie("__Host-session", "abc", secure=True)

    def test_host_prefix_rejects_domain(self) -> None:
        with pytest.raises(ValueError, match="__Host- prefix forbids the Domain attribute"):
            SetCookie("__Host-session", "abc", path="/", domain="example.com", secure=True)

    def test_host_prefix_requires_secure(self) -> None:
        with pytest.raises(ValueError, match="__Host- prefix requires the Secure attribute"):
            SetCookie("__Host-session", "abc", path="/")

    def test_host_prefix_rejects_non_root_path(self) -> None:
        with pytest.raises(ValueError, match="__Host- prefix requires Path=/"):
            SetCookie("__Host-session", "abc", path="/app", secure=True)

    def test_valid_host_cookie_serializes(self) -> None:
        cookie = SetCookie(
            "__Host-session",
            "abc",
            path="/",
            secure=True,
            http_only=True,
            same_site=SameSite.STRICT,
        )
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.name == "__Host-session"
        assert parsed.has("path")
        assert not parsed.has("domain")
        assert parsed.attributes["path"] == "/"
        assert parsed.attributes["secure"] is True


class TestSecurePrefix:
    def test_secure_prefix_requires_secure(self) -> None:
        with pytest.raises(ValueError, match="__Secure- prefix requires the Secure attribute"):
            SetCookie("__Secure-id", "abc")

    def test_secure_prefix_accepts_domain_and_path_with_secure(self) -> None:
        cookie = SetCookie("__Secure-id", "abc", domain="example.com", path="/app", secure=True)
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attributes["domain"] == "example.com"
        assert parsed.attributes["path"] == "/app"
        assert parsed.attributes["secure"] is True


class TestUnprefixedCookie:
    def test_unprefixed_cookie_works_without_secure(self) -> None:
        cookie = SetCookie("plain", "abc", path="/")
        parsed = parse_set_cookie(cookie.header_value)
        assert not parsed.has("secure")
        assert parsed.attributes["path"] == "/"


class TestSameSite:
    @pytest.mark.parametrize(
        ("member", "expected"),
        [
            (SameSite.STRICT, "Strict"),
            (SameSite.LAX, "Lax"),
            (SameSite.NONE, "None"),
        ],
    )
    def test_all_three_levels_serialize(self, member: SameSite, expected: str) -> None:
        cookie = SetCookie("s", "1", same_site=member, secure=True)
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attributes["samesite"] == expected

    def test_same_site_none_requires_secure(self) -> None:
        with pytest.raises(ValueError, match="SameSite=None requires the Secure attribute"):
            SetCookie("s", "1", same_site=SameSite.NONE)

    def test_same_site_none_with_secure_is_allowed(self) -> None:
        cookie = SetCookie("s", "1", same_site=SameSite.NONE, secure=True)
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attributes["samesite"] == "None"
        assert parsed.attributes["secure"] is True

    def test_same_site_accepts_case_insensitive_string(self) -> None:
        cookie = SetCookie("s", "1", same_site="strict", secure=True)
        assert cookie.same_site is SameSite.STRICT

    def test_same_site_rejects_unknown_string(self) -> None:
        with pytest.raises(ValueError, match="SameSite must be one of"):
            SetCookie("s", "1", same_site="banana", secure=True)

    def test_strict_and_lax_do_not_require_secure(self) -> None:
        lax = parse_set_cookie(SetCookie("s", "1", same_site="lax").header_value)
        strict = parse_set_cookie(SetCookie("s", "1", same_site=SameSite.STRICT).header_value)
        assert lax.attributes["samesite"] == "Lax"
        assert strict.attributes["samesite"] == "Strict"
        assert not lax.has("secure")
        assert not strict.has("secure")


class TestPartitioned:
    def test_partitioned_requires_secure(self) -> None:
        with pytest.raises(ValueError, match="Partitioned requires the Secure attribute"):
            SetCookie("s", "1", partitioned=True)

    def test_partitioned_with_secure_serializes(self) -> None:
        cookie = SetCookie(
            "s",
            "1",
            partitioned=True,
            secure=True,
            same_site=SameSite.NONE,
        )
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attributes["partitioned"] is True
        assert parsed.attributes["samesite"] == "None"

    def test_partitioned_combines_with_host_prefix(self) -> None:
        cookie = SetCookie("__Host-s", "1", path="/", secure=True, partitioned=True)
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attributes["partitioned"] is True
        assert not parsed.has("domain")


class TestExpiry:
    def test_max_age_serializes_as_integer_seconds(self) -> None:
        cookie = SetCookie("s", "1", max_age=0)
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attributes["max-age"] == "0"
        assert cookie.max_age == 0

    def test_negative_max_age_rejected(self) -> None:
        with pytest.raises(ValueError, match="Max-Age must be a non-negative integer"):
            SetCookie("s", "1", max_age=-5)

    def test_boolean_max_age_rejected(self) -> None:
        with pytest.raises(TypeError, match="Max-Age must be an integer"):
            SetCookie("s", "1", max_age=True)

    def test_aware_expires_serializes_rfc_http_date(self) -> None:
        expires = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        cookie = SetCookie("s", "1", expires=expires)
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.attributes["expires"] == "Thu, 31 Dec 2026 23:59:59 GMT"

    def test_naive_expires_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware datetime"):
            SetCookie("s", "1", expires=datetime(2026, 12, 31, 23, 59, 59))  # noqa: DTZ001

    def test_max_age_and_expires_conflict_rejected(self) -> None:
        with pytest.raises(ValueError, match="Max-Age and Expires are mutually exclusive"):
            SetCookie(
                "s",
                "1",
                max_age=60,
                expires=datetime(2026, 12, 31, tzinfo=timezone.utc),
            )


class TestInvalidNamesAndValues:
    @pytest.mark.parametrize("name", ["", "bad name", "a;b", "x=y", "tab\tname", "nl\n"])
    def test_invalid_names_rejected(self, name: str) -> None:
        with pytest.raises(ValueError, match="cookie name"):
            SetCookie(name, "1")

    @pytest.mark.parametrize("value", ["a;b", 'a"b', "a,b", "a b", "a\\b", "a\tb", "ctrl\x00", "del\x7f"])
    def test_invalid_values_rejected(self, value: str) -> None:
        with pytest.raises(ValueError):
            SetCookie("s", value)

    def test_non_string_value_rejected(self) -> None:
        with pytest.raises(TypeError, match="cookie value must be a string"):
            SetCookie("s", 123)

    def test_invalid_path_and_domain_rejected(self) -> None:
        with pytest.raises(ValueError, match="Path"):
            SetCookie("s", "1", path="/a b")
        with pytest.raises(ValueError, match="Domain"):
            SetCookie("s", "1", domain="example,com")


class TestLengthAndUnicode:
    def test_ascii_payload_at_limit_accepted(self) -> None:
        value = "a" * (MAX_COOKIE_PAYLOAD_BYTES - len("s="))
        cookie = SetCookie("s", value)
        assert len(cookie.header_value.split(";", 1)[0].encode("utf-8")) == MAX_COOKIE_PAYLOAD_BYTES

    def test_oversized_ascii_payload_rejected(self) -> None:
        with pytest.raises(ValueError, match="payload exceeds 4096 bytes"):
            SetCookie("s", "a" * MAX_COOKIE_PAYLOAD_BYTES)

    def test_oversized_utf8_payload_rejected(self) -> None:
        # Each CJK character is 3 bytes in UTF-8; 1366 of them exceed the limit.
        with pytest.raises(ValueError, match="payload exceeds 4096 bytes"):
            SetCookie("s", "中" * 1366)

    def test_chinese_value_preserved_verbatim(self) -> None:
        cookie = SetCookie("lang", "中文偏好", path="/", secure=True)
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.name == "lang"
        assert parsed.value == "中文偏好"
        assert cookie.header_value.startswith("lang=中文偏好;")

    def test_emoji_value_accepted_as_utf8(self) -> None:
        cookie = SetCookie("emoji", "✅")
        parsed = parse_set_cookie(cookie.header_value)
        assert parsed.value == "✅"


class TestSensitiveValueHandling:
    def test_repr_redacts_value(self) -> None:
        sensitive_value = "supersecret-token"
        cookie = SetCookie("session", sensitive_value, secure=True)
        rendered = repr(cookie)
        assert sensitive_value not in rendered
        assert "<redacted>" in rendered
        assert "session" in rendered

    def test_exception_messages_never_contain_value(self) -> None:
        sensitive_value = "do-not-leak-me"
        invalid_cases = (
            lambda: SetCookie("__Host-s", sensitive_value, path="/"),
            lambda: SetCookie("__Secure-s", sensitive_value),
            lambda: SetCookie("s", sensitive_value, same_site=SameSite.NONE),
            lambda: SetCookie("s", sensitive_value, partitioned=True),
            lambda: SetCookie("s", sensitive_value + "x" * 5000),
        )
        for build in invalid_cases:
            with pytest.raises(ValueError) as exc_info:
                build()
            assert sensitive_value not in str(exc_info.value)


class TestEquality:
    def test_equal_cookies_share_header_value(self) -> None:
        assert SetCookie("s", "1", secure=True) == SetCookie("s", "1", secure=True)
        assert hash(SetCookie("s", "1", secure=True)) == hash(SetCookie("s", "1", secure=True))
        assert SetCookie("s", "1") != SetCookie("s", "2")
        assert SetCookie("s", "1").__eq__("not-a-cookie") is NotImplemented


class TestReadableAttributes:
    def test_attributes_expose_validated_inputs(self) -> None:
        expires = datetime(2027, 1, 1, tzinfo=timezone.utc)
        cookie = SetCookie(
            "s",
            "1",
            path="/",
            domain="example.com",
            expires=expires,
            same_site="lax",
            secure=True,
            http_only=True,
            partitioned=False,
        )
        assert cookie.name == "s"
        assert cookie.path == "/"
        assert cookie.domain == "example.com"
        assert cookie.max_age is None
        assert cookie.expires is expires
        assert cookie.same_site is SameSite.LAX
        assert cookie.secure is True
        assert cookie.http_only is True
        assert cookie.partitioned is False

    def test_del_character_in_name_and_value_rejected(self) -> None:
        with pytest.raises(ValueError, match="cookie name"):
            SetCookie("a\x7fb", "1")
        with pytest.raises(ValueError, match="control characters"):
            SetCookie("s", "a\x7fb")

    def test_length_error_message_does_not_echo_value(self) -> None:
        oversized = "z" * 5000
        with pytest.raises(ValueError) as exc_info:
            SetCookie("s", oversized)
        assert "zzzz" not in str(exc_info.value)
        assert "s" in str(exc_info.value)

    def test_samesite_enum_string_values_match_rfc_spelling(self) -> None:
        assert SameSite.STRICT.value == "Strict"
        assert SameSite.LAX.value == "Lax"
        assert SameSite.NONE.value == "None"

    def test_non_datetime_expires_rejected(self) -> None:
        with pytest.raises(TypeError, match=r"datetime\.datetime instance"):
            SetCookie("s", "1", expires="Thu, 31 Dec 2026 23:59:59 GMT")
