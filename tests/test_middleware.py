from __future__ import annotations

from http import HTTPStatus

from django.http import HttpResponse
from django.test import TestCase
from django.test.utils import override_settings
from django.utils.deprecation import MiddlewareMixin

from corsheaders.middleware import (
    ACCESS_CONTROL_ALLOW_CREDENTIALS,
    ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK,
    ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_CONTROL_MAX_AGE,
)
from tests.utils import prepend_middleware, temporary_check_request_handler


class ShortCircuitMiddleware(MiddlewareMixin):
    def process_request(self, request):
        return HttpResponse("short-circuit-middleware-response")


class CorsMiddlewareTests(TestCase):
    def test_get_no_origin(self):
        resp = self.client.get("/")
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    def test_get_origin_vary_by_default(self):
        resp = self.client.get("/")
        assert resp["vary"] == "origin"

    def test_get_invalid_origin(self):
        resp = self.client.get("/", headers={"origin": "https://example.com]"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_not_in_allowed_origins(self):
        resp = self.client.get("/", headers={"origin": "https://example.org"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["http://example.org"])
    def test_get_not_in_allowed_origins_due_to_wrong_scheme(self):
        resp = self.client.get("/", headers={"origin": "https://example.org"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://example.com", "https://example.org"]
    )
    def test_get_in_allowed_origins(self):
        resp = self.client.get("/", headers={"origin": "https://example.org"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.org"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.org"])
    async def test_async_get_in_allowed_origins(self):
        resp = await self.async_client.get("/async/", origin="https://example.org")
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.org"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com", "null"])
    def test_null_in_allowed_origins(self):
        resp = self.client.get("/", headers={"origin": "null"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "null"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com", "file://"])
    def test_file_in_allowed_origins(self):
        """
        'file://' should be allowed as an origin since Chrome on Android
        mistakenly sends it
        """
        resp = self.client.get("/", headers={"origin": "file://"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "file://"

    @override_settings(
        CORS_ALLOW_ALL_ORIGINS=True,
        CORS_EXPOSE_HEADERS=["accept", "content-type"],
    )
    def test_get_expose_headers(self):
        resp = self.client.get("/", headers={"origin": "https://example.com"})
        assert resp[ACCESS_CONTROL_EXPOSE_HEADERS] == "accept, content-type"

    @override_settings(CORS_ALLOW_ALL_ORIGINS=True)
    def test_get_dont_expose_headers(self):
        resp = self.client.get("/", headers={"origin": "https://example.com"})
        assert ACCESS_CONTROL_EXPOSE_HEADERS not in resp

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://example.com"], CORS_ALLOW_CREDENTIALS=True
    )
    def test_get_allow_credentials(self):
        resp = self.client.get("/", headers={"origin": "https://example.com"})
        assert resp[ACCESS_CONTROL_ALLOW_CREDENTIALS] == "true"

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://example.com"], CORS_ALLOW_CREDENTIALS=True
    )
    def test_get_allow_credentials_bad_origin(self):
        resp = self.client.get("/", headers={"origin": "https://example.org"})
        assert ACCESS_CONTROL_ALLOW_CREDENTIALS not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_allow_credentials_disabled(self):
        resp = self.client.get("/", headers={"origin": "https://example.com"})
        assert ACCESS_CONTROL_ALLOW_CREDENTIALS not in resp

    @override_settings(CORS_ALLOW_PRIVATE_NETWORK=True, CORS_ALLOW_ALL_ORIGINS=True)
    def test_allow_private_network_added_if_enabled_and_requested(self):
        resp = self.client.get(
            "/",
            headers={
                "access-control-request-private-network": "true",
                "origin": "http://example.com",
            },
        )
        assert resp[ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK] == "true"

    @override_settings(CORS_ALLOW_PRIVATE_NETWORK=True, CORS_ALLOW_ALL_ORIGINS=True)
    def test_allow_private_network_not_added_if_enabled_and_not_requested(self):
        resp = self.client.get("/", headers={"origin": "http://example.com"})
        assert ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK not in resp

    @override_settings(
        CORS_ALLOW_PRIVATE_NETWORK=True,
        CORS_ALLOWED_ORIGINS=["http://example.com"],
    )
    def test_allow_private_network_not_added_if_enabled_and_no_cors_origin(self):
        resp = self.client.get(
            "/",
            headers={
                "access-control-request-private-network": "true",
                "origin": "http://example.org",
            },
        )
        assert ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK not in resp

    @override_settings(CORS_ALLOW_PRIVATE_NETWORK=False, CORS_ALLOW_ALL_ORIGINS=True)
    def test_allow_private_network_not_added_if_disabled_and_requested(self):
        resp = self.client.get(
            "/",
            headers={
                "access-control-request-private-network": "true",
                "origin": "http://example.com",
            },
        )
        assert ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK not in resp

    @override_settings(
        CORS_ALLOW_HEADERS=["content-type"],
        CORS_ALLOW_METHODS=["GET", "OPTIONS"],
        CORS_PREFLIGHT_MAX_AGE=1002,
        CORS_ALLOW_ALL_ORIGINS=True,
    )
    def test_options_allowed_origin(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_HEADERS] == "content-type"
        assert resp[ACCESS_CONTROL_ALLOW_METHODS] == "GET, OPTIONS"
        assert resp[ACCESS_CONTROL_MAX_AGE] == "1002"

    @override_settings(
        CORS_ALLOW_HEADERS=["content-type"],
        CORS_ALLOW_METHODS=["GET", "OPTIONS"],
        CORS_PREFLIGHT_MAX_AGE=1002,
        CORS_ALLOW_ALL_ORIGINS=True,
    )
    async def test_async_options_allowed_origin(self):
        resp = await self.async_client.options(
            "/async/",
            origin="https://example.com",
            access_control_request_method="GET",
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_HEADERS] == "content-type"
        assert resp[ACCESS_CONTROL_ALLOW_METHODS] == "GET, OPTIONS"
        assert resp[ACCESS_CONTROL_MAX_AGE] == "1002"

    @override_settings(
        CORS_ALLOW_HEADERS=["content-type"],
        CORS_ALLOW_METHODS=["GET", "OPTIONS"],
        CORS_PREFLIGHT_MAX_AGE=0,
        CORS_ALLOW_ALL_ORIGINS=True,
    )
    def test_options_no_max_age(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp[ACCESS_CONTROL_ALLOW_HEADERS] == "content-type"
        assert resp[ACCESS_CONTROL_ALLOW_METHODS] == "GET, OPTIONS"
        assert ACCESS_CONTROL_MAX_AGE not in resp

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://localhost:9000"],
    )
    def test_options_allowed_origins_with_port(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://localhost:9000",
                "access-control-request-method": "GET",
            },
        )
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://localhost:9000"

    @override_settings(
        CORS_ALLOWED_ORIGIN_REGEXES=[r"^https://\w+\.example\.com$"],
    )
    def test_options_adds_origin_when_domain_found_in_allowed_regexes(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://foo.example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://foo.example.com"

    @override_settings(
        CORS_ALLOWED_ORIGIN_REGEXES=[
            r"^https://\w+\.example\.org$",
            r"^https://\w+\.example\.com$",
        ],
    )
    def test_options_adds_origin_when_domain_found_in_allowed_regexes_second(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://foo.example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://foo.example.com"

    @override_settings(
        CORS_ALLOWED_ORIGIN_REGEXES=[r"^https://\w+\.example\.org$"],
    )
    def test_options_doesnt_add_origin_when_domain_not_found_in_allowed_regexes(
        self,
    ):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://foo.example.com",
                "access-control-request-method": "GET",
            },
        )
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    def test_options_empty_request_method(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "",
            },
        )
        assert resp.status_code == HTTPStatus.OK

    def test_options_no_headers(self):
        resp = self.client.options("/")
        assert resp.status_code == HTTPStatus.METHOD_NOT_ALLOWED

    @override_settings(CORS_ALLOW_CREDENTIALS=True, CORS_ALLOW_ALL_ORIGINS=True)
    def test_allow_all_origins_get(self):
        resp = self.client.get(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.com"
        assert resp["vary"] == "origin"

    @override_settings(CORS_ALLOW_CREDENTIALS=True, CORS_ALLOW_ALL_ORIGINS=True)
    def test_allow_all_origins_options(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.com"
        assert resp["vary"] == (
            "origin, access-control-request-method, "
            + "access-control-request-headers"
        )

    @override_settings(CORS_ALLOW_CREDENTIALS=True, CORS_ALLOW_ALL_ORIGINS=True)
    def test_non_200_headers_still_set(self):
        """
        It's not clear whether the header should still be set for non-HTTP200
        when not a preflight request. However this is the existing behaviour for
        django-cors-middleware, so at least this test makes that explicit, especially
        since for the switch to Django 1.10, special-handling will need to be put in
        place to preserve this behaviour. See `ExceptionMiddleware` mention here:
        https://docs.djangoproject.com/en/stable/topics/http/middleware/#upgrading-pre-django-1-10-style-middleware  # noqa: E501
        """
        resp = self.client.get(
            "/unauthorized/", headers={"origin": "https://example.com"}
        )
        assert resp.status_code == HTTPStatus.UNAUTHORIZED
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.com"

    @override_settings(CORS_ALLOW_CREDENTIALS=True, CORS_ALLOW_ALL_ORIGINS=True)
    def test_auth_view_options(self):
        """
        Ensure HTTP200 and header still set, for preflight requests to views requiring
        authentication. See: https://github.com/adamchainz/django-cors-headers/issues/3
        """
        resp = self.client.options(
            "/test-401/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.com"
        assert resp["Content-Length"] == "0"

    def test_signal_handler_that_returns_false(self):
        def handler(*args, **kwargs):
            return False

        with temporary_check_request_handler(handler):
            resp = self.client.options(
                "/",
                headers={
                    "origin": "https://example.com",
                    "access-control-request-method": "GET",
                },
            )

            assert resp.status_code == HTTPStatus.OK
            assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    def test_signal_handler_that_returns_true(self):
        def handler(*args, **kwargs):
            return True

        with temporary_check_request_handler(handler):
            resp = self.client.options(
                "/",
                headers={
                    "origin": "https://example.com",
                    "access-control-request-method": "GET",
                },
            )
            assert resp.status_code == HTTPStatus.OK
            assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.com"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_signal_handler_allow_some_urls_to_everyone(self):
        def allow_api_to_all(sender, request, **kwargs):
            return request.path.startswith("/api/")

        with temporary_check_request_handler(allow_api_to_all):
            resp = self.client.options(
                "/",
                headers={
                    "origin": "https://example.org",
                    "access-control-request-method": "GET",
                },
            )
            assert resp.status_code == HTTPStatus.OK
            assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

            resp = self.client.options(
                "/api/something/",
                headers={
                    "origin": "https://example.org",
                    "access-control-request-method": "GET",
                },
            )
            assert resp.status_code == HTTPStatus.OK
            assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.org"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_signal_called_once_during_normal_flow(self):
        calls = 0

        def allow_all(sender, request, **kwargs):
            nonlocal calls
            calls += 1
            return True

        with temporary_check_request_handler(allow_all):
            self.client.get("/", headers={"origin": "https://example.org"})

            assert calls == 1

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    @prepend_middleware(f"{__name__}.ShortCircuitMiddleware")
    def test_get_short_circuit(self):
        """
        Test a scenario when a middleware that returns a response is run before
        the ``CorsMiddleware``. In this case
        ``CorsMiddleware.process_response()`` should ignore the request if
        MIDDLEWARE setting is used (new mechanism in Django 1.10+).
        """
        resp = self.client.get("/", headers={"origin": "https://example.com"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://example.com"], CORS_URLS_REGEX=r"^/foo/$"
    )
    @prepend_middleware(f"{__name__}.ShortCircuitMiddleware")
    def test_get_short_circuit_should_be_ignored(self):
        resp = self.client.get("/", headers={"origin": "https://example.com"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://example.com"], CORS_URLS_REGEX=r"^/foo/$"
    )
    def test_get_regex_matches(self):
        resp = self.client.get("/foo/", headers={"origin": "https://example.com"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN in resp

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://example.com"], CORS_URLS_REGEX=r"^/not-foo/$"
    )
    def test_get_regex_doesnt_match(self):
        resp = self.client.get("/foo/", headers={"origin": "https://example.com"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://example.com"], CORS_URLS_REGEX=r"^/foo/$"
    )
    def test_get_regex_matches_path_info(self):
        resp = self.client.get(
            "/foo/", headers={"origin": "https://example.com"}, SCRIPT_NAME="/prefix/"
        )
        assert ACCESS_CONTROL_ALLOW_ORIGIN in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_cors_enabled_is_attached_and_bool(self):
        """
        Ensure that request._cors_enabled is available - although a private API
        someone might use it for debugging
        """
        resp = self.client.get("/", headers={"origin": "https://example.com"})
        request = resp.wsgi_request
        assert isinstance(request._cors_enabled, bool)  # type: ignore [attr-defined]
        assert request._cors_enabled  # type: ignore [attr-defined]

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_works_if_view_deletes_cors_enabled(self):
        """
        Just in case something crazy happens in the view or other middleware,
        check that get_response doesn't fall over if `_cors_enabled` is removed
        """
        resp = self.client.get(
            "/delete-enabled/", headers={"origin": "https://example.com"}
        )
        assert ACCESS_CONTROL_ALLOW_ORIGIN in resp

    @override_settings(
        CORS_ALLOWED_ORIGIN_REGEXES=[r"^https://partner\.example\.com$"],
    )
    def test_get_origin_with_attacker_suffix_not_allowed(self):
        resp = self.client.get(
            "/", headers={"origin": "https://partner.example.com.attacker.test"}
        )
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(
        CORS_ALLOWED_ORIGIN_REGEXES=[r"^https://\w+\.example\.com$"],
    )
    def test_get_origin_regex_with_suffix_not_allowed(self):
        resp = self.client.get(
            "/", headers={"origin": "https://foo.example.com.attacker.test"}
        )
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(
        CORS_ALLOWED_ORIGIN_REGEXES=[r"https://\w+\.example\.com"],
    )
    def test_get_origin_regex_without_anchors_still_matches(self):
        resp = self.client.get("/", headers={"origin": "https://foo.example.com"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://foo.example.com"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_with_path_not_allowed(self):
        resp = self.client.get("/", headers={"origin": "https://example.com/path"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_with_trailing_slash_not_allowed(self):
        resp = self.client.get("/", headers={"origin": "https://example.com/"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_with_query_not_allowed(self):
        resp = self.client.get("/", headers={"origin": "https://example.com/?x=1"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_with_userinfo_not_allowed(self):
        resp = self.client.get(
            "/", headers={"origin": "https://user:pass@example.com"}
        )
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_with_whitespace_not_allowed(self):
        resp = self.client.get("/", headers={"origin": "https://example.com "})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_case_insensitive_scheme_and_host(self):
        resp = self.client.get("/", headers={"origin": "HTTPS://EXAMPLE.COM"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "HTTPS://EXAMPLE.COM"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_with_default_port_allowed(self):
        resp = self.client.get("/", headers={"origin": "https://example.com:443"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.com:443"

    @override_settings(CORS_ALLOWED_ORIGINS=["http://example.com"])
    def test_get_origin_with_default_http_port_allowed(self):
        resp = self.client.get("/", headers={"origin": "http://example.com:80"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "http://example.com:80"

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com"])
    def test_get_origin_with_non_default_port_not_allowed(self):
        resp = self.client.get("/", headers={"origin": "https://example.com:444"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGINS=["https://example.com:8443"])
    def test_get_origin_with_configured_port_allowed(self):
        resp = self.client.get("/", headers={"origin": "https://example.com:8443"})
        assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.com:8443"

    @override_settings(CORS_ALLOW_ALL_ORIGINS=True)
    def test_allow_all_origins_malformed_origin_rejected(self):
        resp = self.client.get("/", headers={"origin": "https://exa mple.com"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGIN_REGEXES=[r".*"])
    def test_null_origin_not_allowed_by_regex(self):
        resp = self.client.get("/", headers={"origin": "null"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(CORS_ALLOWED_ORIGIN_REGEXES=[r".*"])
    def test_file_origin_not_allowed_by_regex(self):
        resp = self.client.get("/", headers={"origin": "file://"})
        assert ACCESS_CONTROL_ALLOW_ORIGIN not in resp

    @override_settings(
        CORS_ALLOW_METHODS=["GET", "OPTIONS"],
        CORS_ALLOW_ALL_ORIGINS=True,
    )
    def test_options_request_method_not_allowed(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "DELETE",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert ACCESS_CONTROL_ALLOW_METHODS not in resp

    @override_settings(
        CORS_ALLOW_METHODS=["GET", "OPTIONS"],
        CORS_ALLOW_ALL_ORIGINS=True,
    )
    def test_options_request_method_allowed(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_METHODS] == "GET, OPTIONS"

    @override_settings(
        CORS_ALLOW_HEADERS=["content-type"],
        CORS_ALLOW_ALL_ORIGINS=True,
    )
    def test_options_request_headers_not_allowed(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
                "access-control-request-headers": "x-evil-header",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert ACCESS_CONTROL_ALLOW_HEADERS not in resp

    @override_settings(
        CORS_ALLOW_HEADERS=["content-type"],
        CORS_ALLOW_ALL_ORIGINS=True,
    )
    def test_options_request_headers_allowed_case_insensitive(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
                "access-control-request-headers": "Content-Type",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_HEADERS] == "content-type"

    @override_settings(CORS_ALLOW_ALL_ORIGINS=True)
    def test_options_preflight_vary_headers(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp["vary"] == (
            "origin, access-control-request-method, "
            + "access-control-request-headers"
        )

    @override_settings(CORS_ALLOW_PRIVATE_NETWORK=False, CORS_ALLOW_ALL_ORIGINS=True)
    def test_options_private_network_requested_but_disabled(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
                "access-control-request-private-network": "true",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK not in resp

    @override_settings(CORS_ALLOW_PRIVATE_NETWORK=True, CORS_ALLOW_ALL_ORIGINS=True)
    def test_options_private_network_requested_and_enabled(self):
        resp = self.client.options(
            "/",
            headers={
                "origin": "https://example.com",
                "access-control-request-method": "GET",
                "access-control-request-private-network": "true",
            },
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp[ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK] == "true"

    def test_signal_handler_allows_origin_not_in_whitelist_on_get(self):
        def handler(*args, **kwargs):
            return True

        with temporary_check_request_handler(handler):
            resp = self.client.get("/", headers={"origin": "https://example.org"})
            assert resp[ACCESS_CONTROL_ALLOW_ORIGIN] == "https://example.org"
