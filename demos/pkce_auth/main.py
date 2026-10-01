import asyncio
import base64
import dataclasses
import hashlib
import secrets

import tornado.web
from tornado.auth import OAuth2PKCEConfig
from tornado.httputil import url_concat


class BaseHandler(tornado.web.RequestHandler):
    def write_error(self, status_code, **kwargs):
        if 400 <= status_code < 500:
            message = "Login failed. Please start a new login."
        else:
            message = "The login service is temporarily unavailable."
        self.finish(f"<html><body><h1>{status_code}</h1><p>{message}</p></body></html>")


class IndexHandler(BaseHandler):
    def get(self):
        user = self.get_signed_cookie("pkce_demo_user")
        if user:
            self.finish("<p>Signed in. <a href='/logout'>Log out</a></p>")
        else:
            self.finish(
                "<p><a href='/login'>Start PKCE login</a></p>"
                "<p><a href='/login?deny=1'>Simulate provider rejection</a></p>"
            )


class LoginHandler(BaseHandler, tornado.auth.OAuth2Mixin):
    def pkce_config(self):
        return self.settings["oauth2_pkce"]

    async def get(self):
        if self.get_query_argument("state", ""):
            await self.oauth2_pkce_complete_login(self.pkce_config())
            self.set_signed_cookie("pkce_demo_user", "local-user")
            self.redirect("/")
            return
        config = self.pkce_config()
        if self.get_query_argument("deny", "0") == "1":
            config = dataclasses.replace(config, extra_authorize_params={"deny": "1"})
        await self.oauth2_pkce_authorize_redirect(config)


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("pkce_demo_user")
        self.redirect("/")


class FakeAuthorizeHandler(BaseHandler):
    def get(self):
        if self.get_query_argument("deny", "0") == "1":
            self.redirect(
                url_concat(
                    self.get_query_argument("redirect_uri"),
                    {
                        "state": self.get_query_argument("state"),
                        "error": "access_denied",
                    },
                )
            )
            return

        code = secrets.token_urlsafe(24)
        self.application.settings["fake_codes"][code] = {
            "challenge": self.get_query_argument("code_challenge"),
            "redirect_uri": self.get_query_argument("redirect_uri"),
            "client_id": self.get_query_argument("client_id"),
        }
        self.redirect(
            url_concat(
                self.get_query_argument("redirect_uri"),
                {"state": self.get_query_argument("state"), "code": code},
            )
        )


class FakeTokenHandler(BaseHandler):
    def post(self):
        code = self.get_body_argument("code")
        authorization = self.application.settings["fake_codes"].pop(code, None)
        if authorization is None:
            self.set_status(400)
            self.finish({"error": "invalid_grant"})
            return

        verifier = self.get_body_argument("code_verifier")
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        if (
            challenge != authorization["challenge"]
            or self.get_body_argument("redirect_uri") != authorization["redirect_uri"]
            or self.get_body_argument("client_id") != authorization["client_id"]
            or self.get_body_argument("grant_type") != "authorization_code"
        ):
            self.set_status(400)
            self.finish({"error": "invalid_grant"})
            return

        self.finish(
            {
                "access_token": secrets.token_urlsafe(32),
                "token_type": "Bearer",
            }
        )


def make_app(port=8888):
    redirect_uri = f"http://localhost:{port}/login"
    return tornado.web.Application(
        [
            (r"/", IndexHandler),
            (r"/login", LoginHandler),
            (r"/logout", LogoutHandler),
            (r"/fake/authorize", FakeAuthorizeHandler),
            (r"/fake/token", FakeTokenHandler),
        ],
        cookie_secret=secrets.token_urlsafe(64),
        fake_codes={},
        oauth2_pkce=OAuth2PKCEConfig(
            client_id="local-client",
            redirect_uri=redirect_uri,
            authorize_url=f"http://localhost:{port}/fake/authorize",
            access_token_url=f"http://localhost:{port}/fake/token",
            scope=["openid", "profile"],
        ),
    )


async def main():
    app = make_app()
    app.listen(8888)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
