import time
from importlib import import_module

from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.middleware import MiddlewareMixin
from django.utils.cache import patch_vary_headers
from django.utils.http import http_date


class SessionMiddleware(MiddlewareMixin):
    async_capable = False

    def __init__(self, get_response):
        super().__init__(get_response)
        engine = import_module(settings.SESSION_ENGINE)
        self.SessionStore = engine.SessionStore

    def process_request(self, request):
        if hasattr(self.SessionStore, "from_cookies"):
            # The backend stores session data in the cookies themselves and
            # may split it across multiple cookies.
            request.session = self.SessionStore.from_cookies(request.COOKIES)
        else:
            session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
            request.session = self.SessionStore(session_key)

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie or delete
        the session cookie if the session has been emptied.
        """
        try:
            accessed = request.session.accessed
            modified = request.session.modified
            empty = request.session.is_empty()
        except AttributeError:
            return response
        # Session backends that store data in the cookies may use several
        # cookies and know which ones must be deleted.
        if hasattr(request.session, "get_delete_cookie_names"):
            delete_cookie_names = request.session.get_delete_cookie_names()
        elif settings.SESSION_COOKIE_NAME in request.COOKIES:
            delete_cookie_names = [settings.SESSION_COOKIE_NAME]
        else:
            delete_cookie_names = []
        # First check if we need to delete this cookie.
        # The session should be deleted only if the session is entirely empty.
        if delete_cookie_names and empty:
            for cookie_name in delete_cookie_names:
                response.delete_cookie(
                    cookie_name,
                    path=settings.SESSION_COOKIE_PATH,
                    domain=settings.SESSION_COOKIE_DOMAIN,
                    samesite=settings.SESSION_COOKIE_SAMESITE,
                )
            need_vary_cookie = True
        else:
            # If the session was accessed, it must be varied on, regardless of
            # whether it was modified or will be saved.
            need_vary_cookie = accessed
            if (modified or settings.SESSION_SAVE_EVERY_REQUEST) and not empty:
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time.time() + max_age
                    expires = http_date(expires_time)
                # Save the session data and refresh the client cookie.
                # Skip session save for 5xx responses.
                if response.status_code < 500:
                    try:
                        request.session.save()
                    except UpdateError:
                        raise SessionInterrupted(
                            "The request's session was deleted before the "
                            "request completed. The user may have logged "
                            "out in a concurrent request, for example."
                        )
                    if hasattr(request.session, "get_set_cookies"):
                        set_cookies = request.session.get_set_cookies()
                        stale_cookie_names = request.session.get_stale_cookie_names()
                    else:
                        set_cookies = {
                            settings.SESSION_COOKIE_NAME: (
                                request.session.session_key
                            ),
                        }
                        stale_cookie_names = ()
                    for cookie_name, cookie_value in set_cookies.items():
                        response.set_cookie(
                            cookie_name,
                            cookie_value,
                            max_age=max_age,
                            expires=expires,
                            domain=settings.SESSION_COOKIE_DOMAIN,
                            path=settings.SESSION_COOKIE_PATH,
                            secure=settings.SESSION_COOKIE_SECURE or None,
                            httponly=settings.SESSION_COOKIE_HTTPONLY or None,
                            samesite=settings.SESSION_COOKIE_SAMESITE,
                        )
                    # Remove cookies left over from a previous, larger
                    # session representation (e.g. old chunks).
                    for cookie_name in stale_cookie_names:
                        response.delete_cookie(
                            cookie_name,
                            path=settings.SESSION_COOKIE_PATH,
                            domain=settings.SESSION_COOKIE_DOMAIN,
                            samesite=settings.SESSION_COOKIE_SAMESITE,
                        )
                    # With a session cookie set, it must be varied on.
                    need_vary_cookie = True
        if need_vary_cookie:
            patch_vary_headers(response, ("Cookie",))
        return response
