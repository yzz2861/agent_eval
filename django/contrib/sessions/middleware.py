import time
from importlib import import_module

from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionDataTooLarge, SessionInterrupted
from django.core.exceptions import ImproperlyConfigured
from django.middleware import MiddlewareMixin
from django.utils.cache import patch_vary_headers
from django.utils.crypto import get_random_string
from django.utils.http import http_date


class ChunkedSessionCookie:
    """
    Split a session cookie that's too large for a single cookie across
    multiple chunk cookies, and reassemble it on the next request.

    Chunk cookies are named "<SESSION_COOKIE_NAME>.<index>". Each chunk value
    has the form "<nonce>.<index>.<count>.<payload>". The nonce is generated
    on every save so that chunks written by different responses cannot be
    combined into a valid session.
    """

    SEPARATOR = "."
    NONCE_LENGTH = 12

    @classmethod
    def cookie_name(cls, index):
        return "%s%s%d" % (settings.SESSION_COOKIE_NAME, cls.SEPARATOR, index)

    @classmethod
    def request_chunk_names(cls, cookies):
        """Return the names of the chunk cookies present in cookies."""
        prefix = settings.SESSION_COOKIE_NAME + cls.SEPARATOR
        return [
            name
            for name in cookies
            if name.startswith(prefix) and name[len(prefix) :].isdigit()
        ]

    @classmethod
    def split(cls, value):
        """
        Split value into a dict of chunk cookie names and values. Raise
        SessionDataTooLarge if value doesn't fit within the configured
        chunk count and size limits.
        """
        chunk_size = settings.SESSION_COOKIE_CHUNK_SIZE
        max_chunks = settings.SESSION_COOKIE_MAX_CHUNKS
        if chunk_size < 1 or max_chunks < 1:
            raise ImproperlyConfigured(
                "SESSION_COOKIE_CHUNK_SIZE and SESSION_COOKIE_MAX_CHUNKS must "
                "be positive integers."
            )
        chunks = [value[i : i + chunk_size] for i in range(0, len(value), chunk_size)]
        if len(chunks) > max_chunks:
            raise SessionDataTooLarge(
                "The session data doesn't fit in %d chunk cookies of %d "
                "bytes. Store less data in the session, or increase "
                "SESSION_COOKIE_CHUNK_SIZE or SESSION_COOKIE_MAX_CHUNKS."
                % (max_chunks, chunk_size)
            )
        nonce = get_random_string(cls.NONCE_LENGTH)
        count = len(chunks)
        return {
            cls.cookie_name(index): cls.SEPARATOR.join(
                (nonce, str(index), str(count), chunk)
            )
            for index, chunk in enumerate(chunks)
        }

    @classmethod
    def join(cls, cookies):
        """
        Reassemble a session cookie value from chunk cookies. Return None if
        no chunk cookies are present. Raise ValueError if the chunks are
        missing, duplicated, inconsistent, or malformed.
        """
        chunks = {}
        for name in cls.request_chunk_names(cookies):
            parts = cookies[name].split(cls.SEPARATOR, 3)
            if len(parts) != 4:
                raise ValueError("Malformed session cookie chunk.")
            nonce, index, count, payload = parts
            if not nonce or not index.isdigit() or not count.isdigit():
                raise ValueError("Malformed session cookie chunk.")
            index = int(index)
            count = int(count)
            if name != cls.cookie_name(index):
                raise ValueError("Session cookie chunk stored under the wrong name.")
            if not 1 <= count <= settings.SESSION_COOKIE_MAX_CHUNKS:
                raise ValueError("Invalid session cookie chunk count.")
            if index >= count:
                raise ValueError("Invalid session cookie chunk index.")
            chunks[index] = (nonce, count, payload)
        if not chunks:
            return None
        nonces = {nonce for nonce, _, _ in chunks.values()}
        counts = {count for _, count, _ in chunks.values()}
        if len(nonces) != 1 or len(counts) != 1:
            # Chunks were written by different responses.
            raise ValueError("Inconsistent session cookie chunks.")
        count = counts.pop()
        if set(chunks) != set(range(count)):
            raise ValueError("Missing session cookie chunks.")
        return "".join(chunks[index][2] for index in range(count))


class SessionMiddleware(MiddlewareMixin):
    async_capable = False

    def __init__(self, get_response):
        super().__init__(get_response)
        engine = import_module(settings.SESSION_ENGINE)
        self.SessionStore = engine.SessionStore

    def process_request(self, request):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        if session_key is None and settings.SESSION_COOKIE_CHUNKED:
            try:
                session_key = ChunkedSessionCookie.join(request.COOKIES)
            except ValueError:
                # Missing, duplicated, tampered, or otherwise inconsistent
                # chunks are treated as an invalid session.
                session_key = None
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
        # Chunk cookies sent with the request, if any. They may have to be
        # removed if the session shrinks or is emptied.
        chunk_cookie_names = (
            ChunkedSessionCookie.request_chunk_names(request.COOKIES)
            if settings.SESSION_COOKIE_CHUNKED
            else ()
        )
        # First check if we need to delete this cookie.
        # The session should be deleted only if the session is entirely empty.
        if (
            settings.SESSION_COOKIE_NAME in request.COOKIES or chunk_cookie_names
        ) and empty:
            response.delete_cookie(
                settings.SESSION_COOKIE_NAME,
                path=settings.SESSION_COOKIE_PATH,
                domain=settings.SESSION_COOKIE_DOMAIN,
                samesite=settings.SESSION_COOKIE_SAMESITE,
            )
            for cookie_name in chunk_cookie_names:
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
                    cookie = {
                        "max_age": max_age,
                        "expires": expires,
                        "domain": settings.SESSION_COOKIE_DOMAIN,
                        "path": settings.SESSION_COOKIE_PATH,
                        "secure": settings.SESSION_COOKIE_SECURE or None,
                        "httponly": settings.SESSION_COOKIE_HTTPONLY or None,
                        "samesite": settings.SESSION_COOKIE_SAMESITE,
                    }
                    deleted_cookie = {
                        "path": settings.SESSION_COOKIE_PATH,
                        "domain": settings.SESSION_COOKIE_DOMAIN,
                        "samesite": settings.SESSION_COOKIE_SAMESITE,
                    }
                    session_key = request.session.session_key
                    if (
                        settings.SESSION_COOKIE_CHUNKED
                        and len(session_key) > settings.SESSION_COOKIE_CHUNK_SIZE
                    ):
                        # The signed session doesn't fit in a single cookie.
                        # Split it across chunk cookies.
                        chunks = ChunkedSessionCookie.split(session_key)
                        # Remove the single cookie and the chunk cookies left
                        # over from a previous, larger session.
                        response.delete_cookie(
                            settings.SESSION_COOKIE_NAME, **deleted_cookie
                        )
                        for cookie_name in chunk_cookie_names:
                            if cookie_name not in chunks:
                                response.delete_cookie(cookie_name, **deleted_cookie)
                        for cookie_name, chunk in chunks.items():
                            response.set_cookie(cookie_name, chunk, **cookie)
                    else:
                        response.set_cookie(
                            settings.SESSION_COOKIE_NAME,
                            session_key,
                            **cookie,
                        )
                        # Remove chunk cookies left over from a previous,
                        # larger session.
                        for cookie_name in chunk_cookie_names:
                            response.delete_cookie(cookie_name, **deleted_cookie)
                    # With a session cookie set, it must be varied on.
                    need_vary_cookie = True
        if need_vary_cookie:
            patch_vary_headers(response, ("Cookie",))
        return response
