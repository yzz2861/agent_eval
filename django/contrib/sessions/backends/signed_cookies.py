import hashlib

from django.conf import settings
from django.contrib.sessions.backends.base import SessionBase
from django.contrib.sessions.exceptions import SessionDataTooLarge
from django.core import signing
from django.core.exceptions import ImproperlyConfigured


class SessionStore(SessionBase):
    # Prefix marking the main cookie value as a manifest describing how the
    # signed session data is split across chunk cookies. A signed session
    # key never starts with this prefix (it's URL-safe base64, optionally
    # prefixed with "." when compressed), so the formats can't collide.
    manifest_prefix = "chunked"

    def __init__(self, session_key=None):
        super().__init__(session_key)
        # Chunk cookie names and values sent by the client, keyed by name.
        self._chunk_cookies = {}
        # Names of all session cookies sent by the client, so that stale
        # ones can be deleted from the client when saving or deleting.
        self._request_cookie_names = set()
        if session_key:
            self._request_cookie_names.add(settings.SESSION_COOKIE_NAME)

    @classmethod
    def from_cookies(cls, cookies):
        """
        Build a session store from the request's full cookie dict, so that
        chunked session data can be reassembled and stale chunk cookies can
        be tracked for deletion.
        """
        store = cls(cookies.get(settings.SESSION_COOKIE_NAME))
        prefix = settings.SESSION_COOKIE_NAME + "."
        for name, value in cookies.items():
            if name.startswith(prefix) and name[len(prefix) :].isdigit():
                store._chunk_cookies[name] = value
                store._request_cookie_names.add(name)
        return store

    @staticmethod
    def _chunk_cookie_name(index):
        return "%s.%d" % (settings.SESSION_COOKIE_NAME, index)

    def _reassemble_session_key(self):
        """
        Return the signed session key. If the main cookie holds a chunk
        manifest, reassemble the key from the chunk cookies, checking that
        all chunks are present and consistent with the manifest. Return None
        if the chunks are missing, duplicated, tampered with, or mixed from
        different responses.
        """
        session_key = self.session_key
        if not session_key:
            return session_key
        prefix = self.manifest_prefix + ":"
        if not session_key.startswith(prefix):
            # A regular, unchunked signed session key.
            return session_key
        parts = session_key.split(":")
        # A manifest is "chunked:<chunk count>:<sha256 hex digest>".
        if len(parts) != 3:
            return None
        try:
            chunk_count = int(parts[1])
        except ValueError:
            return None
        digest = parts[2]
        if chunk_count < 2 or chunk_count > settings.SESSION_COOKIE_MAX_CHUNKS:
            return None
        chunks = []
        for index in range(chunk_count):
            chunk = self._chunk_cookies.get(self._chunk_cookie_name(index))
            if chunk is None:
                return None
            chunks.append(chunk)
        session_key = "".join(chunks)
        if hashlib.sha256(session_key.encode("ascii")).hexdigest() != digest:
            return None
        return session_key

    def load(self):
        """
        Load the data from the key itself instead of fetching from some
        external data store. Opposite of _get_session_key(), raise BadSignature
        if signature fails.
        """
        try:
            session_key = self._reassemble_session_key()
            if session_key is None:
                raise signing.BadSignature(
                    "The session cookie chunks are missing or inconsistent."
                )
            self._session_key = session_key
            return signing.loads(
                session_key,
                serializer=self.serializer,
                # This doesn't handle non-default expiry dates, see #19201
                max_age=self.get_session_cookie_age(),
                salt="django.contrib.sessions.backends.signed_cookies",
            )
        except Exception:
            # BadSignature, ValueError, or unpickling exceptions. If any of
            # these happen, reset the session.
            self.create()
        return {}

    async def aload(self):
        return self.load()

    def get_set_cookies(self):
        """
        Return a dict of cookie names and values representing the current
        session. When chunking is enabled and the signed session key doesn't
        fit in a single cookie, split it across chunk cookies, with the main
        cookie holding a manifest binding the chunks together.
        """
        session_key = self.session_key or ""
        chunk_size = settings.SESSION_COOKIE_CHUNK_SIZE
        if not settings.SESSION_COOKIE_CHUNKED or len(session_key) <= chunk_size:
            return {settings.SESSION_COOKIE_NAME: session_key}
        max_chunks = settings.SESSION_COOKIE_MAX_CHUNKS
        if chunk_size < 1 or max_chunks < 1:
            raise ImproperlyConfigured(
                "SESSION_COOKIE_CHUNK_SIZE and SESSION_COOKIE_MAX_CHUNKS "
                "must be positive integers."
            )
        chunks = [
            session_key[index : index + chunk_size]
            for index in range(0, len(session_key), chunk_size)
        ]
        if len(chunks) > max_chunks:
            raise SessionDataTooLarge(
                "The signed session data is %d bytes, which exceeds the "
                "session cookie budget of %d bytes (%d chunks of at most %d "
                "bytes). Store less data in the session, or increase "
                "SESSION_COOKIE_CHUNK_SIZE or SESSION_COOKIE_MAX_CHUNKS."
                % (
                    len(session_key),
                    chunk_size * max_chunks,
                    max_chunks,
                    chunk_size,
                )
            )
        digest = hashlib.sha256(session_key.encode("ascii")).hexdigest()
        cookies = {
            settings.SESSION_COOKIE_NAME: "%s:%d:%s"
            % (self.manifest_prefix, len(chunks), digest),
        }
        for index, chunk in enumerate(chunks):
            cookies[self._chunk_cookie_name(index)] = chunk
        return cookies

    def get_stale_cookie_names(self):
        """
        Return the names of session cookies sent by the client that aren't
        part of the current session representation and must be deleted from
        the client (e.g. leftover chunks after the session shrank, or after
        chunking was disabled).
        """
        return sorted(self._request_cookie_names - set(self.get_set_cookies()))

    def get_delete_cookie_names(self):
        """
        Return the names of all session cookies sent by the client, so they
        can all be deleted when the session is emptied or flushed.
        """
        return sorted(self._request_cookie_names)

    def create(self):
        """
        To create a new key, set the modified flag so that the cookie is set
        on the client for the current request.
        """
        self.modified = True

    async def acreate(self):
        return self.create()

    def save(self, must_create=False):
        """
        To save, get the session key as a securely signed string and then set
        the modified flag so that the cookie is set on the client for the
        current request.
        """
        self._session_key = self._get_session_key()
        self.modified = True

    async def asave(self, must_create=False):
        return self.save(must_create=must_create)

    def exists(self, session_key=None):
        """
        This method makes sense when you're talking to a shared resource, but
        it doesn't matter when you're storing the information in the client's
        cookie.
        """
        return False

    async def aexists(self, session_key=None):
        return self.exists(session_key=session_key)

    def delete(self, session_key=None):
        """
        To delete, clear the session key and the underlying data structure
        and set the modified flag so that the cookie is set on the client for
        the current request.
        """
        self._session_key = ""
        self._session_cache = {}
        self.modified = True

    async def adelete(self, session_key=None):
        return self.delete(session_key=session_key)

    def cycle_key(self):
        """
        Keep the same data but with a new key. Call save() and it will
        automatically save a cookie with a new key at the end of the request.
        """
        self.save()

    async def acycle_key(self):
        return self.cycle_key()

    def _get_session_key(self):
        """
        Instead of generating a random string, generate a secure url-safe
        base64-encoded string of data as our session key.
        """
        return signing.dumps(
            self._session,
            compress=True,
            salt="django.contrib.sessions.backends.signed_cookies",
            serializer=self.serializer,
        )

    @classmethod
    def clear_expired(cls):
        pass

    @classmethod
    async def aclear_expired(cls):
        pass
