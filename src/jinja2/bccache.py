"""The optional bytecode cache system. This is useful if you have very
complex template situations and the compilation of all those templates
slows down your application too much.

Situations where this is useful are often forking web applications that
are initialized on the first request.
"""

import enum
import errno
import fnmatch
import hmac
import json
import marshal
import os
import pickle
import stat
import struct
import sys
import tempfile
import time
import typing as t
from datetime import timedelta
from hashlib import sha1
from hashlib import sha256
from io import BytesIO
from types import CodeType

if t.TYPE_CHECKING:
    import typing_extensions as te

    from .environment import Environment

    class _MemcachedClient(te.Protocol):
        def get(self, key: str) -> bytes: ...

        def set(self, key: str, value: bytes, timeout: int | None = None) -> None: ...


bc_version = 5
# Magic bytes to identify Jinja bytecode cache files. Contains the
# Python major and minor version to avoid loading incompatible bytecode
# if a project upgrades its Python version.
bc_magic = (
    b"j2"
    + pickle.dumps(bc_version, 2)
    + pickle.dumps((sys.version_info[0] << 24) | sys.version_info[1], 2)
)


class IntegrityCacheStatus(str, enum.Enum):
    """The outcome of an authenticated cache lookup.

    The status is stored on the bucket as ``integrity_status``.  It never
    contains the cached payload, which keeps failed loads safe to log.
    """

    HIT = "hit"
    MISS = "miss"
    MISSING_KEY = "missing_key"
    SIGNATURE_MISMATCH = "signature_mismatch"
    DOMAIN_MISMATCH = "domain_mismatch"
    TEMPLATE_MISMATCH = "template_mismatch"
    SOURCE_CHANGED = "source_changed"
    EXPIRED = "expired"
    LEGACY_FORMAT = "legacy_format"
    INVALID_FORMAT = "invalid_format"
    MALFORMED = "malformed"
    DESERIALIZATION_FAILED = "deserialization_failed"

    def __str__(self) -> str:
        return self.value


class Bucket:
    """Buckets are used to store the bytecode for one template.  It's created
    and initialized by the bytecode cache and passed to the loading functions.

    The buckets get an internal checksum from the cache assigned and use this
    to automatically reject outdated cache material.  Individual bytecode
    cache subclasses don't have to care about cache invalidation.
    """

    template_name: str | None = None
    template_filename: str | None = None
    integrity_status: IntegrityCacheStatus | None = None
    integrity_error: str | None = None
    integrity_write_skipped: bool = False

    def __init__(self, environment: "Environment", key: str, checksum: str) -> None:
        self.environment = environment
        self.key = key
        self.checksum = checksum
        self.reset()

    def reset(self) -> None:
        """Resets the bucket (unloads the bytecode)."""
        self.code: CodeType | None = None

    def load_bytecode(self, f: t.BinaryIO) -> None:
        """Loads bytecode from a file or file like object."""
        # make sure the magic header is correct
        magic = f.read(len(bc_magic))
        if magic != bc_magic:
            self.reset()
            return
        # the source code of the file changed, we need to reload
        checksum = pickle.load(f)
        if self.checksum != checksum:
            self.reset()
            return
        # if marshal_load fails then we need to reload
        try:
            self.code = marshal.load(f)
        except (EOFError, ValueError, TypeError):
            self.reset()
            return

    def write_bytecode(self, f: t.IO[bytes]) -> None:
        """Dump the bytecode into the file or file like object passed."""
        if self.code is None:
            raise TypeError("can't write empty bucket")
        f.write(bc_magic)
        pickle.dump(self.checksum, f, 2)
        marshal.dump(self.code, f)

    def bytecode_from_string(self, string: bytes) -> None:
        """Load bytecode from bytes."""
        self.load_bytecode(BytesIO(string))

    def bytecode_to_string(self) -> bytes:
        """Return the bytecode as bytes."""
        out = BytesIO()
        self.write_bytecode(out)
        return out.getvalue()


class BytecodeCache:
    """To implement your own bytecode cache you have to subclass this class
    and override :meth:`load_bytecode` and :meth:`dump_bytecode`.  Both of
    these methods are passed a :class:`~jinja2.bccache.Bucket`.

    A very basic bytecode cache that saves the bytecode on the file system::

        from os import path

        class MyCache(BytecodeCache):

            def __init__(self, directory):
                self.directory = directory

            def load_bytecode(self, bucket):
                filename = path.join(self.directory, bucket.key)
                if path.exists(filename):
                    with open(filename, 'rb') as f:
                        bucket.load_bytecode(f)

            def dump_bytecode(self, bucket):
                filename = path.join(self.directory, bucket.key)
                with open(filename, 'wb') as f:
                    bucket.write_bytecode(f)

    A more advanced version of a filesystem based bytecode cache is part of
    Jinja.
    """

    def load_bytecode(self, bucket: Bucket) -> None:
        """Subclasses have to override this method to load bytecode into a
        bucket.  If they are not able to find code in the cache for the
        bucket, it must not do anything.
        """
        raise NotImplementedError()

    def dump_bytecode(self, bucket: Bucket) -> None:
        """Subclasses have to override this method to write the bytecode
        from a bucket back to the cache.  If it unable to do so it must not
        fail silently but raise an exception.
        """
        raise NotImplementedError()

    def clear(self) -> None:
        """Clears the cache.  This method is not used by Jinja but should be
        implemented to allow applications to clear the bytecode cache used
        by a particular environment.
        """

    def get_cache_key(self, name: str, filename: str | None = None) -> str:
        """Returns the unique hash key for this template name."""
        hash = sha1(name.encode("utf-8"))

        if filename is not None:
            hash.update(f"|{filename}".encode())

        return hash.hexdigest()

    def get_source_checksum(self, source: str) -> str:
        """Returns a checksum for the source."""
        return sha1(source.encode("utf-8")).hexdigest()

    def get_bucket(
        self,
        environment: "Environment",
        name: str,
        filename: str | None,
        source: str,
    ) -> Bucket:
        """Return a cache bucket for the given template.  All arguments are
        mandatory but filename may be `None`.
        """
        key = self.get_cache_key(name, filename)
        checksum = self.get_source_checksum(source)
        bucket = Bucket(environment, key, checksum)
        self.load_bytecode(bucket)
        return bucket

    def set_bucket(self, bucket: Bucket) -> None:
        """Put the bucket into the cache."""
        self.dump_bytecode(bucket)


class FileSystemBytecodeCache(BytecodeCache):
    """A bytecode cache that stores bytecode on the filesystem.  It accepts
    two arguments: The directory where the cache items are stored and a
    pattern string that is used to build the filename.

    If no directory is specified a default cache directory is selected.  On
    Windows the user's temp directory is used, on UNIX systems a directory
    is created for the user in the system temp directory.

    The pattern can be used to have multiple separate caches operate on the
    same directory.  The default pattern is ``'__jinja2_%s.cache'``.  ``%s``
    is replaced with the cache key.

    >>> bcc = FileSystemBytecodeCache('/tmp/jinja_cache', '%s.cache')

    This bytecode cache supports clearing of the cache using the clear method.
    """

    def __init__(
        self, directory: str | None = None, pattern: str = "__jinja2_%s.cache"
    ) -> None:
        if directory is None:
            directory = self._get_default_cache_dir()
        self.directory = directory
        self.pattern = pattern

    def _get_default_cache_dir(self) -> str:
        def _unsafe_dir() -> "te.NoReturn":
            raise RuntimeError(
                "Cannot determine safe temp directory.  You "
                "need to explicitly provide one."
            )

        tmpdir = tempfile.gettempdir()

        # On windows the temporary directory is used specific unless
        # explicitly forced otherwise.  We can just use that.
        if os.name == "nt":
            return tmpdir
        if not hasattr(os, "getuid"):
            _unsafe_dir()

        dirname = f"_jinja2-cache-{os.getuid()}"
        actual_dir = os.path.join(tmpdir, dirname)

        try:
            os.mkdir(actual_dir, stat.S_IRWXU)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        try:
            os.chmod(actual_dir, stat.S_IRWXU)
            actual_dir_stat = os.lstat(actual_dir)
            if (
                actual_dir_stat.st_uid != os.getuid()
                or not stat.S_ISDIR(actual_dir_stat.st_mode)
                or stat.S_IMODE(actual_dir_stat.st_mode) != stat.S_IRWXU
            ):
                _unsafe_dir()
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        actual_dir_stat = os.lstat(actual_dir)
        if (
            actual_dir_stat.st_uid != os.getuid()
            or not stat.S_ISDIR(actual_dir_stat.st_mode)
            or stat.S_IMODE(actual_dir_stat.st_mode) != stat.S_IRWXU
        ):
            _unsafe_dir()

        return actual_dir

    def _get_cache_filename(self, bucket: Bucket) -> str:
        return os.path.join(self.directory, self.pattern % (bucket.key,))

    def load_bytecode(self, bucket: Bucket) -> None:
        filename = self._get_cache_filename(bucket)

        # Don't test for existence before opening the file, since the
        # file could disappear after the test before the open.
        try:
            f = open(filename, "rb")
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            # PermissionError can occur on Windows when an operation is
            # in progress, such as calling clear().
            return

        with f:
            bucket.load_bytecode(f)

    def dump_bytecode(self, bucket: Bucket) -> None:
        # Write to a temporary file, then rename to the real name after
        # writing. This avoids another process reading the file before
        # it is fully written.
        name = self._get_cache_filename(bucket)
        f = tempfile.NamedTemporaryFile(
            mode="wb",
            dir=os.path.dirname(name),
            prefix=os.path.basename(name),
            suffix=".tmp",
            delete=False,
        )

        def remove_silent() -> None:
            try:
                os.remove(f.name)
            except OSError:
                # Another process may have called clear(). On Windows,
                # another program may be holding the file open.
                pass

        try:
            with f:
                bucket.write_bytecode(f)
        except BaseException:
            remove_silent()
            raise

        try:
            os.replace(f.name, name)
        except OSError:
            # Another process may have called clear(). On Windows,
            # another program may be holding the file open.
            remove_silent()
        except BaseException:
            remove_silent()
            raise

    def clear(self) -> None:
        # imported lazily here because google app-engine doesn't support
        # write access on the file system and the function does not exist
        # normally.
        from os import remove

        files = fnmatch.filter(os.listdir(self.directory), self.pattern % ("*",))
        for filename in files:
            try:
                remove(os.path.join(self.directory, filename))
            except OSError:
                pass


class MemcachedBytecodeCache(BytecodeCache):
    """This class implements a bytecode cache that uses a memcache cache for
    storing the information.  It does not enforce a specific memcache library
    (tummy's memcache or cmemcache) but will accept any class that provides
    the minimal interface required.

    Libraries compatible with this class:

    -   `cachelib <https://github.com/pallets/cachelib>`_
    -   `python-memcached <https://pypi.org/project/python-memcached/>`_

    (Unfortunately the django cache interface is not compatible because it
    does not support storing binary data, only text. You can however pass
    the underlying cache client to the bytecode cache which is available
    as `django.core.cache.cache._client`.)

    The minimal interface for the client passed to the constructor is this:

    .. class:: MinimalClientInterface

        .. method:: set(key, value[, timeout])

            Stores the bytecode in the cache.  `value` is a string and
            `timeout` the timeout of the key.  If timeout is not provided
            a default timeout or no timeout should be assumed, if it's
            provided it's an integer with the number of seconds the cache
            item should exist.

        .. method:: get(key)

            Returns the value for the cache key.  If the item does not
            exist in the cache the return value must be `None`.

    The other arguments to the constructor are the prefix for all keys that
    is added before the actual cache key and the timeout for the bytecode in
    the cache system.  We recommend a high (or no) timeout.

    This bytecode cache does not support clearing of used items in the cache.
    The clear method is a no-operation function.

    .. versionadded:: 2.7
       Added support for ignoring memcache errors through the
       `ignore_memcache_errors` parameter.
    """

    def __init__(
        self,
        client: "_MemcachedClient",
        prefix: str = "jinja2/bytecode/",
        timeout: int | None = None,
        ignore_memcache_errors: bool = True,
    ):
        self.client = client
        self.prefix = prefix
        self.timeout = timeout
        self.ignore_memcache_errors = ignore_memcache_errors

    def load_bytecode(self, bucket: Bucket) -> None:
        try:
            code = self.client.get(self.prefix + bucket.key)
        except Exception:
            if not self.ignore_memcache_errors:
                raise
        else:
            bucket.bytecode_from_string(code)

    def dump_bytecode(self, bucket: Bucket) -> None:
        key = self.prefix + bucket.key
        value = bucket.bytecode_to_string()

        try:
            if self.timeout is not None:
                self.client.set(key, value, self.timeout)
            else:
                self.client.set(key, value)
        except Exception:
            if not self.ignore_memcache_errors:
                raise


class IntegrityBytecodeCache(FileSystemBytecodeCache):
    """An opt-in filesystem bytecode cache with authenticated envelopes.

    Cache files are not trusted merely because they exist. Each entry is
    wrapped in an envelope that binds the cache domain (the environment's
    namespace), template name, source checksum, format version, expiration
    time, and the complete bytecode payload using HMAC-SHA256. The payload
    is only handed to Jinja's normal bytecode deserializer after the
    envelope has been verified.

    Verification failures never raise from :meth:`load_bytecode`. They reset
    the bucket, record a safe :class:`IntegrityCacheStatus` on
    ``bucket.integrity_status``, and let the loader compile from source.
    By default an invalid entry is not overwritten by that fallback; set
    ``rewrite_on_failure=True`` to explicitly allow replacing it.

    Key rotation is supported with ``old_keys``. Old keys are accepted for
    reads, while only the active ``key`` is used for writes. The number of
    retained old keys is bounded by ``max_old_keys``.

    Args:
        directory: Directory for cache files, as for
            :class:`FileSystemBytecodeCache`.
        pattern: Filename pattern, as for
            :class:`FileSystemBytecodeCache`.
        key: Active HMAC key. A string is encoded as UTF-8.
        key_id: Identifier stored in new envelopes. Defaults to a SHA-256
            fingerprint of ``key``. It is not the key itself.
        old_keys: Additional keys accepted for reads. This may be a mapping
            of key IDs to secrets, or an iterable of secrets (whose IDs are
            their fingerprints).
        max_old_keys: Maximum number of old keys retained. Passing more
            raises ``ValueError``.
        namespace: Fallback cache domain when the environment does not
            define one. The environment's ``cache_namespace`` (or
            ``namespace`` when present) takes precedence.
        cache_domain: Alias for ``namespace``.
        ttl: Expiration for newly written envelopes, in seconds or as a
            ``timedelta``. ``None`` disables expiration.
        clock: Callable returning the current time, for testing.
        rewrite_on_failure: If true, a source-compilation fallback may
            replace an entry that failed verification.
    """

    format_version = 1
    _magic = b"JINJA2-INTEGRITY-CACHE:1\n"
    _mac_size = 32
    _max_header_size = 64 * 1024

    _no_rewrite_statuses = frozenset(
        {
            IntegrityCacheStatus.MISSING_KEY,
            IntegrityCacheStatus.SIGNATURE_MISMATCH,
            IntegrityCacheStatus.DOMAIN_MISMATCH,
            IntegrityCacheStatus.TEMPLATE_MISMATCH,
            IntegrityCacheStatus.LEGACY_FORMAT,
            IntegrityCacheStatus.INVALID_FORMAT,
            IntegrityCacheStatus.MALFORMED,
            IntegrityCacheStatus.DESERIALIZATION_FAILED,
        }
    )

    def __init__(
        self,
        directory: str | None = None,
        pattern: str = "__jinja2_%s.cache",
        *,
        key: bytes | str | None = None,
        key_id: str | None = None,
        old_keys: t.Mapping[str, bytes | str] | t.Iterable[bytes | str] = (),
        max_old_keys: int = 2,
        namespace: str | None = None,
        cache_domain: str | None = None,
        ttl: float | int | timedelta | None = None,
        clock: t.Callable[[], float] = time.time,
        rewrite_on_failure: bool = False,
    ) -> None:
        super().__init__(directory, pattern)

        if namespace is not None and cache_domain is not None:
            if namespace != cache_domain:
                raise ValueError("namespace and cache_domain must match")

        if not isinstance(max_old_keys, int) or isinstance(max_old_keys, bool):
            raise TypeError("max_old_keys must be an integer")

        if max_old_keys < 0:
            raise ValueError("max_old_keys must not be negative")

        self.namespace = namespace if namespace is not None else cache_domain
        self.rewrite_on_failure = rewrite_on_failure
        self._clock = clock
        self._ttl = self._normalize_ttl(ttl)
        self._active_key: bytes | None = None
        self._active_key_id: str | None = None
        self._keys: dict[str, bytes] = {}
        self._old_key_ids: tuple[str, ...] = ()

        if key is None:
            if old_keys:
                raise ValueError("old_keys requires an active key")
            return

        active_secret = self._key_bytes(key, "key")
        active_id = (
            key_id if key_id is not None else self._key_fingerprint(active_secret)
        )

        if not active_id:
            raise ValueError("key_id must not be empty")

        old = self._normalize_old_keys(old_keys)

        if active_id in old and old[active_id] != active_secret:
            raise ValueError("key_id conflicts with an old key")

        old.pop(active_id, None)

        if len(old) > max_old_keys:
            raise ValueError(
                "too many old keys retained: "
                f"{len(old)} > max_old_keys={max_old_keys}"
            )

        self._active_key = active_secret
        self._active_key_id = active_id
        self._old_key_ids = tuple(old)
        self._keys = {active_id: active_secret, **old}

    @property
    def key_id(self) -> str | None:
        """The ID written into new envelopes, or ``None`` if keyless."""
        return self._active_key_id

    @property
    def old_key_ids(self) -> tuple[str, ...]:
        """IDs of old keys accepted for reads."""
        return self._old_key_ids

    @staticmethod
    def _key_bytes(value: bytes | str, label: str) -> bytes:
        if isinstance(value, str):
            value = value.encode("utf-8")

        if not isinstance(value, bytes):
            raise TypeError(f"{label} must be bytes or str")

        if not value:
            raise ValueError(f"{label} must not be empty")

        return value

    @staticmethod
    def _key_fingerprint(value: bytes) -> str:
        return sha256(value).hexdigest()

    @classmethod
    def _normalize_old_keys(
        cls, old_keys: t.Mapping[str, bytes | str] | t.Iterable[bytes | str]
    ) -> dict[str, bytes]:
        result: dict[str, bytes] = {}

        if isinstance(old_keys, bytes):
            raise TypeError("old_keys must be a mapping or an iterable of secrets")

        if isinstance(old_keys, t.Mapping):
            items: t.Iterable[tuple[str | None, bytes | str]] = old_keys.items()
        else:
            items = ((None, value) for value in old_keys)

        for key_id, value in items:
            secret = cls._key_bytes(value, "old key")
            actual_id = key_id if key_id is not None else cls._key_fingerprint(secret)

            if not isinstance(actual_id, str) or not actual_id:
                raise ValueError("old key IDs must be non-empty strings")

            if actual_id in result and result[actual_id] != secret:
                raise ValueError("duplicate old key ID with a different secret")

            result[actual_id] = secret

        return result

    @staticmethod
    def _normalize_ttl(ttl: float | int | timedelta | None) -> float | None:
        if ttl is None:
            return None

        if isinstance(ttl, timedelta):
            return ttl.total_seconds()

        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
            raise TypeError("ttl must be a number, timedelta, or None")

        return float(ttl)

    def get_bucket(
        self,
        environment: "Environment",
        name: str,
        filename: str | None,
        source: str,
    ) -> Bucket:
        key = self.get_cache_key(name, filename)
        checksum = self.get_source_checksum(source)
        bucket = Bucket(environment, key, checksum)
        bucket.template_name = name
        bucket.template_filename = filename
        self.load_bytecode(bucket)
        return bucket

    def _environment_domain(self, environment: t.Optional["Environment"]) -> str | None:
        if environment is None:
            return None

        for attribute in (
            "cache_namespace",
            "namespace",
            "cache_domain",
            "environment_namespace",
        ):
            value = getattr(environment, attribute, None)

            if value is not None:
                return str(value)

        return None

    def _domain(self, environment: t.Optional["Environment"]) -> str:
        domain = self._environment_domain(environment)

        if domain is not None:
            return domain

        if self.namespace is not None:
            return self.namespace

        return ""

    @staticmethod
    def _template_name(bucket: Bucket) -> str:
        name = getattr(bucket, "template_name", None)
        return name if isinstance(name, str) else bucket.key

    @staticmethod
    def _fail(bucket: Bucket, status: IntegrityCacheStatus) -> None:
        bucket.reset()
        bucket.integrity_status = status
        bucket.integrity_error = status.value

    def _now(self) -> float:
        return float(self._clock())

    def _mac(self, key: bytes, signed: bytes) -> bytes:
        return hmac.new(key, signed, sha256).digest()

    def _read_envelope(
        self, data: bytes, bucket: Bucket
    ) -> tuple[IntegrityCacheStatus, dict[str, t.Any] | None, bytes | None]:
        if not data:
            return IntegrityCacheStatus.MALFORMED, None, None

        if not data.startswith(self._magic):
            if data.startswith(bc_magic):
                return IntegrityCacheStatus.LEGACY_FORMAT, None, None

            return IntegrityCacheStatus.INVALID_FORMAT, None, None

        prefix_size = len(self._magic)

        if len(data) < prefix_size + 4:
            return IntegrityCacheStatus.MALFORMED, None, None

        (header_size,) = struct.unpack(">I", data[prefix_size : prefix_size + 4])
        header_start = prefix_size + 4
        header_end = header_start + header_size
        mac_end = header_end + self._mac_size

        if header_size == 0 or header_size > self._max_header_size:
            return IntegrityCacheStatus.MALFORMED, None, None

        if mac_end > len(data):
            return IntegrityCacheStatus.MALFORMED, None, None

        header_raw = data[header_start:header_end]

        try:
            header = json.loads(header_raw)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return IntegrityCacheStatus.MALFORMED, None, None

        if not isinstance(header, dict):
            return IntegrityCacheStatus.MALFORMED, None, None

        version = header.get("format_version")

        if version != self.format_version:
            if isinstance(version, int) and version < self.format_version:
                return IntegrityCacheStatus.LEGACY_FORMAT, None, None

            return IntegrityCacheStatus.INVALID_FORMAT, None, None

        key_id = header.get("key_id")

        if not isinstance(key_id, str) or not key_id:
            return IntegrityCacheStatus.MALFORMED, None, None

        key = self._keys.get(key_id)

        if key is None:
            return IntegrityCacheStatus.MISSING_KEY, None, None

        signed = data[:header_end] + data[mac_end:]
        expected = self._mac(key, signed)
        actual = data[header_end:mac_end]

        if not hmac.compare_digest(actual, expected):
            return IntegrityCacheStatus.SIGNATURE_MISMATCH, None, None

        domain = header.get("cache_domain")
        template = header.get("template_name")
        checksum = header.get("source_checksum")

        if not all(isinstance(value, str) for value in (domain, template, checksum)):
            return IntegrityCacheStatus.MALFORMED, None, None

        if domain != self._domain(bucket.environment):
            return IntegrityCacheStatus.DOMAIN_MISMATCH, None, None

        if template != self._template_name(bucket):
            return IntegrityCacheStatus.TEMPLATE_MISMATCH, None, None

        if header.get("bytecode_version") != bc_version:
            return IntegrityCacheStatus.INVALID_FORMAT, None, None

        python = f"{sys.version_info[0]}.{sys.version_info[1]}"

        if header.get("python_version") != python:
            return IntegrityCacheStatus.INVALID_FORMAT, None, None

        if checksum != bucket.checksum:
            return IntegrityCacheStatus.SOURCE_CHANGED, None, None

        expires_at = header.get("expires_at")

        if expires_at is not None:
            if isinstance(expires_at, bool) or not isinstance(
                expires_at, (int, float)
            ):
                return IntegrityCacheStatus.MALFORMED, None, None

            if self._now() >= expires_at:
                return IntegrityCacheStatus.EXPIRED, None, None

        return IntegrityCacheStatus.HIT, header, data[mac_end:]

    def load_bytecode(self, bucket: Bucket) -> None:
        filename = self._get_cache_filename(bucket)

        try:
            f = open(filename, "rb")
        except OSError:
            self._fail(bucket, IntegrityCacheStatus.MISS)
            return

        try:
            with f:
                data = f.read()
        except OSError:
            self._fail(bucket, IntegrityCacheStatus.MISS)
            return

        status, _header, payload = self._read_envelope(data, bucket)

        if status is not IntegrityCacheStatus.HIT or payload is None:
            self._fail(bucket, status)
            return

        envelope = BytesIO()
        envelope.write(bc_magic)
        envelope.write(pickle.dumps(bucket.checksum, 2))
        envelope.write(payload)
        envelope.seek(0)
        bucket.load_bytecode(envelope)

        if bucket.code is None:
            self._fail(bucket, IntegrityCacheStatus.DESERIALIZATION_FAILED)
            return

        bucket.integrity_status = IntegrityCacheStatus.HIT
        bucket.integrity_error = None

    def _build_envelope(self, bucket: Bucket) -> bytes:
        if self._active_key is None or self._active_key_id is None:
            raise ValueError("an active key is required to write cache entries")

        if bucket.code is None:
            raise TypeError("can't write empty bucket")

        now = self._now()
        expires_at = None if self._ttl is None else now + self._ttl
        header = {
            "format_version": self.format_version,
            "bytecode_version": bc_version,
            "python_version": f"{sys.version_info[0]}.{sys.version_info[1]}",
            "cache_domain": self._domain(bucket.environment),
            "template_name": self._template_name(bucket),
            "source_checksum": bucket.checksum,
            "expires_at": expires_at,
            "created_at": now,
            "key_id": self._active_key_id,
        }
        header_raw = json.dumps(
            header, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        payload = marshal.dumps(bucket.code)
        prefix = self._magic + struct.pack(">I", len(header_raw)) + header_raw
        mac = self._mac(self._active_key, prefix + payload)
        return prefix + mac + payload

    def _write_atomic(self, name: str, data: bytes) -> None:
        f = tempfile.NamedTemporaryFile(
            mode="wb",
            dir=os.path.dirname(name),
            prefix=os.path.basename(name),
            suffix=".tmp",
            delete=False,
        )

        def remove_silent() -> None:
            try:
                os.remove(f.name)
            except OSError:
                pass

        try:
            with f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())

            os.replace(f.name, name)
        except BaseException:
            remove_silent()
            raise

    def dump_bytecode(self, bucket: Bucket) -> None:
        if bucket.code is None:
            raise TypeError("can't write empty bucket")

        bucket.integrity_write_skipped = False

        if self._active_key is None:
            self._fail(bucket, IntegrityCacheStatus.MISSING_KEY)
            bucket.integrity_write_skipped = True
            return

        status = getattr(bucket, "integrity_status", None)

        if not self.rewrite_on_failure and status in self._no_rewrite_statuses:
            bucket.integrity_write_skipped = True
            return

        name = self._get_cache_filename(bucket)
        data = self._build_envelope(bucket)
        self._write_atomic(name, data)
