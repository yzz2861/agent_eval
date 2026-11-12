from __future__ import annotations

import hashlib
import logging
import os
import shutil
import sys
import tempfile
from enum import IntEnum, global_enum
from io import BufferedRandom, BytesIO
from numbers import Number
from typing import TYPE_CHECKING, cast

from .decoders import Base64Decoder, QuotedPrintableDecoder
from .exceptions import FileError, FormParserError, MultipartParseError, QuerystringParseError

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any, Literal, Protocol, TypeAlias, TypedDict

    class SupportsRead(Protocol):
        def read(self, __n: int) -> bytes: ...

    class QuerystringCallbacks(TypedDict, total=False):
        on_field_start: Callable[[], None]
        on_field_name: Callable[[bytes, int, int], None]
        on_field_data: Callable[[bytes, int, int], None]
        on_field_end: Callable[[], None]
        on_end: Callable[[], None]

    class OctetStreamCallbacks(TypedDict, total=False):
        on_start: Callable[[], None]
        on_data: Callable[[bytes, int, int], None]
        on_end: Callable[[], None]

    class MultipartCallbacks(TypedDict, total=False):
        on_part_begin: Callable[[], None]
        on_part_data: Callable[[bytes, int, int], None]
        on_part_end: Callable[[], None]
        on_header_begin: Callable[[], None]
        on_header_field: Callable[[bytes, int, int], None]
        on_header_value: Callable[[bytes, int, int], None]
        on_header_end: Callable[[], None]
        on_headers_finished: Callable[[], None]
        on_end: Callable[[], None]

    class FileConfig(TypedDict, total=False):
        UPLOAD_DIR: str | bytes | None
        UPLOAD_TMP_DIR: str | bytes | None
        UPLOAD_TEMP_DIR: str | bytes | None
        TEMP_DIR: str | bytes | None
        TMP_DIR: str | bytes | None
        UPLOAD_DELETE_TMP: bool
        UPLOAD_KEEP_FILENAME: bool
        UPLOAD_KEEP_EXTENSIONS: bool
        UPLOAD_REDACT_FILENAMES: bool | str
        UPLOAD_REDACT_FILENAME: bool | str
        UPLOAD_FILENAME_REDACTION: bool | str
        UPLOAD_LOG_FILENAME_POLICY: bool | str
        UPLOAD_FILENAME_POLICY: bool | str
        MAX_MEMORY_FILE_SIZE: int
        MAX_FILE_SIZE: int | float
        MAX_FILE_BYTES: int | float
        MAX_UPLOAD_FILE_SIZE: int | float
        MAX_TOTAL_FILE_SIZE: int | float
        MAX_TOTAL_UPLOAD_SIZE: int | float
        MAX_DISK_BUDGET: int | float
        MAX_DISK_SIZE: int | float
        MAX_DISK_QUOTA: int | float
        MAX_TOTAL_DISK_SIZE: int | float

    class FormParserConfig(FileConfig):
        UPLOAD_ERROR_ON_BAD_CTE: bool
        MAX_BODY_SIZE: float
        MAX_FIELDS: int | float
        MAX_FIELD_SIZE: int | float
        MAX_HEADER_COUNT: int
        MAX_HEADER_SIZE: int

    CallbackName: TypeAlias = Literal[
        "start",
        "data",
        "end",
        "field_start",
        "field_name",
        "field_data",
        "field_end",
        "part_begin",
        "part_data",
        "part_end",
        "header_begin",
        "header_field",
        "header_value",
        "header_end",
        "headers_finished",
    ]

# Unique missing object.
_missing = object()


def _config_limit(config: dict[Any, Any], *names: str, default: int | float = float("inf")) -> int | float:
    """Return the first configured byte limit, validating it as non-negative."""
    for name in names:
        value = config.get(name)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, Number) or value < 0:
            raise ValueError(f"{name} must be a non-negative number")
        return value
    return default


class _DiskBudget:
    """A shared, logical byte budget for files written to disk by one parser."""

    def __init__(self, limit: int | float = float("inf")) -> None:
        if isinstance(limit, bool) or not isinstance(limit, Number) or limit < 0:
            raise ValueError("disk budget must be a non-negative number")
        self.limit = limit
        self.used: int | float = 0

    def reserve(self, amount: int) -> None:
        if amount <= 0:
            return
        if self.used + amount > self.limit:
            raise FileError(f"Total disk quota of {self.limit} bytes exceeded")
        self.used += amount

    def release(self, amount: int) -> None:
        if amount <= 0:
            return
        self.used = max(0, self.used - amount)


def _filename_redaction_policy(config: dict[Any, Any]) -> str:
    """Resolve the configured log-facing filename policy.

    Redaction is enabled by default so upload names and path segments cannot
    accidentally end up in logs. Callers may explicitly opt into ``none`` or
    choose a hashed/masked representation.
    """
    value: Any = config.get("UPLOAD_FILENAME_REDACTION")
    if value is None:
        value = config.get("UPLOAD_REDACT_FILENAMES")
    if value is None:
        value = config.get("UPLOAD_REDACT_FILENAME")
    if value is None:
        value = config.get("UPLOAD_LOG_FILENAME_POLICY")
    if value is None:
        value = config.get("UPLOAD_FILENAME_POLICY")
    if value is None:
        value = True

    if value is False:
        return "none"
    if isinstance(value, str):
        normalized = value.lower()
        if normalized in {"none", "off", "false", "full"}:
            return "none"
        if normalized in {"hash", "sha256", "hashed"}:
            return "hash"
        if normalized in {"mask", "masked"}:
            return "mask"
    return "redact"


def _noop_event() -> None:
    pass


def _noop_data(_data: bytes, _start: int, _end: int) -> None:
    pass


@global_enum
class QuerystringState(IntEnum):
    """Querystring parser states.

    These are used to keep track of the state of the parser, and are used to determine
    what to do when new data is encountered.
    """

    BEFORE_FIELD = 0
    FIELD_NAME = 1
    FIELD_DATA = 2


@global_enum
class MultipartState(IntEnum):
    """Multipart parser states.

    These are used to keep track of the state of the parser, and are used to determine
    what to do when new data is encountered.
    """

    START = 0
    START_BOUNDARY = 1
    HEADER_FIELD_START = 2
    HEADER_FIELD = 3
    HEADER_VALUE_START = 4
    HEADER_VALUE = 5
    HEADER_VALUE_ALMOST_DONE = 6
    HEADERS_ALMOST_DONE = 7
    PART_DATA_START = 8
    PART_DATA = 9
    PART_DATA_END = 10
    END_BOUNDARY = 11
    END = 12
    BOUNDARY_PADDING = 13


if TYPE_CHECKING:
    BEFORE_FIELD = QuerystringState.BEFORE_FIELD
    FIELD_NAME = QuerystringState.FIELD_NAME
    FIELD_DATA = QuerystringState.FIELD_DATA

    START = MultipartState.START
    START_BOUNDARY = MultipartState.START_BOUNDARY
    HEADER_FIELD_START = MultipartState.HEADER_FIELD_START
    HEADER_FIELD = MultipartState.HEADER_FIELD
    HEADER_VALUE_START = MultipartState.HEADER_VALUE_START
    HEADER_VALUE = MultipartState.HEADER_VALUE
    HEADER_VALUE_ALMOST_DONE = MultipartState.HEADER_VALUE_ALMOST_DONE
    HEADERS_ALMOST_DONE = MultipartState.HEADERS_ALMOST_DONE
    PART_DATA_START = MultipartState.PART_DATA_START
    PART_DATA = MultipartState.PART_DATA
    PART_DATA_END = MultipartState.PART_DATA_END
    END_BOUNDARY = MultipartState.END_BOUNDARY
    END = MultipartState.END
    BOUNDARY_PADDING = MultipartState.BOUNDARY_PADDING

# Flags for the multipart parser.
FLAG_PART_BOUNDARY = 1
FLAG_LAST_BOUNDARY = 2

# Get constants.  Since iterating over a str on Python 2 gives you a 1-length
# string, but iterating over a bytes object on Python 3 gives you an integer,
# we need to save these constants.
CR = b"\r"[0]
LF = b"\n"[0]
COLON = b":"[0]
SPACE = b" "[0]
HYPHEN = b"-"[0]
AMPERSAND = b"&"[0]
LOWER_A = b"a"[0]
LOWER_Z = b"z"[0]
NULL = b"\x00"[0]

# fmt: off
# Mask for ASCII characters that can be http tokens.
# Per RFC7230 - 3.2.6, this is all alpha-numeric characters
# and these: !#$%&'*+-.^_`|~
TOKEN_CHARS = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"abcdefghijklmnopqrstuvwxyz"
    b"0123456789"
    b"!#$%&'*+-.^_`|~")
TOKEN_CHARS_SET = frozenset(TOKEN_CHARS)
# fmt: on

DEFAULT_MAX_HEADER_COUNT = 8
"""Default maximum number of headers allowed per multipart part."""

DEFAULT_MAX_HEADER_SIZE = 4096 + 128
"""Default maximum size of a single multipart header line, including syntax overhead."""

MAX_BOUNDARY_LENGTH = 256
"""Maximum allowed length of a multipart boundary.

[RFC 2046 §5.1.1](https://datatracker.ietf.org/doc/html/rfc2046#section-5.1.1)
recommends boundaries be at most 70 bytes. 256 bytes is generous headroom over
every HTTP client.
"""


def _parseparam(s: str) -> list[str]:
    # Vendored from the standard library's
    # [`email.message._parseparam`](https://github.com/python/cpython/blob/v3.14.2/Lib/email/message.py#L73-L96)
    # to split a header into its `;`-separated parts without treating a `;` inside a double-quoted string as a
    # separator - and without the RFC 2231 decoding that `email.message.Message.get_params` would apply on top.
    s = ";" + s
    plist: list[str] = []
    start = 0
    while s.find(";", start) == start:
        start += 1
        end = s.find(";", start)
        ind, diff = start, 0
        while end > 0:
            diff += s.count('"', ind, end) - s.count('\\"', ind, end)
            if diff % 2 == 0:
                break
            end, ind = ind, s.find(";", end + 1)
        if end < 0:
            end = len(s)
        i = s.find("=", start, end)
        if i == -1:
            f = s[start:end]
        else:
            f = s[start:i].rstrip(" \t").lower() + "=" + s[i + 1 : end].lstrip(" \t")
        plist.append(f.strip(" \t"))
        start = end
    return plist


def parse_options_header(value: str | bytes | None) -> tuple[bytes, dict[bytes, bytes]]:
    """Parses a Content-Type header into a value in the following format: (content_type, {parameters})."""
    if not value:
        return (b"", {})

    # If we are passed bytes, we assume that it conforms to WSGI, encoding in latin-1.
    if isinstance(value, bytes):  # pragma: no cover
        value = value.decode("latin-1")

    # For types
    assert isinstance(value, str), "Value should be a string by now"

    # If we have no options, return the string as-is.
    if ";" not in value:
        return (value.lower().strip(" \t").encode("latin-1"), {})

    ctype, *segments = _parseparam(value)
    options: dict[bytes, bytes] = {}
    for segment in segments:
        key, _, val = segment.partition("=")
        # [RFC 7578 §4.2](https://datatracker.ietf.org/doc/html/rfc7578#section-4.2)
        # forbids the RFC 5987/2231 extended syntax (`key*=`, `key*0`, ...) in
        # multipart/form-data, so we ignore those parameters and keep the plain
        # `key` authoritative.
        if "*" in key:
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1].replace("\\\\", "\\").replace('\\"', '"')
        # Work around an IE6 bug where the full file path is sent instead of
        # just the filename.
        if key == "filename" and (val[1:3] == ":\\" or val[:2] == "\\\\"):
            val = val.split("\\")[-1]
        options[key.encode("latin-1")] = val.encode("latin-1")
    return ctype.lower().encode("latin-1"), options


class Field:
    """A Field object represents a (parsed) form field.  It represents a single
    field with a corresponding name and value.

    The name that a :class:`Field` will be instantiated with is the same name
    that would be found in the following HTML::

        <input name="name_goes_here" type="text"/>

    This class defines two methods, :meth:`on_data` and :meth:`on_end`, that
    will be called when data is written to the Field, and when the Field is
    finalized, respectively.

    Args:
        name: The name of the form field.
        content_type: The value of the Content-Type header for this field.
    """

    def __init__(self, name: bytes | None, *, content_type: str | None = None) -> None:
        self._name = name
        self._value: list[bytes] = []
        self._content_type = content_type

        # We cache the joined version of _value for speed.
        self._cache = _missing

    @classmethod
    def from_value(cls, name: bytes, value: bytes | None) -> Field:
        """Create an instance of a :class:`Field`, and set the corresponding
        value - either None or an actual value.  This method will also
        finalize the Field itself.

        Args:
            name: the name of the form field.
            value: the value of the form field - either a bytestring or None.

        Returns:
            A new instance of a [`Field`][python_multipart.Field].
        """

        f = cls(name)
        if value is None:
            f.set_none()
        else:
            f.write(value)
        f.finalize()
        return f

    def write(self, data: bytes) -> int:
        """Write some data into the form field.

        Args:
            data: The data to write to the field.

        Returns:
            The number of bytes written.
        """
        return self.on_data(data)

    def on_data(self, data: bytes) -> int:
        """This method is a callback that will be called whenever data is
        written to the Field.

        Args:
            data: The data to write to the field.

        Returns:
            The number of bytes written.
        """
        self._value.append(data)
        self._cache = _missing
        return len(data)

    def on_end(self) -> None:
        """This method is called whenever the Field is finalized."""
        if self._cache is _missing:
            self._cache = b"".join(self._value)

    def finalize(self) -> None:
        """Finalize the form field."""
        self.on_end()

    def close(self) -> None:
        """Close the Field object.  This will free any underlying cache."""
        # Free our value array.
        if self._cache is _missing:
            self._cache = b"".join(self._value)

        del self._value

    def set_none(self) -> None:
        """Some fields in a querystring can possibly have a value of None - for
        example, the string "foo&bar=&baz=asdf" will have a field with the
        name "foo" and value None, one with name "bar" and value "", and one
        with name "baz" and value "asdf".  Since the write() interface doesn't
        support writing None, this function will set the field value to None.
        """
        self._cache = None

    @property
    def field_name(self) -> bytes | None:
        """This property returns the name of the field."""
        return self._name

    @property
    def value(self) -> bytes | None:
        """This property returns the value of the form field."""
        if self._cache is _missing:
            self._cache = b"".join(self._value)

        assert isinstance(self._cache, bytes) or self._cache is None
        return self._cache

    @property
    def content_type(self) -> str | None:
        """This property returns the content_type value of the field."""
        return self._content_type

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Field):
            return self.field_name == other.field_name and self.value == other.value
        else:
            return NotImplemented

    def __repr__(self) -> str:
        if self.value is not None and len(self.value) > 97:
            # We get the repr, and then insert three dots before the final
            # quote.
            v = repr(self.value[:97])[:-1] + "...'"
        else:
            v = repr(self.value)

        return f"{self.__class__.__name__}(field_name={self.field_name!r}, value={v})"


class File:
    """This class represents an uploaded file.  It handles writing file data to
    either an in-memory file or a temporary file on-disk, if the optional
    threshold is passed.

    There are some options that can be passed to the File to change behavior
    of the class.  Valid options are as follows:

    | Name                  | Type  | Default | Description |
    |-----------------------|-------|---------|-------------|
    | UPLOAD_DIR            | `str` | None    | The directory to store uploaded files in. If this is None, a temporary file will be created in the system's standard location. |
    | UPLOAD_TMP_DIR        | `str` | None    | The directory to create automatically named temporary files in. Falls back to `UPLOAD_DIR`, then the system temporary directory. |
    | UPLOAD_DELETE_TMP     | `bool`| True    | Delete automatically created TMP file |
    | UPLOAD_KEEP_FILENAME  | `bool`| False   | Whether or not to keep the filename of the uploaded file. If True, then the filename is reduced to its basename (directory components are stripped) and the file is saved with that name. Otherwise, a temporary name will be used. |
    | UPLOAD_KEEP_EXTENSIONS| `bool`| False   | Whether or not to keep the uploaded file's extension. If False, the file will be saved with the default temporary extension (usually ".tmp"). Otherwise, the file's extension will be maintained. Note that this will properly combine with the UPLOAD_KEEP_FILENAME setting. |
    | MAX_MEMORY_FILE_SIZE  | `int` | 1 MiB   | The maximum number of bytes of a File to keep in memory. By default, the contents of a File are kept into memory until a certain limit is reached, after which the contents of the File are written to a temporary file. This behavior can be disabled by setting this value to an appropriately large value (or, for example, infinity, such as `float('inf')`. |
    | MAX_FILE_SIZE         | `int` | infinity| The maximum size of this file. The write is rejected before data beyond the limit is stored. |
    | MAX_TOTAL_FILE_SIZE   | `int` | infinity| The maximum number of bytes all files from one parser may use (whether in memory or on disk). Shared across file parts. |
    | UPLOAD_FILENAME_REDACTION | `str` | `"redact"` | Log-facing filename policy: `redact`, `hash`, `mask`, or `none`. Logs never include upload paths. |

    Args:
        file_name: The name of the file that this [`File`][python_multipart.File] represents.
        field_name: The name of the form field that this file was uploaded with.  This can be None, if, for example,
            the file was uploaded with Content-Type application/octet-stream.
        config: The configuration for this File.  See above for valid configuration keys and their corresponding values.
        content_type: The value of the Content-Type header.
    """  # noqa: E501

    def __init__(
        self,
        file_name: bytes | None,
        field_name: bytes | None = None,
        config: FileConfig = {},
        *,
        content_type: str | None = None,
        _disk_budget: _DiskBudget | None = None,
        _parser_owned: bool = False,
    ) -> None:
        # Save configuration, set other variables default.
        self.logger = logging.getLogger(__name__)
        self._config = config
        self._owner = "parser" if _parser_owned else "caller"
        self._closed = False
        self._finalized = False
        self._in_memory = True
        self._bytes_written = 0
        self._fileobj: BytesIO | BufferedRandom = BytesIO()
        self._hasher = hashlib.sha256()

        # Disk accounting is shared by every file created by a FormParser.
        total_limit = _config_limit(
            config,
            "MAX_TOTAL_FILE_SIZE",
            "MAX_TOTAL_UPLOAD_SIZE",
            "MAX_DISK_BUDGET",
            "MAX_DISK_SIZE",
            "MAX_DISK_QUOTA",
            "MAX_TOTAL_DISK_SIZE",
        )
        self._disk_budget = _disk_budget if _disk_budget is not None else _DiskBudget(total_limit)
        self._budget_reserved = 0
        _config_limit(config, "MAX_FILE_SIZE", "MAX_FILE_BYTES", "MAX_UPLOAD_FILE_SIZE")

        # Temporary file bookkeeping. `_temp_path` is the real path used by the
        # OS, while `_actual_file_name` preserves the public naming behavior.
        self._temp_path: bytes | None = None
        self._delete_tmp = bool(config.get("UPLOAD_DELETE_TMP", True))
        self._temp_is_auto_named = False

        # Save the provided field/file name and content type.
        self._field_name = field_name
        self._file_name = file_name
        self._content_type = content_type

        # Our actual file name is None by default, since, depending on our
        # config, we may not actually use the provided name.
        self._actual_file_name: bytes | None = None

        # Nameless uploads (e.g. `application/octet-stream`) have no base or extension.
        self._file_base: bytes | None = None
        self._ext = b""
        if file_name is not None:
            # Extract just the basename to avoid directory traversal
            basename = os.path.basename(file_name)
            base, ext = os.path.splitext(basename)
            self._file_base = base
            self._ext = ext

    @classmethod
    def _for_parser(
        cls,
        file_name: bytes | None,
        field_name: bytes | None,
        config: FileConfig,
        *,
        content_type: str | None,
        disk_budget: _DiskBudget,
    ) -> File:
        """Create a file owned by the parser until an explicit hand-off."""
        return cls(
            file_name,
            field_name,
            config=config,
            content_type=content_type,
            _disk_budget=disk_budget,
            _parser_owned=True,
        )

    @property
    def owner(self) -> str:
        """Who is responsible for closing this file: ``parser`` or ``caller``."""
        return self._owner

    @property
    def owned_by_parser(self) -> bool:
        return self._owner == "parser"

    @property
    def finalized(self) -> bool:
        return self._finalized

    @property
    def ownership(self) -> str:
        return self._owner

    @property
    def is_parser_owned(self) -> bool:
        return self.owned_by_parser

    def transfer_ownership(self) -> File:
        """Explicitly hand a parser-owned file over to the caller."""
        if self._owner == "parser":
            self._owner = "caller"
        return self

    @property
    def field_name(self) -> bytes | None:
        """The form field associated with this file.  May be None if there isn't
        one, for example when we have an application/octet-stream upload.
        """
        return self._field_name

    @property
    def file_name(self) -> bytes | None:
        """The file name given in the upload request."""
        return self._file_name

    @property
    def actual_file_name(self) -> bytes | None:
        """The file name that this file is saved as.  Will be None if it's not
        currently saved on disk.
        """
        return self._actual_file_name

    @property
    def file_object(self) -> BytesIO | BufferedRandom:
        """The file object that we're currently writing to.  Note that this
        will either be an instance of a :class:`io.BytesIO`, or a regular file
        object.
        """
        return self._fileobj

    @property
    def size(self) -> int:
        """The total size of this file, counted as the number of bytes that
        currently have been written to the file.
        """
        return self._bytes_written

    @property
    def digest(self) -> str:
        """SHA-256 hex digest of the file content written so far."""
        return self._hasher.hexdigest()

    @property
    def hexdigest(self) -> str:
        return self.digest

    @property
    def digest_bytes(self) -> bytes:
        return self._hasher.digest()

    @property
    def sha256_digest(self) -> bytes:
        return self.digest_bytes

    @property
    def content_digest(self) -> str:
        return self.digest

    @property
    def sha256_hexdigest(self) -> str:
        return self.digest

    @property
    def content_sha256(self) -> str:
        return self.digest

    @property
    def sha256(self) -> str:
        return self.digest

    def get_digest(self) -> str:
        return self.digest

    def _display_file_name(self) -> str:
        if self._file_name is None:
            return "<unnamed>"
        policy = _filename_redaction_policy(self._config)
        if policy == "none":
            return os.fsdecode(os.path.basename(self._file_name))
        if policy == "hash":
            return "sha256:" + hashlib.sha256(self._file_name).hexdigest()[:8]
        if policy == "mask":
            extension = self._ext.decode("latin-1")
            return "***" + extension if extension else "***"
        return "<redacted>"

    @property
    def in_memory(self) -> bool:
        """A boolean representing whether or not this file object is currently
        stored in-memory or on-disk.
        """
        return self._in_memory

    @property
    def content_type(self) -> str | None:
        """The Content-Type value for this part, if it was set."""
        return self._content_type

    def flush_to_disk(self) -> None:
        """If the file is already on-disk, do nothing.  Otherwise, copy from
        the in-memory buffer to a disk file, and then reassign our internal
        file object to this new disk file.

        Note that if you attempt to flush a file that is already on-disk, a
        warning will be logged to this module's logger.
        """
        if not self._in_memory:
            self.logger.warning("Trying to flush to disk when we're not in memory")
            return

        # Reserve any bytes that are not already accounted for before opening
        # the file, so quota failures happen before more data reaches disk.
        needed = max(0, self._bytes_written - self._budget_reserved)
        if needed:
            self._disk_budget.reserve(needed)
            self._budget_reserved += needed

        old_fileobj = self._fileobj
        new_file: BufferedRandom | None = None
        try:
            old_fileobj.seek(0)
            new_file = self._get_disk_file()
            shutil.copyfileobj(old_fileobj, new_file)
            new_file.seek(self._bytes_written)
        except BaseException:
            if new_file is not None:
                try:
                    new_file.close()
                finally:
                    self._remove_tmp_file()
                    self._actual_file_name = None
            self._release_reserved_budget()
            raise

        self._fileobj = new_file
        self._in_memory = False
        self._budget_reserved = max(self._budget_reserved, self._bytes_written)
        old_fileobj.close()

    def _get_disk_file(self) -> BufferedRandom:
        """This function is responsible for getting a file object on-disk for us."""
        self.logger.info("Opening a disk-backed upload file")

        upload_dir = self._config.get("UPLOAD_DIR")
        file_dir = self._config.get("UPLOAD_TMP_DIR")
        if file_dir is None:
            file_dir = self._config.get("UPLOAD_TEMP_DIR")
        if file_dir is None:
            file_dir = self._config.get("TEMP_DIR")
        if file_dir is None:
            file_dir = self._config.get("TMP_DIR")
        if file_dir is None:
            file_dir = upload_dir
        keep_filename = self._config.get("UPLOAD_KEEP_FILENAME", False)
        keep_extensions = self._config.get("UPLOAD_KEEP_EXTENSIONS", False)
        delete_tmp = self._config.get("UPLOAD_DELETE_TMP", True)
        tmp_file: None | BufferedRandom = None
        fname: bytes | None = None
        temp_path: bytes | None = None

        # If we have a directory and a filename to keep...
        if file_dir is not None and keep_filename and self._file_base is not None:
            self.logger.info("Saving an upload with its original filename")

            # Build our filename.
            fname = self._file_base + self._ext if keep_extensions else self._file_base

            target_dir = upload_dir if upload_dir is not None else file_dir
            path = os.path.join(os.fsencode(target_dir), fname)
            temp_path = os.path.abspath(path)
            try:
                tmp_file = open(path, "w+b")
            except OSError as exc:
                self.logger.warning("Error opening temporary upload file (%s)", type(exc).__name__)
                raise FileError("Error opening temporary file")
        else:
            # Build options array.
            # Note that on Python 3, tempfile doesn't support byte names.  We
            # encode our paths using the default filesystem encoding.
            suffix = self._ext.decode(sys.getfilesystemencoding()) if keep_extensions else None

            if file_dir is None:
                directory = None
            else:
                directory = os.fsdecode(file_dir)

            # Create a temporary (named) file with the appropriate settings.
            self.logger.info(
                "Creating a temporary upload file (keep_extensions=%s, delete=%s)", keep_extensions, delete_tmp
            )
            try:
                tmp_file = cast(
                    BufferedRandom, tempfile.NamedTemporaryFile(suffix=suffix, delete=delete_tmp, dir=directory)
                )
            except OSError as exc:
                self.logger.warning("Error creating temporary upload file (%s)", type(exc).__name__)
                raise FileError("Error creating named temporary file")

            assert tmp_file is not None
            # Encode filename as bytes.
            if isinstance(tmp_file.name, str):
                fname = tmp_file.name.encode(sys.getfilesystemencoding())
            else:
                fname = cast(bytes, tmp_file.name)  # pragma: no cover
            temp_path = os.path.abspath(fname)
            self._temp_is_auto_named = True

        assert tmp_file is not None
        assert fname is not None
        assert temp_path is not None
        self._actual_file_name = fname
        self._temp_path = temp_path
        self._delete_tmp = bool(delete_tmp)
        return tmp_file

    def _remove_tmp_file(self) -> None:
        """Best-effort removal of the OS temporary path, without logging it."""
        path = self._temp_path
        if path is None:
            return
        self._temp_path = None
        try:
            os.unlink(os.fsdecode(path))
        except FileNotFoundError:
            pass
        except OSError as exc:
            self.logger.warning("Unable to remove temporary upload file (%s)", type(exc).__name__)

    def _release_reserved_budget(self) -> None:
        reserved = self._budget_reserved
        self._budget_reserved = 0
        self._disk_budget.release(reserved)

    def _dispose(self, *, force_delete: bool) -> None:
        """Close and release this file exactly once, optionally deleting it."""
        close_error: BaseException | None = None
        if not self._closed:
            self._closed = True
            try:
                self._fileobj.close()
            except BaseException as exc:
                close_error = exc

        if force_delete or (self._delete_tmp and self._temp_is_auto_named):
            self._remove_tmp_file()
        self._release_reserved_budget()

        if close_error is not None:
            raise close_error

    def _discard(self) -> None:
        """Parser-owned cleanup path. Transferred files are never touched."""
        if self._owner != "parser":
            return
        self._dispose(force_delete=True)

    def write(self, data: bytes) -> int:
        """Write some data to the File.

        :param data: a bytestring
        """
        return self.on_data(data)

    def on_data(self, data: bytes) -> int:
        """This method is a callback that will be called whenever data is
        written to the File.

        Args:
            data: The data to write to the file.

        Returns:
            The number of bytes written.
        """
        incoming = len(data)
        max_file_size = _config_limit(self._config, "MAX_FILE_SIZE", "MAX_FILE_BYTES", "MAX_UPLOAD_FILE_SIZE")
        if self._bytes_written + incoming > max_file_size:
            raise FileError(f"File exceeds maximum size of {max_file_size} bytes")

        max_memory_file_size = self._config.get("MAX_MEMORY_FILE_SIZE")
        reserved_now = 0
        needed = max(0, self._bytes_written + incoming - self._budget_reserved)
        if needed:
            self._disk_budget.reserve(needed)
            self._budget_reserved += needed
            reserved_now = needed

        try:
            bwritten = self._fileobj.write(data)
        except BaseException:
            if reserved_now:
                self._disk_budget.release(reserved_now)
                self._budget_reserved -= reserved_now
            raise

        # If the bytes written isn't the same as the length, just return.
        if bwritten != len(data):
            if reserved_now:
                self._disk_budget.release(reserved_now)
                self._budget_reserved -= reserved_now
            self.logger.warning("bwritten != len(data) (%d != %d)", bwritten, len(data))
            return bwritten

        # Keep track of how many bytes we've written.
        self._bytes_written += bwritten
        self._hasher.update(data[:bwritten])

        # If we're in-memory and are over our limit, we create a file.
        if self._in_memory and max_memory_file_size is not None and (self._bytes_written > max_memory_file_size):
            self.logger.info("Flushing to disk")
            self.flush_to_disk()

        # Return the number of bytes written.
        return bwritten

    def on_end(self) -> None:
        """This method is called whenever the Field is finalized."""
        # Flush the underlying file object
        self._fileobj.flush()

    def finalize(self) -> None:
        """Finalize the form file.  This will not close the underlying file,
        but simply signal that we are finished writing to the File.
        """
        self.on_end()
        self._finalized = True
        self.logger.info(
            "File part finalized: name=%s size=%d sha256=%s", self._display_file_name(), self.size, self.digest
        )

    def close(self) -> None:
        """Close the File object exactly once.

        For automatically named temporary files, the behavior is controlled by
        ``UPLOAD_DELETE_TMP``. Parser-driven cleanup uses a separate path that
        also removes files created by the parser even when ``UPLOAD_DELETE_TMP``
        was disabled.
        """
        self._dispose(force_delete=False)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(file_name={self._display_file_name()!r}, field_name={self.field_name!r})"


class BaseParser:
    """This class is the base class for all parsers.  It contains the logic for
    calling and adding callbacks.

    A callback can be one of two different forms.  "Notification callbacks" are
    callbacks that are called when something happens - for example, when a new
    part of a multipart message is encountered by the parser.  "Data callbacks"
    are called when we get some sort of data - for example, part of the body of
    a multipart chunk.  Notification callbacks are called with no parameters,
    whereas data callbacks are called with three, as follows::

        data_callback(data, start, end)

    The "data" parameter is a bytestring (i.e. "foo" on Python 2, or b"foo" on
    Python 3).  "start" and "end" are integer indexes into the "data" string
    that represent the data of interest.  Thus, in a data callback, the slice
    `data[start:end]` represents the data that the callback is "interested in".
    The callback is not passed a copy of the data, since copying severely hurts
    performance.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.callbacks: QuerystringCallbacks | OctetStreamCallbacks | MultipartCallbacks = {}

    def callback(
        self, name: CallbackName, data: bytes | None = None, start: int | None = None, end: int | None = None
    ) -> None:
        """This function calls a provided callback with some data.  If the
        callback is not set, will do nothing.

        Args:
            name: The name of the callback to call (as a string).
            data: Data to pass to the callback.  If None, then it is assumed that the callback is a notification
                callback, and no parameters are given.
            end: An integer that is passed to the data callback.
            start: An integer that is passed to the data callback.
        """
        func = self.callbacks.get("on_" + name)
        if func is None:
            return
        func = cast("Callable[..., Any]", func)
        # Depending on whether we're given a buffer...
        if data is not None:
            # Don't do anything if we have start == end.
            if start is not None and start == end:
                return
            func(data, start, end)
        else:
            func()

    def set_callback(self, name: CallbackName, new_func: Callable[..., Any] | None) -> None:
        """Update the function for a callback.  Removes from the callbacks dict
        if new_func is None.

        :param name: The name of the callback to call (as a string).

        :param new_func: The new function for the callback.  If None, then the
                         callback will be removed (with no error if it does not
                         exist).
        """
        if new_func is None:
            self.callbacks.pop("on_" + name, None)  # type: ignore[misc]
        else:
            self.callbacks["on_" + name] = new_func  # type: ignore[literal-required]

    def close(self) -> None:
        pass  # pragma: no cover

    def finalize(self) -> None:
        pass  # pragma: no cover

    def __repr__(self) -> str:
        return "%s()" % self.__class__.__name__


class OctetStreamParser(BaseParser):
    """This parser parses an octet-stream request body and calls callbacks when
    incoming data is received.  Callbacks are as follows:

    | Callback Name  | Parameters      | Description                                         |
    |----------------|-----------------|-----------------------------------------------------|
    | on_start       | None            | Called when the first data is parsed.               |
    | on_data        | data, start, end| Called for each data chunk that is parsed.           |
    | on_end         | None            | Called when the parser is finished parsing all data.|

    Args:
        callbacks: A dictionary of callbacks.  See the documentation for [`BaseParser`][python_multipart.BaseParser].
        max_size: The maximum size of body to parse.  Defaults to infinity - i.e. unbounded.
    """

    def __init__(self, callbacks: OctetStreamCallbacks | None = None, max_size: float = float("inf")):
        super().__init__()
        self.callbacks = {} if callbacks is None else callbacks
        self._started = False

        if not isinstance(max_size, Number) or max_size < 1:
            raise ValueError("max_size must be a positive number, not %r" % max_size)
        self.max_size: int | float = max_size
        self._current_size = 0

    def write(self, data: bytes) -> int:
        """Write some data to the parser, which will perform size verification,
        and then pass the data to the underlying callback.

        Args:
            data: The data to write to the parser.

        Returns:
            The number of bytes written.
        """
        if not self._started:
            self.callback("start")
            self._started = True

        # Truncate data length.
        data_len = len(data)
        if (self._current_size + data_len) > self.max_size:
            # We truncate the length of data that we are to process.
            new_size = int(self.max_size - self._current_size)
            self.logger.warning(
                "Current size is %d (max %d), so truncating data length from %d to %d",
                self._current_size,
                self.max_size,
                data_len,
                new_size,
            )
            data_len = new_size

        # Increment size, then callback, in case there's an exception.
        self._current_size += data_len
        self.callback("data", data, 0, data_len)
        return data_len

    def finalize(self) -> None:
        """Finalize this parser, which signals to that we are finished parsing,
        and sends the on_end callback.
        """
        self.callback("end")

    def __repr__(self) -> str:
        return "%s()" % self.__class__.__name__


class QuerystringParser(BaseParser):
    """This is a streaming querystring parser.  It will consume data, and call
    the callbacks given when it has data.

    | Callback Name  | Parameters      | Description                                         |
    |----------------|-----------------|-----------------------------------------------------|
    | on_field_start | None            | Called when a new field is encountered.             |
    | on_field_name  | data, start, end| Called when a portion of a field's name is encountered. |
    | on_field_data  | data, start, end| Called when a portion of a field's data is encountered. |
    | on_field_end   | None            | Called when the end of a field is encountered.      |
    | on_end         | None            | Called when the parser is finished parsing all data.|

    Args:
        callbacks: A dictionary of callbacks.  See the documentation for [`BaseParser`][python_multipart.BaseParser].
        strict_parsing: Whether or not to parse the body strictly.  Defaults to False.  If this is set to True, then the
            behavior of the parser changes as the following: if a field has a value with an equal sign
            (e.g. "foo=bar", or "foo="), it is always included.  If a field has no equals sign (e.g. "...&name&..."),
            it will be treated as an error if 'strict_parsing' is True, otherwise included.  If an error is encountered,
            then a [`QuerystringParseError`][python_multipart.exceptions.QuerystringParseError] will be raised.
        max_size: The maximum size of body to parse.  Defaults to infinity - i.e. unbounded.
    """  # noqa: E501

    state: QuerystringState

    def __init__(
        self,
        callbacks: QuerystringCallbacks | None = None,
        strict_parsing: bool = False,
        max_size: float = float("inf"),
    ) -> None:
        super().__init__()
        self.state = BEFORE_FIELD
        self._found_sep = False

        self.callbacks = {} if callbacks is None else callbacks

        # Max-size stuff
        if not isinstance(max_size, Number) or max_size < 1:
            raise ValueError("max_size must be a positive number, not %r" % max_size)
        self.max_size: int | float = max_size
        self._current_size = 0

        # Should parsing be strict?
        self.strict_parsing = strict_parsing

    def write(self, data: bytes) -> int:
        """Write some data to the parser, which will perform size verification,
        parse into either a field name or value, and then pass the
        corresponding data to the underlying callback.  If an error is
        encountered while parsing, a QuerystringParseError will be raised.  The
        "offset" attribute of the raised exception will be set to the offset in
        the input data chunk (NOT the overall stream) that caused the error.

        Args:
            data: The data to write to the parser.

        Returns:
            The number of bytes written.
        """
        # Handle sizing.
        data_len = len(data)
        if (self._current_size + data_len) > self.max_size:
            # We truncate the length of data that we are to process.
            new_size = int(self.max_size - self._current_size)
            self.logger.warning(
                "Current size is %d (max %d), so truncating data length from %d to %d",
                self._current_size,
                self.max_size,
                data_len,
                new_size,
            )
            data_len = new_size

        l = 0
        try:
            l = self._internal_write(data, data_len)
        finally:
            self._current_size += l

        return l

    def _internal_write(self, data: bytes, length: int) -> int:
        state = self.state
        strict_parsing = self.strict_parsing
        found_sep = self._found_sep
        callbacks = cast("QuerystringCallbacks", self.callbacks)
        on_field_start = callbacks.get("on_field_start")
        on_field_name = callbacks.get("on_field_name")
        on_field_data = callbacks.get("on_field_data")
        on_field_end = callbacks.get("on_field_end")
        if on_field_start is None:
            on_field_start = _noop_event
        if on_field_name is None:
            on_field_name = _noop_data
        if on_field_data is None:
            on_field_data = _noop_data
        if on_field_end is None:
            on_field_end = _noop_event

        i = 0
        while i < length:
            ch = data[i]

            # Depending on our state...
            if state == BEFORE_FIELD:
                # If the 'found_sep' flag is set, we've already encountered
                # and skipped a single separator.  If so, we check our strict
                # parsing flag and decide what to do.  Otherwise, we haven't
                # yet reached a separator, and thus, if we do, we need to skip
                # it as it will be the boundary between fields that's supposed
                # to be there.
                if ch == AMPERSAND:
                    if found_sep:
                        # If we're parsing strictly, we disallow blank chunks.
                        if strict_parsing:
                            raise QuerystringParseError("Skipping duplicate ampersand at %d" % i, offset=i)
                        else:
                            self.logger.debug("Skipping duplicate ampersand at %d", i)
                    else:
                        # This case is when we're skipping the (first)
                        # separator between fields, so we just set our flag
                        # and continue on.
                        found_sep = True
                else:
                    # Emit a field-start event, and go to that state.  Also,
                    # reset the "found_sep" flag, for the next time we get to
                    # this state.
                    on_field_start()
                    i -= 1
                    state = FIELD_NAME
                    found_sep = False

            elif state == FIELD_NAME:
                # Try and find a separator - we ensure that, if we do, we only
                # look for the equal sign before it.
                sep_pos = data.find(b"&", i, length)

                # See if we can find an equals sign in the remaining data.  If
                # so, we can immediately emit the field name and jump to the
                # data state.
                if sep_pos != -1:
                    equals_pos = data.find(b"=", i, sep_pos)
                else:
                    equals_pos = data.find(b"=", i, length)

                if equals_pos != -1:
                    # Emit this name.
                    if i != equals_pos:
                        on_field_name(data, i, equals_pos)

                    # Jump i to this position.  Note that it will then have 1
                    # added to it below, which means the next iteration of this
                    # loop will inspect the character after the equals sign.
                    i = equals_pos
                    state = FIELD_DATA
                else:
                    # No equals sign found.
                    if not strict_parsing:
                        # See also comments in the QuerystringState.FIELD_DATA case below.
                        # If we found the separator, we emit the name and just
                        # end - there's no data callback at all (not even with
                        # a blank value).
                        if sep_pos != -1:
                            if i != sep_pos:
                                on_field_name(data, i, sep_pos)
                            on_field_end()

                            i = sep_pos - 1
                            state = BEFORE_FIELD
                        else:
                            # Otherwise, no separator in this block, so the
                            # rest of this chunk must be a name.
                            if i != length:
                                on_field_name(data, i, length)
                            i = length

                    else:
                        # We're parsing strictly.  If we find a separator,
                        # this is an error - we require an equals sign.
                        if sep_pos != -1:
                            raise QuerystringParseError(
                                "When strict_parsing is True, we require an "
                                "equals sign in all field chunks. Did not "
                                "find one in the chunk that starts at %d" % (i,),
                                offset=i,
                            )

                        # No separator in the rest of this chunk, so it's just
                        # a field name.
                        if i != length:
                            on_field_name(data, i, length)
                        i = length

            elif state == FIELD_DATA:
                # Try finding an ampersand after this position.
                sep_pos = data.find(b"&", i, length)

                # If we found it, callback this bit as data and then go back
                # to expecting to find a field.
                if sep_pos != -1:
                    if i != sep_pos:
                        on_field_data(data, i, sep_pos)
                    on_field_end()

                    # Note that we go to the separator, which brings us to the
                    # "before field" state.  This allows us to properly emit
                    # "field_start" events only when we actually have data for
                    # a field of some sort.
                    i = sep_pos - 1
                    state = BEFORE_FIELD

                # Otherwise, emit the rest as data and finish.
                else:
                    if i != length:
                        on_field_data(data, i, length)
                    i = length

            else:  # pragma: no cover (error case)
                msg = "Reached an unknown state %d at %d" % (state, i)
                self.logger.warning(msg)
                raise QuerystringParseError(msg, offset=i)

            i += 1

        self.state = state
        self._found_sep = found_sep
        return length

    def finalize(self) -> None:
        """Finalize this parser, which signals to that we are finished parsing,
        if we're still in the middle of a field, an on_field_end callback, and
        then the on_end callback.
        """
        callbacks = cast("QuerystringCallbacks", self.callbacks)
        # If we're currently in the middle of a field, we finish it.
        if self.state in (FIELD_DATA, FIELD_NAME):
            on_field_end = callbacks.get("on_field_end")
            if on_field_end is None:
                on_field_end = _noop_event
            on_field_end()
        on_end = callbacks.get("on_end")
        if on_end is None:
            on_end = _noop_event
        on_end()

    def __repr__(self) -> str:
        return "{}(strict_parsing={!r}, max_size={!r})".format(
            self.__class__.__name__, self.strict_parsing, self.max_size
        )


class MultipartParser(BaseParser):
    """This class is a streaming multipart/form-data parser.

    | Callback Name      | Parameters      | Description |
    |--------------------|-----------------|-------------|
    | on_part_begin      | None            | Called when a new part of the multipart message is encountered. |
    | on_part_data       | data, start, end| Called when a portion of a part's data is encountered. |
    | on_part_end        | None            | Called when the end of a part is reached. |
    | on_header_begin    | None            | Called when we've found a new header in a part of a multipart message |
    | on_header_field    | data, start, end| Called each time an additional portion of a header is read (i.e. the part of the header that is before the colon; the "Foo" in "Foo: Bar"). |
    | on_header_value    | data, start, end| Called when we get data for a header. |
    | on_header_end      | None            | Called when the current header is finished - i.e. we've reached the newline at the end of the header. |
    | on_headers_finished| None            | Called when all headers are finished, and before the part data starts. |
    | on_end             | None            | Called when the parser is finished parsing all data. |

    Args:
        boundary: The multipart boundary.  This is required, and must match what is given in the HTTP request - usually in the Content-Type header.
        callbacks: A dictionary of callbacks.  See the documentation for [`BaseParser`][python_multipart.BaseParser].
        max_size: The maximum size of body to parse.  Defaults to infinity - i.e. unbounded.
        max_header_count: The maximum number of headers allowed per part.
        max_header_size: The maximum size of a single header line (excluding the trailing CRLF).
    """  # noqa: E501

    def __init__(
        self,
        boundary: bytes | str,
        callbacks: MultipartCallbacks | None = None,
        max_size: float = float("inf"),
        *,
        max_header_count: int = DEFAULT_MAX_HEADER_COUNT,
        max_header_size: int = DEFAULT_MAX_HEADER_SIZE,
    ) -> None:
        # Initialize parser state.
        super().__init__()
        self.state = START
        self.index = self.flags = 0

        self.callbacks = {} if callbacks is None else callbacks

        if not isinstance(max_size, Number) or max_size < 1:
            raise ValueError("max_size must be a positive number, not %r" % max_size)
        self.max_size = max_size
        self._current_size = 0

        self.max_header_count = max_header_count
        self._current_header_count = 0

        self.max_header_size = max_header_size
        self._current_header_size = 0

        # Setup marks.  These are used to track the state of data received.
        self.marks: dict[str, int] = {}

        # Save our boundary.
        if isinstance(boundary, str):  # pragma: no cover
            boundary = boundary.encode("latin-1")
        if len(boundary) > MAX_BOUNDARY_LENGTH:
            raise FormParserError(f"Boundary length {len(boundary)} exceeds maximum of {MAX_BOUNDARY_LENGTH}")
        self.boundary = b"\r\n--" + boundary

    def write(self, data: bytes) -> int:
        """Write some data to the parser, which will perform size verification,
        and then parse the data into the appropriate location (e.g. header,
        data, etc.), and pass this on to the underlying callback.  If an error
        is encountered, a MultipartParseError will be raised.  The "offset"
        attribute on the raised exception will be set to the offset of the byte
        in the input chunk that caused the error.

        Args:
            data: The data to write to the parser.

        Returns:
            The number of bytes written.
        """
        # Handle sizing.
        data_len = len(data)
        if (self._current_size + data_len) > self.max_size:
            # We truncate the length of data that we are to process.
            new_size = int(self.max_size - self._current_size)
            self.logger.warning(
                "Current size is %d (max %d), so truncating data length from %d to %d",
                self._current_size,
                self.max_size,
                data_len,
                new_size,
            )
            data_len = new_size

        l = 0
        try:
            l = self._internal_write(data, data_len)
        finally:
            self._current_size += l

        return l

    def _internal_write(self, data: bytes, length: int) -> int:
        # Get values from locals.
        boundary = self.boundary
        boundary_length = len(boundary)

        # Get our state, flags and index.  These are persisted between calls to
        # this function.
        state = self.state
        index = self.index
        flags = self.flags
        current_header_count = self._current_header_count
        current_header_size = self._current_header_size

        # Our index defaults to 0.
        i = 0

        def advance_header_size(amount: int = 1) -> None:
            nonlocal current_header_size
            current_header_size += amount
            if current_header_size > self.max_header_size:
                raise MultipartParseError("Maximum header size exceeded", offset=i)

        # Set a mark.
        def set_mark(name: str) -> None:
            self.marks[name] = i

        # Remove a mark.
        def delete_mark(name: str, reset: bool = False) -> None:
            self.marks.pop(name, None)

        # Helper function that makes calling a callback with data easier. The
        # 'remaining' parameter will callback from the marked value until the
        # end of the buffer, and reset the mark, instead of deleting it.  This
        # is used at the end of the function to call our callbacks with any
        # remaining data in this chunk.
        def data_callback(name: CallbackName, end_i: int, remaining: bool = False) -> None:
            marked_index = self.marks.get(name)
            if marked_index is None:
                return

            # Otherwise, we call it from the mark to the current byte we're
            # processing.
            if end_i <= marked_index:
                # There is no additional data to send.
                pass
            elif marked_index >= 0:
                # We are emitting data from the local buffer.
                self.callback(name, data, marked_index, end_i)
            else:
                # Some of the data comes from a partial boundary match.
                # and requires look-behind.
                # We need to use self.flags (and not flags) because we care about
                # the state when we entered the loop.
                lookbehind_len = -marked_index
                if lookbehind_len <= boundary_length:
                    self.callback(name, boundary, 0, lookbehind_len)
                elif self.flags & FLAG_PART_BOUNDARY:
                    lookback = boundary + b"\r\n"
                    self.callback(name, lookback, 0, lookbehind_len)
                elif self.flags & FLAG_LAST_BOUNDARY:
                    lookback = boundary + b"--\r\n"
                    self.callback(name, lookback, 0, lookbehind_len)
                else:  # pragma: no cover (error case)
                    self.logger.warning("Look-back buffer error")

                if end_i > 0:
                    self.callback(name, data, 0, end_i)
            # If we're getting remaining data, we have got all the data we
            # can be certain is not a boundary, leaving only a partial boundary match.
            if remaining:
                self.marks[name] = end_i - length
            else:
                self.marks.pop(name, None)

        # For each byte...
        while i < length:
            c = data[i]

            if state == START:
                # Skip leading newlines
                if c == CR or c == LF:
                    i = data.find(b"-", i)
                    if i == -1:
                        # No boundary candidate in this chunk, so ignore the content after the leading CR/LF.
                        i = length
                        break
                    continue

                # index is used as in index into our boundary.  Set to 0.
                index = 0

                # Move to the next state, but decrement i so that we re-process
                # this character.
                state = START_BOUNDARY
                i -= 1

            elif state == START_BOUNDARY:
                if index == 0 and data.startswith(boundary[2:], i, length):
                    index = boundary_length - 2
                    i += index
                    continue

                # Check to ensure that the last 2 characters in our boundary
                # are CRLF.
                if index == boundary_length - 2:
                    if c == HYPHEN:
                        # Potential empty message.
                        state = END_BOUNDARY
                    elif c != CR:
                        # Error!
                        msg = "Did not find CR at end of boundary (%d)" % (i,)
                        self.logger.warning(msg)
                        raise MultipartParseError(msg, offset=i)

                    index += 1

                elif index == boundary_length - 1:
                    if c != LF:
                        msg = "Did not find LF at end of boundary (%d)" % (i,)
                        self.logger.warning(msg)
                        raise MultipartParseError(msg, offset=i)

                    # The index is now used for indexing into our boundary.
                    index = 0

                    # Callback for the start of a part.
                    self.callback("part_begin")
                    current_header_count = 0
                    current_header_size = 0

                    # Move to the next character and state.
                    state = HEADER_FIELD_START

                else:
                    # Check to ensure our boundary matches
                    if c != boundary[index + 2]:
                        msg = "Expected boundary character %r, got %r at index %d" % (boundary[index + 2], c, index + 2)
                        self.logger.warning(msg)
                        raise MultipartParseError(msg, offset=i)

                    # Increment index into boundary and continue.
                    index += 1

            elif state == HEADER_FIELD_START:
                # Mark the start of a header field here, reset the index, and
                # continue parsing our header field.
                index = 0

                if c != CR:
                    current_header_count += 1
                    if current_header_count > self.max_header_count:
                        raise MultipartParseError("Maximum header count exceeded", offset=i)
                    current_header_size = 0

                # Set a mark of our header field.
                set_mark("header_field")

                # Notify that we're starting a header if the next character is
                # not a CR; a CR at the beginning of the header will cause us
                # to stop parsing headers in the MultipartState.HEADER_FIELD state,
                # below.
                if c != CR:
                    self.callback("header_begin")

                # Move to parsing header fields.
                state = HEADER_FIELD
                i -= 1

            elif state == HEADER_FIELD:
                # If we've reached a CR at the beginning of a header, it means
                # that we've reached the second of 2 newlines, and so there are
                # no more headers to parse.
                if c == CR and index == 0:
                    delete_mark("header_field")
                    state = HEADERS_ALMOST_DONE
                    i += 1
                    continue

                # The field name runs until the colon; jump straight to it and
                # validate the whole span at once instead of byte by byte.
                colon = data.find(b":", i, length)
                end = colon if colon != -1 else length

                # Enforce the size limit before slicing and validating, so an oversized header
                # name fails fast instead of copying and scanning a potentially huge span.
                advance_header_size(end - i if colon == -1 else end - i + 1)

                field = data[i:end]
                if field.translate(None, TOKEN_CHARS):
                    bad = next(b for b in field if b not in TOKEN_CHARS_SET)
                    bad_i = i + field.index(bad)
                    msg = "Found invalid character %r in header at %d" % (bad, bad_i)
                    self.logger.warning(msg)
                    raise MultipartParseError(msg, offset=bad_i)

                index += end - i
                if colon == -1:
                    # Field name continues into the next chunk.
                    i = length
                else:
                    # A 0-length header is an error.
                    if index == 0:
                        msg = "Found 0-length header at %d" % (i,)
                        self.logger.warning(msg)
                        raise MultipartParseError(msg, offset=i)

                    # Call our callback with the header field.
                    i = colon
                    data_callback("header_field", i)

                    # Move to parsing the header value.
                    state = HEADER_VALUE_START

            elif state == HEADER_VALUE_START:
                # Skip leading spaces.
                if c == SPACE:
                    advance_header_size()
                    i += 1
                    continue

                # Mark the start of the header value.
                set_mark("header_value")

                # Move to the header-value state, reprocessing this character.
                state = HEADER_VALUE
                i -= 1

            elif state == HEADER_VALUE:
                # The value runs until the terminating CR; jump straight to it
                # instead of inspecting every byte.
                cr = data.find(b"\r", i, length)
                end = cr if cr != -1 else length
                advance_header_size(end - i)
                if cr != -1:
                    i = cr
                    data_callback("header_value", i)
                    self.callback("header_end")
                    current_header_size = 0
                    state = HEADER_VALUE_ALMOST_DONE
                else:
                    i = length

            elif state == HEADER_VALUE_ALMOST_DONE:
                # The last character should be a LF.  If not, it's an error.
                if c != LF:
                    msg = f"Did not find LF character at end of header (found {c!r})"
                    self.logger.warning(msg)
                    raise MultipartParseError(msg, offset=i)

                # Move back to the start of another header.  Note that if that
                # state detects ANOTHER newline, it'll trigger the end of our
                # headers.
                state = HEADER_FIELD_START

            elif state == HEADERS_ALMOST_DONE:
                # We're almost done our headers.  This is reached when we parse
                # a CR at the beginning of a header, so our next character
                # should be a LF, or it's an error.
                if c != LF:
                    msg = f"Did not find LF at end of headers (found {c!r})"
                    self.logger.warning(msg)
                    raise MultipartParseError(msg, offset=i)

                self.callback("headers_finished")
                state = PART_DATA_START

            elif state == PART_DATA_START:
                # Mark the start of our part data.
                set_mark("part_data")

                # Start processing part data, including this character.
                state = PART_DATA
                i -= 1

            elif state == PART_DATA:
                # We're processing our part data right now.  During this, we
                # need to efficiently search for our boundary, since any data
                # on any number of lines can be a part of the current data.

                # Save the current value of our index.  We use this in case we
                # find part of a boundary, but it doesn't match fully.
                prev_index = index

                # If our index is 0, we're starting a new part, so start our
                # search.
                if index == 0:
                    # The most common case is likely to be that the whole
                    # boundary is present in the buffer.
                    # Calling `find` is much faster than iterating here.
                    i0 = data.find(boundary, i, length)
                    if i0 >= 0:
                        # We matched the whole boundary string.
                        index = boundary_length - 1
                        i = i0 + boundary_length - 1
                        c = data[i]
                    else:
                        # No whole boundary, but the tail may hold a partial one
                        # that completes in the next chunk. Boundary starts with
                        # CR, which an RFC boundary contains nowhere else, so the
                        # last CR in the tail is the only candidate prefix start.
                        k = data.rfind(boundary[:1], max(i, length - boundary_length + 1), length)
                        if k != -1 and boundary.startswith(data[k:length]):
                            index = length - k
                        # Carry the partial via index; the end-of-chunk flush
                        # emits the data before it and re-marks the lookbehind.
                        i = length
                        continue

                # Now, we have a couple of cases here.  If our index is before
                # the end of the boundary...
                if index < boundary_length:
                    # If the character matches...
                    if boundary[index] == c:
                        # The current character matches, so continue!
                        index += 1
                    else:
                        index = 0

                # Our index is equal to the length of our boundary!
                elif index == boundary_length:
                    # First we increment it.
                    index += 1

                    # Now, if we've reached a newline, we need to set this as
                    # the potential end of our boundary.
                    if c == CR:
                        flags |= FLAG_PART_BOUNDARY

                    # Otherwise, if this is a hyphen, we might be at the last
                    # of all boundaries.
                    elif c == HYPHEN:
                        flags |= FLAG_LAST_BOUNDARY

                    # RFC 2046 forbids lines starting with the boundary in a part, so this can't be data.
                    elif c in b" \t":
                        data_callback("part_data", i - boundary_length)
                        delete_mark("part_data")
                        index = 0
                        state = BOUNDARY_PADDING

                    # Otherwise, we reset our index, since this isn't either a
                    # newline or a hyphen.
                    else:
                        index = 0

                # Our index is right after the part boundary, which should be
                # a LF.
                elif index == boundary_length + 1:
                    # If we're at a part boundary (i.e. we've seen a CR
                    # character already)...
                    if flags & FLAG_PART_BOUNDARY:
                        # We need a LF character next.
                        if c == LF:
                            # Unset the part boundary flag.
                            flags &= ~FLAG_PART_BOUNDARY

                            # We have identified a boundary, callback for any data before it.
                            data_callback("part_data", i - index)
                            # Callback indicating that we've reached the end of
                            # a part, and are starting a new one.
                            self.callback("part_end")
                            self.callback("part_begin")
                            current_header_count = 0
                            current_header_size = 0

                            # Move to parsing new headers.
                            index = 0
                            state = HEADER_FIELD_START
                            i += 1
                            continue

                        # We didn't find an LF character, so no match.  Reset
                        # our index and clear our flag.
                        index = 0
                        flags &= ~FLAG_PART_BOUNDARY

                    # Otherwise, if we're at the last boundary (i.e. we've
                    # seen a hyphen already)...
                    elif flags & FLAG_LAST_BOUNDARY:
                        # We need a second hyphen here.
                        if c == HYPHEN:
                            # We have identified a boundary, callback for any data before it.
                            data_callback("part_data", i - index)
                            # Callback to end the current part, and then the
                            # message.
                            self.callback("part_end")
                            self.callback("end")
                            state = END
                        else:
                            # No match, so reset index.
                            index = 0

                # Otherwise, our index is 0.  If the previous index is not, it
                # means we reset something, and we need to take the data we
                # thought was part of our boundary and send it along as actual
                # data.
                if index == 0 and prev_index > 0:
                    # Overwrite our previous index.
                    prev_index = 0

                    # Re-consider the current character, since this could be
                    # the start of the boundary itself.
                    i -= 1

            elif state == BOUNDARY_PADDING:
                if index == 0 and c == CR:
                    index = 1
                elif index == 1 and c == LF:
                    self.callback("part_end")
                    self.callback("part_begin")
                    current_header_count = 0
                    current_header_size = 0
                    index = 0
                    state = HEADER_FIELD_START
                elif index == 1 or c not in b" \t":
                    msg = "Did not find CRLF after boundary padding at %d" % (i,)
                    self.logger.warning(msg)
                    raise MultipartParseError(msg, offset=i)

            elif state == END_BOUNDARY:
                if index == boundary_length - 1:
                    if c != HYPHEN:
                        msg = "Did not find - at end of boundary (%d)" % (i,)
                        self.logger.warning(msg)
                        raise MultipartParseError(msg, offset=i)
                    index += 1
                    self.callback("end")
                    state = END

            elif state == END:
                # Silently discard any epilogue data (RFC 2046 section 5.1.1 allows a CRLF and optional
                # epilogue after the closing boundary). Django and Werkzeug do the same.
                i = length
                break

            else:  # pragma: no cover (error case)
                # We got into a strange state somehow!  Just stop processing.
                msg = "Reached an unknown state %d at %d" % (state, i)
                self.logger.warning(msg)
                raise MultipartParseError(msg, offset=i)

            # Move to the next byte.
            i += 1

        # We call our callbacks with any remaining data.  Note that we pass
        # the 'remaining' flag, which sets the mark back to 0 instead of
        # deleting it, if it's found.  This is because, if the mark is found
        # at this point, we assume that there's data for one of these things
        # that has been parsed, but not yet emitted.  And, as such, it implies
        # that we haven't yet reached the end of this 'thing'.  So, by setting
        # the mark to 0, we cause any data callbacks that take place in future
        # calls to this function to start from the beginning of that buffer.
        data_callback("header_field", length, True)
        data_callback("header_value", length, True)
        data_callback("part_data", length - index, True)

        # Save values to locals.
        self.state = state
        self.index = index
        self.flags = flags
        self._current_header_count = current_header_count
        self._current_header_size = current_header_size

        # Return our data length to indicate no errors, and that we processed
        # all of it.
        return length

    def finalize(self) -> None:
        """Finalize this parser, which signals to that we are finished parsing.

        Note: It does not currently, but in the future, it will verify that we
        are in the final state of the parser (i.e. the end of the multipart
        message is well-formed), and, if not, throw an error.
        """
        # TODO: verify that we're in the state MultipartState.END, otherwise throw an
        # error or otherwise state that we're not finished parsing.
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(boundary={self.boundary!r})"


class FormParser:
    """This class is the all-in-one form parser.  Given all the information
    necessary to parse a form, it will instantiate the correct parser, create
    the proper :class:`Field` and :class:`File` classes to store the data that
    is parsed, and call the two given callbacks with each field and file as
    they become available.

    Args:
        content_type: The Content-Type of the incoming request.  This is used to select the appropriate parser.
        on_field: The callback to call when a field has been parsed and is ready for usage.  See above for parameters.
        on_file: The callback to call when a file has been parsed and is ready for usage.  See above for parameters.
        on_end: An optional callback to call when all fields and files in a request has been parsed.  Can be None.
        boundary: If the request is a multipart/form-data request, this should be the boundary of the request, as given
            in the Content-Type header, as a bytestring.
        file_name: If the request is of type application/octet-stream, then the body of the request will not contain any
            information about the uploaded file.  In such cases, you can provide the file name of the uploaded file
            manually.
        config: Configuration to use for this FormParser.  The default values are taken from the DEFAULT_CONFIG value,
            and then any keys present in this dictionary will overwrite the default values.
    """

    #: This is the default configuration for our form parser.
    #: Note: all file sizes should be in bytes.
    DEFAULT_CONFIG: FormParserConfig = {
        "MAX_BODY_SIZE": float("inf"),
        "MAX_FIELDS": float("inf"),
        "MAX_FIELD_SIZE": float("inf"),
        "MAX_HEADER_COUNT": DEFAULT_MAX_HEADER_COUNT,
        "MAX_HEADER_SIZE": DEFAULT_MAX_HEADER_SIZE,
        "MAX_MEMORY_FILE_SIZE": 1 * 1024 * 1024,
        "UPLOAD_DIR": None,
        "UPLOAD_DELETE_TMP": True,
        "UPLOAD_KEEP_FILENAME": False,
        "UPLOAD_KEEP_EXTENSIONS": False,
        # Error on invalid Content-Transfer-Encoding?
        "UPLOAD_ERROR_ON_BAD_CTE": False,
    }

    def __init__(
        self,
        content_type: str,
        on_field: Callable[[Field], None] | None,
        on_file: Callable[[File], None] | None,
        on_end: Callable[[], None] | None = None,
        boundary: bytes | str | None = None,
        file_name: bytes | None = None,
        config: dict[Any, Any] = {},
    ) -> None:
        self.logger = logging.getLogger(__name__)

        # Save variables.
        self.content_type = content_type
        self.boundary = boundary
        self.bytes_received = 0
        self.parser = None

        # Save callbacks.
        self.on_field = on_field
        self.on_file = on_file
        self.on_end = on_end

        # Set configuration options.
        self.config: FormParserConfig = self.DEFAULT_CONFIG.copy()
        self.config.update(config)  # type: ignore[typeddict-item]

        # Files created by this parser are owned by the parser until a callback
        # completes and the hand-off is recorded explicitly.
        self._pending_files: list[File] = []
        self._disk_budget = _DiskBudget(
            _config_limit(
                self.config,
                "MAX_TOTAL_FILE_SIZE",
                "MAX_TOTAL_UPLOAD_SIZE",
                "MAX_DISK_BUDGET",
                "MAX_DISK_SIZE",
                "MAX_DISK_QUOTA",
                "MAX_TOTAL_DISK_SIZE",
            )
        )
        self._closed = False

        parser: OctetStreamParser | MultipartParser | QuerystringParser | None = None

        # Depending on the Content-Type, we instantiate the correct parser.
        if content_type == "application/octet-stream":
            file: File | None = None

            def on_start() -> None:
                nonlocal file
                file = self._new_file(file_name, None, content_type=None)

            def on_data(data: bytes, start: int, end: int) -> None:
                nonlocal file
                assert file is not None
                file.write(data[start:end])

            def _on_end() -> None:
                nonlocal file
                if file is None:
                    file = self._new_file(file_name, None, content_type=None)
                # Finalize the file itself.
                file.finalize()

                # Only transfer ownership after the callback returns normally.
                self._handoff_file(file)
                file = None

                # Call the on-end callback.
                if self.on_end is not None:
                    self.on_end()

            # Instantiate an octet-stream parser
            parser = OctetStreamParser(
                callbacks={"on_start": on_start, "on_data": on_data, "on_end": _on_end},
                max_size=self.config["MAX_BODY_SIZE"],
            )

        elif content_type == "application/x-www-form-urlencoded" or content_type == "application/x-url-encoded":
            max_fields = self.config["MAX_FIELDS"]
            max_field_size = self.config["MAX_FIELD_SIZE"]
            for key, limit in (("MAX_FIELDS", max_fields), ("MAX_FIELD_SIZE", max_field_size)):
                if not isinstance(limit, (int, float)) or not limit >= 0:
                    raise ValueError(f"{key} must be a non-negative number, not {limit!r}")

            name_buffer: list[bytes] = []
            field_count = 0
            field_size = 0
            f: Field | None = None

            def on_field_start() -> None:
                nonlocal field_count, field_size
                field_count += 1
                if field_count > max_fields:
                    raise FormParserError(f"Too many fields. Maximum number of fields is {max_fields}.")
                field_size = 0

            def on_field_name(data: bytes, start: int, end: int) -> None:
                nonlocal field_size
                field_size += end - start
                if field_size > max_field_size:
                    raise FormParserError(f"Field exceeded maximum size of {max_field_size} bytes.")
                name_buffer.append(data[start:end])

            def on_field_data(data: bytes, start: int, end: int) -> None:
                nonlocal f, field_size
                field_size += end - start
                if field_size > max_field_size:
                    raise FormParserError(f"Field exceeded maximum size of {max_field_size} bytes.")
                if f is None:
                    f = Field(b"".join(name_buffer))
                    del name_buffer[:]
                f.write(data[start:end])

            def on_field_end() -> None:
                nonlocal f
                # Finalize and call callback.
                if f is None:
                    # If we get here, it's because there was no field data.
                    # We create a field, set it to None, and then continue.
                    f = Field(b"".join(name_buffer))
                    del name_buffer[:]
                    f.set_none()

                f.finalize()
                if on_field:
                    on_field(f)
                f = None

            def _on_end() -> None:
                if self.on_end is not None:
                    self.on_end()

            # Instantiate parser.
            parser = QuerystringParser(
                callbacks={
                    "on_field_start": on_field_start,
                    "on_field_name": on_field_name,
                    "on_field_data": on_field_data,
                    "on_field_end": on_field_end,
                    "on_end": _on_end,
                },
                max_size=self.config["MAX_BODY_SIZE"],
            )

        elif content_type == "multipart/form-data":
            if boundary is None:
                self.logger.error("No boundary given")
                raise FormParserError("No boundary given")

            header_name: list[bytes] = []
            header_value: list[bytes] = []
            headers: dict[bytes, bytes] = {}

            f_multi: File | Field | None = None
            writer: File | Field | Base64Decoder | QuotedPrintableDecoder | None = None
            is_file = False

            def on_part_begin() -> None:
                # Reset headers in case this isn't the first part.
                nonlocal headers
                headers = {}

            def on_part_data(data: bytes, start: int, end: int) -> None:
                nonlocal writer
                assert writer is not None
                writer.write(data[start:end])
                # TODO: check for error here.

            def on_part_end() -> None:
                nonlocal f_multi, writer
                assert f_multi is not None
                assert writer is not None
                writer.finalize()
                if is_file:
                    assert isinstance(f_multi, File)
                    self._handoff_file(f_multi)
                else:
                    if on_field:
                        assert isinstance(f_multi, Field)
                        on_field(f_multi)
                f_multi = None
                writer = None

            def on_header_field(data: bytes, start: int, end: int) -> None:
                header_name.append(data[start:end])

            def on_header_value(data: bytes, start: int, end: int) -> None:
                header_value.append(data[start:end])

            def on_header_end() -> None:
                headers[b"".join(header_name).lower()] = b"".join(header_value)
                del header_name[:]
                del header_value[:]

            def on_headers_finished() -> None:
                nonlocal is_file, f_multi, writer
                # Reset the 'is file' flag.
                is_file = False

                # Parse the content-disposition header.
                content_disp = headers.get(b"content-disposition")
                disp, options = parse_options_header(content_disp)

                # Get the field and filename.
                field_name = options.get(b"name")
                file_name = options.get(b"filename")
                # RFC 7578 §4.2: each part MUST have a Content-Disposition header with a "name" parameter.
                if field_name is None:
                    raise FormParserError(f'Field name not found in Content-Disposition: "{content_disp!r}"')

                # Create the proper class.
                content_type_b = headers.get(b"content-type")
                content_type = content_type_b.decode("latin-1") if content_type_b is not None else None
                if file_name is None:
                    f_multi = Field(field_name, content_type=content_type)
                else:
                    f_multi = self._new_file(file_name, field_name, content_type=content_type)
                    is_file = True

                # Parse the given Content-Transfer-Encoding to determine what
                # we need to do with the incoming data.
                # TODO: check that we properly handle 8bit / 7bit encoding.
                # RFC 2045 section 6.1: Content-Transfer-Encoding values are case-insensitive.
                # https://www.rfc-editor.org/rfc/rfc2045#section-6.1
                transfer_encoding = headers.get(b"content-transfer-encoding", b"7bit").lower()

                if transfer_encoding in (b"binary", b"8bit", b"7bit"):
                    writer = f_multi

                elif transfer_encoding == b"base64":
                    writer = Base64Decoder(f_multi)

                elif transfer_encoding == b"quoted-printable":
                    writer = QuotedPrintableDecoder(f_multi)

                else:
                    self.logger.warning("Unknown Content-Transfer-Encoding: %r", transfer_encoding)
                    if self.config["UPLOAD_ERROR_ON_BAD_CTE"]:
                        raise FormParserError(f'Unknown Content-Transfer-Encoding "{transfer_encoding!r}"')
                    else:
                        # If we aren't erroring, then we just treat this as an
                        # unencoded Content-Transfer-Encoding.
                        writer = f_multi

            def _on_end() -> None:
                if self.on_end is not None:
                    self.on_end()

            # Instantiate a multipart parser.
            parser = MultipartParser(
                boundary,
                callbacks={
                    "on_part_begin": on_part_begin,
                    "on_part_data": on_part_data,
                    "on_part_end": on_part_end,
                    "on_header_field": on_header_field,
                    "on_header_value": on_header_value,
                    "on_header_end": on_header_end,
                    "on_headers_finished": on_headers_finished,
                    "on_end": _on_end,
                },
                max_size=self.config["MAX_BODY_SIZE"],
                max_header_count=self.config["MAX_HEADER_COUNT"],
                max_header_size=self.config["MAX_HEADER_SIZE"],
            )

        else:
            self.logger.warning("Unknown Content-Type: %r", content_type)
            raise FormParserError(f"Unknown Content-Type: {content_type}")

        self.parser = parser

    def _new_file(self, file_name: bytes | None, field_name: bytes | None, *, content_type: str | None) -> File:
        file = File._for_parser(
            file_name, field_name, self.config, content_type=content_type, disk_budget=self._disk_budget
        )
        self._pending_files.append(file)
        return file

    def _forget_file(self, file: File) -> None:
        try:
            self._pending_files.remove(file)
        except ValueError:
            pass

    def _handoff_file(self, file: File) -> None:
        """Run the success callback, then explicitly transfer ownership."""
        if self.on_file is None:
            try:
                file._discard()
            finally:
                self._forget_file(file)
            return

        self.on_file(file)
        file.transfer_ownership()
        self._forget_file(file)

    def _cleanup_files(self) -> None:
        files = self._pending_files
        self._pending_files = []
        for file in files:
            try:
                file._discard()
            except BaseException as exc:  # cleanup must never replace the original error
                self.logger.warning("Error cleaning up parser-owned file (%s)", type(exc).__name__)

    def write(self, data: bytes) -> int:
        """Write some data.  The parser will forward this to the appropriate
        underlying parser.

        Args:
            data: The data to write.

        Returns:
            The number of bytes processed.
        """
        self.bytes_received += len(data)
        # TODO: check the parser's return value for errors?
        assert self.parser is not None
        try:
            return self.parser.write(data)
        except BaseException:
            self._cleanup_files()
            raise

    def finalize(self) -> None:
        """Finalize the parser."""
        if self.parser is not None and hasattr(self.parser, "finalize"):
            try:
                self.parser.finalize()
            except BaseException:
                self._cleanup_files()
                raise
        # A truncated body can leave a file that was never handed off.
        self._cleanup_files()

    def close(self) -> None:
        """Close the parser and discard every file that was not handed off.

        This method is idempotent. Files already transferred to the caller are
        deliberately left open.
        """
        if self._closed:
            return
        self._closed = True
        self._cleanup_files()
        if self.parser is not None and hasattr(self.parser, "close"):
            self.parser.close()

    def cancel(self) -> None:
        """Cancel parsing and release all parser-owned resources."""
        self.close()

    def __enter__(self) -> FormParser:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self._cleanup_files()
        except BaseException:
            pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(content_type={self.content_type!r}, parser={self.parser!r})"


def create_form_parser(
    headers: dict[str, bytes],
    on_field: Callable[[Field], None] | None,
    on_file: Callable[[File], None] | None,
    config: dict[Any, Any] = {},
) -> FormParser:
    """This function is a helper function to aid in creating a FormParser
    instances.  Given a dictionary-like headers object, it will determine
    the correct information needed, instantiate a FormParser with the
    appropriate values and given callbacks, and then return the corresponding
    parser.

    Args:
        headers: A dictionary-like object of HTTP headers.  The only required header is Content-Type.
        on_field: Callback to call with each parsed field.
        on_file: Callback to call with each parsed file.
        config: Configuration variables to pass to the FormParser.
    """
    content_type: str | bytes | None = headers.get("Content-Type")
    if content_type is None:
        logging.getLogger(__name__).warning("No Content-Type header given")
        raise ValueError("No Content-Type header given!")

    # Boundaries are optional (the FormParser will raise if one is needed
    # but not given).
    content_type, params = parse_options_header(content_type)
    boundary = params.get(b"boundary")

    # We need content_type to be a string, not a bytes object.
    content_type = content_type.decode("latin-1")

    # Instantiate a form parser.
    form_parser = FormParser(content_type, on_field, on_file, boundary=boundary, config=config)

    # Return our parser.
    return form_parser


def parse_form(
    headers: dict[str, bytes],
    input_stream: SupportsRead,
    on_field: Callable[[Field], None] | None,
    on_file: Callable[[File], None] | None,
    chunk_size: int = 1048576,
) -> None:
    """This function is useful if you just want to parse a request body,
    without too much work.  Pass it a dictionary-like object of the request's
    headers, and a file-like object for the input stream, along with two
    callbacks that will get called whenever a field or file is parsed.

    Args:
        headers: A dictionary-like object of HTTP headers.  The only required header is Content-Type.
        input_stream: A file-like object that represents the request body. The read() method must return bytestrings.
        on_field: Callback to call with each parsed field.
        on_file: Callback to call with each parsed file.
        chunk_size: The maximum size to read from the input stream and write to the parser at one time.
            Defaults to 1 MiB.
    """
    if chunk_size < 1:
        raise ValueError(f"chunk_size must be a positive number, not {chunk_size!r}")

    # Create our form parser.
    parser = create_form_parser(headers, on_field, on_file)

    # Read chunks of 1MiB and write to the parser, but never read more than
    # the given Content-Length, if any.
    content_length: int | float | bytes | None = headers.get("Content-Length")
    if content_length is not None:
        content_length = int(content_length)
        if content_length < 0:
            raise ValueError("Content-Length must be non-negative")
    else:
        content_length = float("inf")
    bytes_read = 0

    try:
        while True:
            # Read only up to the Content-Length given.
            max_readable = int(min(content_length - bytes_read, chunk_size))
            buff = input_stream.read(max_readable)

            # Write to the parser and update our length.
            parser.write(buff)
            bytes_read += len(buff)

            # If we get a buffer that's smaller than the size requested, or if we
            # have read up to our content length, we're done.
            if len(buff) != max_readable or bytes_read == content_length:
                break

        # Tell our parser that we're done writing data.
        parser.finalize()
    finally:
        parser.close()
