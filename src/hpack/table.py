# flake8: noqa
from collections import deque
import logging
import threading
from typing import Optional

from .exceptions import InvalidTableIndex

log = logging.getLogger(__name__)


def table_entry_size(name: bytes, value: bytes) -> int:
    """
    Calculates the size of a single entry

    This size is mostly irrelevant to us and defined
    specifically to accommodate memory management for
    lower level implementations. The 32 extra bytes are
    considered the "maximum" overhead that would be
    required to represent each entry in the table.

    See RFC7541 Section 4.1
    """
    return 32 + len(name) + len(value)


class HeaderTable:
    """
    Implements the combined static and dynamic header table

    The name and value arguments for all the functions
    should ONLY be byte strings (b'') however this is not
    strictly enforced in the interface.

    See RFC7541 Section 2.3
    """
    #: Default maximum size of the dynamic table. See
    #:  RFC7540 Section 6.5.2.
    DEFAULT_SIZE = 4096

    #: Constant list of static headers. See RFC7541 Section
    #:  2.3.1 and Appendix A
    STATIC_TABLE = (
        (b':authority'                  , b''             ),  # noqa
        (b':method'                     , b'GET'          ),  # noqa
        (b':method'                     , b'POST'         ),  # noqa
        (b':path'                       , b'/'            ),  # noqa
        (b':path'                       , b'/index.html'  ),  # noqa
        (b':scheme'                     , b'http'         ),  # noqa
        (b':scheme'                     , b'https'        ),  # noqa
        (b':status'                     , b'200'          ),  # noqa
        (b':status'                     , b'204'          ),  # noqa
        (b':status'                     , b'206'          ),  # noqa
        (b':status'                     , b'304'          ),  # noqa
        (b':status'                     , b'400'          ),  # noqa
        (b':status'                     , b'404'          ),  # noqa
        (b':status'                     , b'500'          ),  # noqa
        (b'accept-charset'              , b''             ),  # noqa
        (b'accept-encoding'             , b'gzip, deflate'),  # noqa
        (b'accept-language'             , b''             ),  # noqa
        (b'accept-ranges'               , b''             ),  # noqa
        (b'accept'                      , b''             ),  # noqa
        (b'access-control-allow-origin' , b''             ),  # noqa
        (b'age'                         , b''             ),  # noqa
        (b'allow'                       , b''             ),  # noqa
        (b'authorization'               , b''             ),  # noqa
        (b'cache-control'               , b''             ),  # noqa
        (b'content-disposition'         , b''             ),  # noqa
        (b'content-encoding'            , b''             ),  # noqa
        (b'content-language'            , b''             ),  # noqa
        (b'content-length'              , b''             ),  # noqa
        (b'content-location'            , b''             ),  # noqa
        (b'content-range'               , b''             ),  # noqa
        (b'content-type'                , b''             ),  # noqa
        (b'cookie'                      , b''             ),  # noqa
        (b'date'                        , b''             ),  # noqa
        (b'etag'                        , b''             ),  # noqa
        (b'expect'                      , b''             ),  # noqa
        (b'expires'                     , b''             ),  # noqa
        (b'from'                        , b''             ),  # noqa
        (b'host'                        , b''             ),  # noqa
        (b'if-match'                    , b''             ),  # noqa
        (b'if-modified-since'           , b''             ),  # noqa
        (b'if-none-match'               , b''             ),  # noqa
        (b'if-range'                    , b''             ),  # noqa
        (b'if-unmodified-since'         , b''             ),  # noqa
        (b'last-modified'               , b''             ),  # noqa
        (b'link'                        , b''             ),  # noqa
        (b'location'                    , b''             ),  # noqa
        (b'max-forwards'                , b''             ),  # noqa
        (b'proxy-authenticate'          , b''             ),  # noqa
        (b'proxy-authorization'         , b''             ),  # noqa
        (b'range'                       , b''             ),  # noqa
        (b'referer'                     , b''             ),  # noqa
        (b'refresh'                     , b''             ),  # noqa
        (b'retry-after'                 , b''             ),  # noqa
        (b'server'                      , b''             ),  # noqa
        (b'set-cookie'                  , b''             ),  # noqa
        (b'strict-transport-security'   , b''             ),  # noqa
        (b'transfer-encoding'           , b''             ),  # noqa
        (b'user-agent'                  , b''             ),  # noqa
        (b'vary'                        , b''             ),  # noqa
        (b'via'                         , b''             ),  # noqa
        (b'www-authenticate'            , b''             ),  # noqa
    )  # noqa

    STATIC_TABLE_LENGTH = len(STATIC_TABLE)

    STATIC_TABLE_MAPPING: dict[bytes, tuple[int, dict[bytes, int]]]

    def __init__(self) -> None:
        self._maxsize = HeaderTable.DEFAULT_SIZE
        self._current_size = 0
        self.resized = False
        self.dynamic_entries: deque[tuple[bytes, bytes]] = deque()
        # Guards every read and mutation of the dynamic table so that concurrent
        # encoders/decoders never observe a partially evicted table.
        self._lock = threading.RLock()

    def get_by_index(self, index: int) -> tuple[bytes, bytes]:
        """
        Returns the entry specified by index

        Note that the table is 1-based ie an index of 0 is
        invalid.  This is due to the fact that a zero value
        index signals that a completely unindexed header
        follows.

        The entry will either be from the static table or
        the dynamic table depending on the value of index.
        """
        original_index = index
        with self._lock:
            index -= 1
            if 0 <= index:
                if index < HeaderTable.STATIC_TABLE_LENGTH:
                    return HeaderTable.STATIC_TABLE[index]

                index -= HeaderTable.STATIC_TABLE_LENGTH
                if index < len(self.dynamic_entries):
                    return self.dynamic_entries[index]

        raise InvalidTableIndex("Invalid table index %d" % original_index)

    def __repr__(self) -> str:
        return "HeaderTable(%d, %s, %r)" % (
            self._maxsize,
            self.resized,
            self.dynamic_entries
        )

    def add(self, name: bytes, value: bytes) -> None:
        """
        Adds a new entry to the table

        We reduce the table size if the entry will make the
        table size greater than maxsize.
        """
        size = table_entry_size(name, value)
        with self._lock:
            # We just clear the table if the entry is too big
            if size > self._maxsize:
                self.dynamic_entries.clear()
                self._current_size = 0
                return

            # Stage the insertion and every eviction it needs on a private
            # copy, then commit the resulting state in a single step so a
            # concurrent reader never sees a partially updated table.
            candidate = deque(self.dynamic_entries)
            candidate.appendleft((name, value))
            candidate_size = self._current_size + size
            candidate_size = self._evict_to_fit(
                candidate, candidate_size, self._maxsize,
            )

            self.dynamic_entries = candidate
            self._current_size = candidate_size

    def search(self, name: bytes, value: bytes) -> Optional[tuple[int, bytes, Optional[bytes]]]:
        """
        Searches the table for the entry specified by name
        and value

        Returns one of the following:
            - ``None``, no match at all
            - ``(index, name, None)`` for partial matches on name only.
            - ``(index, name, value)`` for perfect matches.
        """
        partial = None

        with self._lock:
            header_name_search_result = HeaderTable.STATIC_TABLE_MAPPING.get(name)
            if header_name_search_result:
                index = header_name_search_result[1].get(value)
                if index is not None:
                    return index, name, value
                else:
                    partial = (header_name_search_result[0], name, None)

            offset = HeaderTable.STATIC_TABLE_LENGTH + 1
            for (i, (n, v)) in enumerate(self.dynamic_entries):
                if n == name:
                    if v == value:
                        return i + offset, n, v
                    elif partial is None:
                        partial = (i + offset, n, None)
        return partial

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @maxsize.setter
    def maxsize(self, newmax: int) -> None:
        newmax = int(newmax)
        with self._lock:
            oldmax = self._maxsize
            log.debug("Resizing header table to %d from %d", newmax, oldmax)
            self.resized = (newmax != oldmax)
            if newmax == oldmax:
                return

            # Stage the whole resize on a private copy. Nothing is mutated
            # until the post-resize table is fully computed, so a capacity
            # change either completes entirely or leaves prior state intact.
            candidate = deque(self.dynamic_entries)
            candidate_size = self._current_size

            if newmax <= 0:
                candidate.clear()
                candidate_size = 0
            elif oldmax > newmax:
                candidate_size = self._evict_to_fit(
                    candidate, candidate_size, newmax,
                )

            self._maxsize = newmax
            self.dynamic_entries = candidate
            self._current_size = candidate_size

    def _shrink(self) -> None:
        """
        Shrinks the dynamic table to be at or below maxsize
        """
        with self._lock:
            self._current_size = self._evict_to_fit(
                self.dynamic_entries, self._current_size, self._maxsize,
            )

    @staticmethod
    def _evict_to_fit(
        entries: deque[tuple[bytes, bytes]],
        current_size: int,
        maxsize: int,
    ) -> int:
        """
        Evicts entries from the tail of ``entries`` until the table fits
        ``maxsize`` and returns the resulting size.

        This only touches the state it is given, letting callers stage an
        entire change before committing it atomically.
        """
        while current_size > maxsize and entries:
            name, value = entries.pop()
            current_size -= table_entry_size(name, value)
            log.debug("Evicting %s: %s from the header table", name, value)
        return current_size


def _build_static_table_mapping() -> dict[bytes, tuple[int, dict[bytes, int]]]:
    """
    Build static table mapping from header name to tuple with next structure:
    (<minimal index of header>, <mapping from header value to it index>).

    static_table_mapping used for hash searching.
    """
    static_table_mapping: dict[bytes, tuple[int, dict[bytes, int]]] = {}
    for index, (name, value) in enumerate(HeaderTable.STATIC_TABLE, 1):
        header_name_search_result = static_table_mapping.setdefault(name, (index, {}))
        header_name_search_result[1][value] = index
    return static_table_mapping


HeaderTable.STATIC_TABLE_MAPPING = _build_static_table_mapping()
