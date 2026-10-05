from __future__ import annotations

import bisect
import threading
import time
from collections import Counter, defaultdict
from math import floor
from zoneinfo import ZoneInfo

import limits.typing
from limits.calendar import (
    CalendarWindowUnit,
    calendar_window_key,
    get_calendar_window,
    get_timezone,
)
from limits.storage.base import (
    CalendarWindowSupport,
    MovingWindowSupport,
    SlidingWindowCounterSupport,
    Storage,
    TimestampedSlidingWindow,
)


class Entry:
    def __init__(self, expiry: float, atime: float | None = None) -> None:
        self.atime = time.time() if atime is None else atime
        self.expiry = self.atime + expiry


class MemoryStorage(
    Storage,
    MovingWindowSupport,
    CalendarWindowSupport,
    SlidingWindowCounterSupport,
    TimestampedSlidingWindow,
):
    """
    rate limit storage using :class:`collections.Counter`
    as an in memory storage for fixed and sliding window strategies,
    and a simple list to implement moving window strategy.

    """

    STORAGE_SCHEME = ["memory"]

    def __init__(
        self,
        uri: str | None = None,
        wrap_exceptions: bool = False,
        clock: limits.typing.Callable[[], float] | None = None,
        **_: limits.typing.Any,
    ):
        self.time = clock or time.time
        self.storage: limits.typing.Counter[str] = Counter()
        self.locks: defaultdict[str, threading.RLock] = defaultdict(threading.RLock)
        self.expirations: dict[str, float] = {}
        self.events: dict[str, list[Entry]] = {}
        self._timer_lock = threading.Lock()
        self.timer: threading.Timer = threading.Timer(0.01, self.__expire_events)
        self.timer.start()
        super().__init__(uri, wrap_exceptions=wrap_exceptions, **_)

    def __getstate__(self) -> dict[str, limits.typing.Any]:  # type: ignore[explicit-any]
        state = self.__dict__.copy()
        del state["timer"]
        del state["locks"]
        del state["_timer_lock"]
        return state

    def __setstate__(self, state: dict[str, limits.typing.Any]) -> None:  # type: ignore[explicit-any]
        self.__dict__.update(state)
        self.locks = defaultdict(threading.RLock)
        self._timer_lock = threading.Lock()
        self.timer = threading.Timer(0.01, self.__expire_events)
        self.timer.start()

    def __expire_events(self) -> None:
        now = self.time()
        for key in list(self.events.keys()):
            with self.locks[key]:
                if events := self.events.get(key, []):
                    oldest = bisect.bisect_left(
                        events, -now, key=lambda event: -event.expiry
                    )
                    self.events[key] = self.events[key][:oldest]
                if not self.events.get(key, None):
                    self.locks.pop(key, None)
        for key in list(self.expirations.keys()):
            if self.expirations[key] <= self.time():
                self.storage.pop(key, None)
                self.expirations.pop(key, None)
                self.locks.pop(key, None)

    def __schedule_expiry(self) -> None:
        with self._timer_lock:
            if not self.timer.is_alive():
                self.timer = threading.Timer(0.01, self.__expire_events)
                self.timer.start()

    @property
    def base_exceptions(
        self,
    ) -> type[Exception] | tuple[type[Exception], ...]:  # pragma: no cover
        return ValueError

    def incr(self, key: str, expiry: float, amount: int = 1) -> int:
        """
        increments the counter for a given rate limit key

        :param key: the key to increment
        :param expiry: amount in seconds for the key to expire in
        :param amount: the number to increment by
        """
        self.get(key)
        self.__schedule_expiry()
        with self.locks[key]:
            self.storage[key] += amount
            if self.storage[key] == amount:
                self.expirations[key] = self.time() + expiry
        return self.storage.get(key, 0)

    def decr(self, key: str, amount: int = 1) -> int:
        """
        decrements the counter for a given rate limit key

        :param key: the key to decrement
        :param amount: the number to decrement by
        """
        self.get(key)
        self.__schedule_expiry()
        with self.locks[key]:
            self.storage[key] = max(self.storage[key] - amount, 0)

        return self.storage.get(key, 0)

    def get(self, key: str) -> int:
        """
        :param key: the key to get the counter value for
        """

        if self.expirations.get(key, 0) <= self.time():
            self.storage.pop(key, None)
            self.expirations.pop(key, None)
            self.locks.pop(key, None)

        return self.storage.get(key, 0)

    def clear(self, key: str) -> None:
        """
        :param key: the key to clear rate limits for
        """
        self.storage.pop(key, None)
        self.expirations.pop(key, None)
        self.events.pop(key, None)
        self.locks.pop(key, None)

    def acquire_entry(self, key: str, limit: int, expiry: int, amount: int = 1) -> bool:
        """
        :param key: rate limit key to acquire an entry in
        :param limit: amount of entries allowed
        :param expiry: expiry of the entry
        :param amount: the number of entries to acquire
        """
        if amount > limit:
            return False

        self.__schedule_expiry()
        with self.locks[key]:
            self.events.setdefault(key, [])
            timestamp = self.time()
            try:
                entry = self.events[key][limit - amount]
            except IndexError:
                entry = None

            if entry and entry.atime >= timestamp - expiry:
                return False
            else:
                self.events[key][:0] = [Entry(expiry, timestamp)] * amount
                return True

    def get_expiry(self, key: str) -> float:
        """
        :param key: the key to get the expiry for
        """

        return self.expirations.get(key, self.time())

    def get_moving_window(self, key: str, limit: int, expiry: int) -> tuple[float, int]:
        """
        returns the starting point and the number of entries in the moving
        window

        :param key: rate limit key
        :param expiry: expiry of entry
        :return: (start of window, number of acquired entries)
        """
        timestamp = self.time()
        if events := self.events.get(key, []):
            oldest = bisect.bisect_left(
                events, -(timestamp - expiry), key=lambda entry: -entry.atime
            )
            return events[oldest - 1].atime, oldest
        return timestamp, 0

    def acquire_sliding_window_entry(
        self,
        key: str,
        limit: int,
        expiry: int,
        amount: int = 1,
    ) -> bool:
        if amount > limit:
            return False
        now = self.time()
        previous_key, current_key = self.sliding_window_keys(key, expiry, now)
        (
            previous_count,
            previous_ttl,
            current_count,
            _,
        ) = self._get_sliding_window_info(previous_key, current_key, expiry, now)
        weighted_count = previous_count * previous_ttl / expiry + current_count
        if floor(weighted_count) + amount > limit:
            return False
        else:
            # Hit, increase the current counter.
            # If the counter doesn't exist yet, set twice the theorical expiry.
            current_count = self.incr(current_key, 2 * expiry, amount=amount)
            weighted_count = previous_count * previous_ttl / expiry + current_count
            if floor(weighted_count) > limit:
                # Another hit won the race condition: revert the incrementation and refuse this hit
                # Limitation: during high concurrency at the end of the window,
                # the counter is shifted and cannot be decremented, so less requests than expected are allowed.
                self.decr(current_key, amount)
                return False
            return True

    def _get_sliding_window_info(
        self,
        previous_key: str,
        current_key: str,
        expiry: int,
        now: float,
    ) -> tuple[int, float, int, float]:
        previous_count = self.get(previous_key)
        current_count = self.get(current_key)
        if previous_count == 0:
            previous_ttl = float(0)
        else:
            previous_ttl = (1 - (((now - expiry) / expiry) % 1)) * expiry
        current_ttl = (1 - ((now / expiry) % 1)) * expiry + expiry
        return previous_count, previous_ttl, current_count, current_ttl

    def get_sliding_window(
        self, key: str, expiry: int
    ) -> tuple[int, float, int, float]:
        now = self.time()
        previous_key, current_key = self.sliding_window_keys(key, expiry, now)
        return self._get_sliding_window_info(previous_key, current_key, expiry, now)

    def clear_sliding_window(self, key: str, expiry: int) -> None:
        now = self.time()
        previous_key, current_key = self.sliding_window_keys(key, expiry, now)
        self.clear(previous_key)
        self.clear(current_key)

    def incr_calendar_window(
        self,
        key: str,
        unit: CalendarWindowUnit,
        timezone: str | ZoneInfo,
        amount: int = 1,
    ) -> tuple[float, float, int]:
        zone = get_timezone(timezone)
        self.__schedule_expiry()
        with self.locks[key]:
            now = self.time()
            start, end = get_calendar_window(now, zone, unit)
            window_key = calendar_window_key(key, start, zone, unit)
            current_count = self.get(window_key)
            self.storage[window_key] += amount
            if current_count == 0:
                self.expirations[window_key] = end
            return start, end, self.storage[window_key]

    def get_calendar_window(
        self, key: str, unit: CalendarWindowUnit, timezone: str | ZoneInfo
    ) -> tuple[float, float, int]:
        zone = get_timezone(timezone)
        now = self.time()
        start, end = get_calendar_window(now, zone, unit)
        window_key = calendar_window_key(key, start, zone, unit)
        return start, end, self.get(window_key)

    def clear_calendar_window(
        self, key: str, unit: CalendarWindowUnit, timezone: str | ZoneInfo
    ) -> None:
        zone = get_timezone(timezone)
        now = self.time()
        start, _ = get_calendar_window(now, zone, unit)
        self.clear(calendar_window_key(key, start, zone, unit))

    def check(self) -> bool:
        """
        check if storage is healthy
        """

        return True

    def reset(self) -> int | None:
        num_items = max(len(self.storage), len(self.events))
        self.storage.clear()
        self.expirations.clear()
        self.events.clear()
        self.locks.clear()
        return num_items
