# -*- coding: utf-8 -*-

from __future__ import absolute_import

import threading
from contextlib import contextmanager

from .types import TYPES, Type


class TypeRegistry(object):
    """
    Thread-safe registry of file type matchers.

    The matchers shipped with the library are treated as the immutable
    baseline. Custom matchers can be registered at runtime with an explicit
    priority, which also allows overriding a baseline MIME type or file
    extension without editing the library source code.

    The shared ``filetype.types.TYPES`` list is always rebuilt in place, so
    every module holding a reference to it (matchers, helpers, ...) observes
    the same effective matcher set.
    """

    def __init__(self, baseline=TYPES):
        self._lock = threading.RLock()
        self._baseline = list(baseline)
        # Each entry: (matcher, priority, sequence)
        self._custom = []
        self._sequence = 0
        self._rebuild()

    def _rebuild(self):
        ordered = sorted(
            self._custom,
            key=lambda entry: (-entry[1], -entry[2])
        )
        effective = [entry[0] for entry in ordered] + list(self._baseline)

        del TYPES[:]
        TYPES.extend(effective)
        return list(TYPES)

    def snapshot(self):
        """
        Returns a stable copy of the currently effective matcher list.

        Iterating over the snapshot is safe even if another thread mutates
        the registry concurrently.
        """
        with self._lock:
            return list(TYPES)

    def add_type(self, instance, priority=0):
        """
        Registers a custom type matcher.

        Higher ``priority`` values are matched first. Matchers sharing the
        same priority keep most-recently-registered-first semantics, matching
        the legacy ``add_type`` behavior of inserting at the head.

        Re-registering an equivalent matcher (same identity or same MIME and
        extension) updates its priority instead of inserting a duplicate.

        Args:
            instance: Type inherited instance.
            priority: integer priority, higher wins. Defaults to 0.

        Returns:
            The registered matcher instance.
        """
        if not isinstance(instance, Type):
            raise TypeError('instance must inherit from filetype.types.Type')
        if not isinstance(priority, int):
            raise TypeError('priority must be an integer')

        with self._lock:
            for index, (matcher, _priority, sequence) in enumerate(
                    self._custom):
                if matcher is instance or (
                        matcher.mime == instance.mime and
                        matcher.extension == instance.extension):
                    self._custom[index] = (instance, priority, sequence)
                    self._rebuild()
                    return instance

            self._sequence += 1
            self._custom.append((instance, priority, self._sequence))
            self._rebuild()
            return instance

    def remove_type(self, instance=None, mime=None, extension=None):
        """
        Removes a previously registered custom matcher.

        The matcher can be identified by instance, MIME type or extension.
        Baseline matchers shipped with the library cannot be removed; use
        :func:`add_type` with a higher priority to override them instead.

        Args:
            instance: exact matcher instance to remove.
            mime: MIME type of the matcher to remove.
            extension: file extension of the matcher to remove.

        Returns:
            The removed matcher instance. Otherwise None.
        """
        if instance is None and mime is None and extension is None:
            raise TypeError(
                'one of instance, mime or extension is required')

        with self._lock:
            for index, (matcher, _priority, _sequence) in enumerate(
                    self._custom):
                if ((instance is not None and matcher is instance) or
                        (mime is not None and matcher.mime == mime) or
                        (extension is not None and
                         matcher.extension == extension)):
                    del self._custom[index]
                    self._rebuild()
                    return matcher
            return None

    def reset(self):
        """
        Removes every custom matcher, restoring the baseline matchers
        shipped with the library.
        """
        with self._lock:
            self._custom = []
            self._rebuild()

    def custom_types(self):
        """
        Returns a copy of the currently registered custom matchers,
        ordered by effective match priority.
        """
        with self._lock:
            ordered = sorted(
                self._custom,
                key=lambda entry: (-entry[1], -entry[2])
            )
            return [entry[0] for entry in ordered]

    @contextmanager
    def registered_type(self, instance, priority=0):
        """
        Context manager registering a matcher for the duration of a
        ``with`` block and removing it afterwards, even on exceptions.
        """
        self.add_type(instance, priority=priority)
        try:
            yield instance
        finally:
            self.remove_type(instance=instance)


# Process-wide default registry used by the public package API.
registry = TypeRegistry()
