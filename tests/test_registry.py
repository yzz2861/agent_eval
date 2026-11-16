# -*- coding: utf-8 -*-

from __future__ import absolute_import

import threading

import pytest

import filetype
from filetype.match import match_all
from filetype.registry import TypeRegistry
from filetype.types import TYPES, Type


class PrivateType(Type):
    """Custom matcher used by the dynamic registration tests."""

    MIME = 'application/x-private'
    EXTENSION = 'xpriv'

    def __init__(self, magic=b'\x99\x88\x77'):
        super(PrivateType, self).__init__(
            mime=PrivateType.MIME,
            extension=PrivateType.EXTENSION
        )
        self._magic = magic

    def match(self, buf):
        return len(buf) >= len(self._magic) and buf[:len(self._magic)] == \
            self._magic


class JpegOverride(Type):
    """Business-side override of the baseline image/jpeg matcher."""

    MIME = 'image/x-risk-jpeg'
    EXTENSION = 'rjpg'

    def __init__(self):
        super(JpegOverride, self).__init__(
            mime=JpegOverride.MIME,
            extension=JpegOverride.EXTENSION
        )

    def match(self, buf):
        return (len(buf) > 2 and
                buf[0] == 0xFF and
                buf[1] == 0xD8 and
                buf[2] == 0xFF)


class AnotherJpegOverride(Type):
    """Second matcher colliding on the JPEG magic bytes."""

    MIME = 'image/x-alt-jpeg'
    EXTENSION = 'ajpg'

    def __init__(self):
        super(AnotherJpegOverride, self).__init__(
            mime=AnotherJpegOverride.MIME,
            extension=AnotherJpegOverride.EXTENSION
        )

    def match(self, buf):
        return (len(buf) > 2 and
                buf[0] == 0xFF and
                buf[1] == 0xD8 and
                buf[2] == 0xFF)


JPEG_BUF = bytearray([0xFF, 0xD8, 0xFF, 0x00, 0x08])


@pytest.fixture(autouse=True)
def clean_registry():
    filetype.reset_types()
    yield
    filetype.reset_types()


def test_baseline_types_are_restored_on_reset():
    registry = TypeRegistry()
    baseline = list(TYPES)

    registry.add_type(PrivateType())
    assert TYPES[0].mime == PrivateType.MIME

    registry.reset()
    assert list(TYPES) == baseline


def test_register_and_unregister_private_type():
    private = PrivateType()

    assert filetype.guess(bytearray(b'\x99\x88\x77\x00')) is None

    filetype.register_type(private)
    kind = filetype.guess(bytearray(b'\x99\x88\x77\x00'))
    assert kind is private
    assert filetype.guess_mime(bytearray(b'\x99\x88\x77\x00')) == \
        'application/x-private'
    assert filetype.guess_extension(bytearray(b'\x99\x88\x77\x00')) == \
        'xpriv'

    removed = filetype.unregister_type(instance=private)
    assert removed is private
    assert filetype.guess(bytearray(b'\x99\x88\x77\x00')) is None


def test_unregister_by_mime_and_extension():
    filetype.register_type(PrivateType())

    assert filetype.unregister_type(mime='application/x-private') is not None
    assert filetype.unregister_type(mime='application/x-private') is None

    filetype.register_type(PrivateType())
    assert filetype.unregister_type(extension='xpriv') is not None
    assert filetype.unregister_type(extension='xpriv') is None


def test_unregister_requires_an_identifier():
    with pytest.raises(TypeError):
        filetype.unregister_type()


def test_register_rejects_invalid_instance():
    with pytest.raises(TypeError):
        filetype.register_type(object())


def test_priority_overrides_baseline_mime():
    override = JpegOverride()

    assert filetype.guess_mime(JPEG_BUF) == 'image/jpeg'

    filetype.register_type(override, priority=10)
    try:
        assert filetype.guess(JPEG_BUF) is override
        assert filetype.guess_mime(JPEG_BUF) == 'image/x-risk-jpeg'
        assert filetype.guess_extension(JPEG_BUF) == 'rjpg'
    finally:
        filetype.unregister_type(instance=override)

    assert filetype.guess_mime(JPEG_BUF) == 'image/jpeg'


def test_priority_decides_duplicate_magic_conflict():
    low = AnotherJpegOverride()
    high = JpegOverride()

    filetype.register_type(low, priority=1)
    filetype.register_type(high, priority=5)

    assert filetype.guess(JPEG_BUF) is high

    filetype.unregister_type(instance=high)
    assert filetype.guess(JPEG_BUF) is low


def test_same_priority_keeps_legacy_head_insertion_order():
    first = AnotherJpegOverride()
    second = JpegOverride()

    filetype.register_type(first)
    filetype.register_type(second)

    assert filetype.guess(JPEG_BUF) is second


def test_reregistering_equivalent_matcher_updates_priority():
    registry = TypeRegistry()
    first = PrivateType()
    second = PrivateType()

    registry.add_type(first, priority=1)
    registry.add_type(second, priority=2)

    custom = registry.custom_types()
    assert custom == [second]
    assert TYPES[0] is second


def test_duplicate_magic_is_reported_as_polyglot():
    override = JpegOverride()
    filetype.register_type(override, priority=10)

    matches = match_all(JPEG_BUF)
    assert override in matches
    assert any(kind.mime == 'image/jpeg' for kind in matches)
    assert len(matches) >= 2

    result = filetype.guess_info(JPEG_BUF)
    assert result.polyglot is True
    assert result.kind is override
    assert result.mime == 'image/x-risk-jpeg'
    assert result.extension == 'rjpg'
    assert result.matches == matches
    assert result.confidence == pytest.approx(1.0 / len(matches))
    assert bool(result) is True

    mime_result = filetype.guess_mime_info(JPEG_BUF)
    ext_result = filetype.guess_extension_info(JPEG_BUF)
    assert mime_result == result
    assert ext_result == result


def test_unique_match_has_full_confidence():
    result = filetype.guess_info(JPEG_BUF)
    assert result.polyglot is False
    assert result.confidence == 1.0
    assert result.mime == 'image/jpeg'
    assert result.extension == 'jpg'
    assert bool(result) is True


def test_no_match_result_is_empty():
    result = filetype.guess_info(bytearray([0x00, 0x01, 0x02, 0x03]))
    assert result.kind is None
    assert result.mime is None
    assert result.extension is None
    assert result.matches == []
    assert result.polyglot is False
    assert result.confidence == 1.0
    assert bool(result) is False
    assert filetype.guess_all(bytearray([0x00, 0x01, 0x02])) == []


def test_registered_type_context_manager():
    private = PrivateType()
    buf = bytearray(b'\x99\x88\x77\x00')

    with filetype.registered_type(private, priority=3):
        assert filetype.guess(buf) is private

    assert filetype.guess(buf) is None

    with pytest.raises(RuntimeError):
        with filetype.registered_type(PrivateType()):
            raise RuntimeError('boom')
    assert filetype.guess(buf) is None


def test_concurrent_registration_is_thread_safe():
    registry = TypeRegistry()
    thread_count = 16
    iterations = 200
    barrier = threading.Barrier(thread_count)
    errors = []

    def worker(worker_id):
        try:
            barrier.wait()
            for index in range(iterations):
                matcher = PrivateType(
                    magic=bytes([0x70, worker_id, index % 256]))
                registry.add_type(matcher, priority=index)
                snapshot = registry.snapshot()
                # The effective list must stay internally consistent:
                # no duplicates, every element is a Type instance.
                assert len(snapshot) == len(set(id(kind) for kind in
                                                snapshot))
                assert all(isinstance(kind, Type) for kind in snapshot)
                registry.remove_type(instance=matcher)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert registry.custom_types() == []


def test_concurrent_guesses_never_observe_corrupt_state():
    registry = TypeRegistry()
    stop = threading.Event()
    errors = []

    def registrar():
        index = 0
        while not stop.is_set():
            matcher = PrivateType()
            registry.add_type(matcher, priority=index % 5)
            registry.remove_type(instance=matcher)
            index += 1

    def guesser():
        try:
            while not stop.is_set():
                filetype.guess(JPEG_BUF)
                filetype.guess_info(JPEG_BUF)
                match_all(JPEG_BUF)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=registrar)]
    threads += [threading.Thread(target=guesser) for _ in range(4)]
    for thread in threads:
        thread.start()

    stop.wait(1.0)
    stop.set()
    for thread in threads:
        thread.join()

    assert errors == []
    assert filetype.guess_mime(JPEG_BUF) == 'image/jpeg'


def test_legacy_add_type_still_works():
    private = PrivateType()
    filetype.add_type(private)

    assert filetype.guess(bytearray(b'\x99\x88\x77\x00')) is private

    filetype.reset_types()
    assert filetype.guess(bytearray(b'\x99\x88\x77\x00')) is None
