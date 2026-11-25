"""Unit tests for the RangeGate / GuardedFile read enforcement."""

import io
import unittest

from oletools.custody.errors import AccessDeniedError
from oletools.custody.guard import GuardedFile, RangeGate


class TestRangeGate(unittest.TestCase):

    def test_empty_gate_denies_everything(self):
        gate = RangeGate.deny_all()
        self.assertEqual(gate.ranges, ())
        self.assertFalse(gate.is_allowed(0, 1))

    def test_ranges_are_merged_and_sorted(self):
        gate = RangeGate(((10, 20), (0, 5), (18, 25)))
        self.assertEqual(gate.ranges, ((0, 5), (10, 25)))

    def test_partial_overlap_is_denied(self):
        gate = RangeGate(((10, 20),))
        self.assertTrue(gate.is_allowed(10, 10))
        self.assertFalse(gate.is_allowed(15, 10))
        self.assertFalse(gate.is_allowed(9, 2))

    def test_dict_round_trip(self):
        gate = RangeGate(((2, 4), (8, 9)))
        self.assertEqual(RangeGate.from_dict(gate.to_dict()), gate)

    def test_invalid_ranges_are_rejected(self):
        with self.assertRaises(ValueError):
            RangeGate(((5, 4),))
        with self.assertRaises(ValueError):
            RangeGate(((-1, 2),))


class TestGuardedFile(unittest.TestCase):

    def setUp(self):
        self.stream = io.BytesIO(b'0123456789abcdef')

    def test_read_inside_range(self):
        guarded = GuardedFile(self.stream, RangeGate(((2, 6),)))
        self.assertEqual(guarded.read_range(2, 4), b'2345')

    def test_read_outside_range_raises_without_returning_bytes(self):
        guarded = GuardedFile(self.stream, RangeGate(((0, 4),)))
        with self.assertRaises(AccessDeniedError):
            guarded.read_range(4, 4)
        # No byte was returned by the denied read; an in-range read still
        # works and returns the correct content.
        self.assertEqual(guarded.read_range(0, 2), b'01')

    def test_unbounded_read_is_forbidden(self):
        guarded = GuardedFile(self.stream, RangeGate.allow_all(16))
        with self.assertRaises(AccessDeniedError):
            guarded.read()

    def test_adjacent_ranges_do_not_leak(self):
        guarded = GuardedFile(self.stream, RangeGate(((4, 8),)))
        with self.assertRaises(AccessDeniedError):
            guarded.read_range(8, 1)
        with self.assertRaises(AccessDeniedError):
            guarded.read_range(3, 1)

    def test_seek_beyond_gate_then_read_fails(self):
        guarded = GuardedFile(self.stream, RangeGate(((0, 2),)))
        guarded.seek(10)
        with self.assertRaises(AccessDeniedError):
            guarded.read(1)


if __name__ == '__main__':
    unittest.main()
