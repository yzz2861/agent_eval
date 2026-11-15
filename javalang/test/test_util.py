import unittest

from ..util import LookAheadIterator
from ..tokenizer import Position, PositionTracker


class TestPositionTracker(unittest.TestCase):
    def test_line_and_column_start_at_one(self):
        tracker = PositionTracker("abc")
        self.assertEqual(tracker.position(), Position(line=1, column=1))
        self.assertEqual(tracker.position_at(2), Position(line=1, column=3))

    def test_crlf_is_a_single_line_break(self):
        data = "a\r\nb"
        positions = [PositionTracker(data).position_at(i) for i in range(4)]
        self.assertEqual(positions, [
            Position(line=1, column=1),
            Position(line=1, column=2),
            Position(line=2, column=1),
            Position(line=2, column=1),
        ])
        self.assertEqual(PositionTracker(data).position_after(3), Position(line=2, column=2))

    def test_lone_carriage_return_is_a_line_break(self):
        tracker = PositionTracker("a\rb")
        self.assertEqual(tracker.position_at(2), Position(line=2, column=1))

    def test_tab_is_one_column(self):
        tracker = PositionTracker("\ta")
        self.assertEqual(tracker.position_at(1), Position(line=1, column=2))

    def test_surrogate_pair_is_one_code_point_column(self):
        data = u"a\U0001F600b"
        self.assertEqual(PositionTracker(data).position_at(0), Position(line=1, column=1))
        self.assertEqual(PositionTracker(data).position_at(1), Position(line=1, column=2))
        self.assertEqual(PositionTracker(data).position_at(2), Position(line=1, column=3))
        self.assertEqual(PositionTracker(data).position_at(3), Position(line=1, column=4))

    def test_position_after_end_of_input(self):
        tracker = PositionTracker("ab")
        self.assertEqual(tracker.position_after(2), Position(line=1, column=3))

    def test_mark_and_reset(self):
        tracker = PositionTracker("a\nb")
        tracker.advance_to(2)
        tracker.mark()
        tracker.advance_to(3)
        tracker.reset()
        self.assertEqual(tracker.position(), Position(line=2, column=1))


class TestLookAheadIterator(unittest.TestCase):
    def test_usage(self):
        i = LookAheadIterator(list(range(0, 10000)))

        self.assertEqual(next(i), 0)
        self.assertEqual(next(i), 1)
        self.assertEqual(next(i), 2)

        self.assertEqual(i.last(), 2)

        self.assertEqual(i.look(), 3)
        self.assertEqual(i.last(), 3)

        self.assertEqual(i.look(1), 4)
        self.assertEqual(i.look(2), 5)
        self.assertEqual(i.look(3), 6)
        self.assertEqual(i.look(4), 7)

        self.assertEqual(i.last(), 7)

        i.push_marker()
        self.assertEqual(next(i), 3)
        self.assertEqual(next(i), 4)
        self.assertEqual(next(i), 5)
        i.pop_marker(True) # reset

        self.assertEqual(i.look(), 3)
        self.assertEqual(next(i), 3)

        i.push_marker() #1
        self.assertEqual(next(i), 4)
        self.assertEqual(next(i), 5)
        i.push_marker() #2
        self.assertEqual(next(i), 6)
        self.assertEqual(next(i), 7)
        i.push_marker() #3
        self.assertEqual(next(i), 8)
        self.assertEqual(next(i), 9)
        i.pop_marker(False) #3
        self.assertEqual(next(i), 10)
        i.pop_marker(True) #2
        self.assertEqual(next(i), 6)
        self.assertEqual(next(i), 7)
        self.assertEqual(next(i), 8)
        i.pop_marker(False) #1
        self.assertEqual(next(i), 9)

        try:
            with i:
                self.assertEqual(next(i), 10)
                self.assertEqual(next(i), 11)
                raise Exception()
        except:
            self.assertEqual(next(i), 10)
            self.assertEqual(next(i), 11)

        with i:
            self.assertEqual(next(i), 12)
            self.assertEqual(next(i), 13)
        self.assertEqual(next(i), 14)


if __name__=="__main__":
    unittest.main()
