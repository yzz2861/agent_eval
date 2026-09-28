from peewee import JOIN
from peewee import CharField
from peewee import FloatField
from peewee import IntegerField
from peewee import asof_join

from .base import ModelTestCase
from .base import TestModel
from .base import db


class Trade(TestModel):
    symbol = CharField()
    ts = IntegerField()
    side = CharField()


class Quote(TestModel):
    symbol = CharField()
    ts = IntegerField()
    px = FloatField()


class TestAsofJoin(ModelTestCase):
    requires = [Trade, Quote]

    def setUp(self):
        super(TestAsofJoin, self).setUp()
        Quote.insert_many([
            ('A', 100, 10.0),
            ('A', 105, 11.0),
            ('A', 105, 11.5),  # Same timestamp as previous row.
            ('A', 130, 13.0),
            ('B', 100, 20.0),
            ('B', 140, 24.0),
        ]).execute()
        Trade.insert_many([
            ('A', 105, 's1'),
            ('A', 120, 's2'),
            ('A', 106, 's3'),
            ('C', 100, 's4'),  # No quotes for group C.
            ('B', 150, 's5'),
        ]).execute()

    def _query(self, right=None, **kwargs):
        right = right or Quote
        on = asof_join(Trade.ts, right.ts,
                       group=[(right.symbol, Trade.symbol)],
                       tiebreaker=right.id, **kwargs)
        return (Trade
                .select(Trade.side, right.px)
                .join(right, JOIN.LEFT_OUTER, on=on)
                .order_by(Trade.id))

    def test_backward_asof(self):
        rows = list(self._query().dicts())
        self.assertEqual(rows, [
            {'side': 's1', 'px': 11.5},  # ts=105 tie, larger id wins.
            {'side': 's2', 'px': 11.5},  # Nearest <= 120 is ts=105.
            {'side': 's3', 'px': 11.5},
            {'side': 's4', 'px': None},  # Unmatched left row preserved.
            {'side': 's5', 'px': 24.0},
        ])

    def test_disallow_equal(self):
        rows = list(self._query(allow_equal=False).dicts())
        self.assertEqual(rows, [
            {'side': 's1', 'px': 10.0},  # ts=105 excluded, falls to 100.
            {'side': 's2', 'px': 11.5},
            {'side': 's3', 'px': 11.5},
            {'side': 's4', 'px': None},
            {'side': 's5', 'px': 24.0},
        ])

    def test_forward_direction(self):
        rows = list(self._query(direction='forward').dicts())
        self.assertEqual(rows, [
            {'side': 's1', 'px': 11.5},  # ts=105 tie, larger id wins.
            {'side': 's2', 'px': 13.0},  # Nearest >= 120 is ts=130.
            {'side': 's3', 'px': 13.0},
            {'side': 's4', 'px': None},
            {'side': 's5', 'px': None},  # No quote at or after ts=150.
        ])

    def test_tolerance(self):
        rows = list(self._query(tolerance=10).dicts())
        self.assertEqual(rows, [
            {'side': 's1', 'px': 11.5},  # ts=105 within 10 of 105.
            {'side': 's2', 'px': None},  # ts=105 is 15 away, excluded.
            {'side': 's3', 'px': 11.5},
            {'side': 's4', 'px': None},
            {'side': 's5', 'px': 24.0},  # ts=140 within 10 of 150.
        ])

    def test_tolerance_is_bound_parameter(self):
        query = self._query(tolerance=10)
        sql, params = query.sql()
        self.assertEqual(params, [10, 10])
        self.assertNotIn(' 10', sql)

    def test_composable_filter_and_order(self):
        query = (self._query()
                 .where(Trade.symbol == 'A')
                 .order_by(Trade.ts.desc()))
        rows = list(query.dicts())
        self.assertEqual(rows, [
            {'side': 's2', 'px': 11.5},
            {'side': 's3', 'px': 11.5},
            {'side': 's1', 'px': 11.5},
        ])

    def test_model_alias(self):
        QA = Quote.alias()
        rows = list(self._query(right=QA).dicts())
        self.assertEqual(rows, [
            {'side': 's1', 'px': 11.5},
            {'side': 's2', 'px': 11.5},
            {'side': 's3', 'px': 11.5},
            {'side': 's4', 'px': None},
            {'side': 's5', 'px': 24.0},
        ])

    def test_filter_on_joined_field(self):
        # The query remains composable: filters on the joined model's
        # columns can be applied after the ASOF join.
        rows = list(self._query().where(Quote.px < 20).dicts())
        self.assertEqual(rows, [
            {'side': 's1', 'px': 11.5},
            {'side': 's2', 'px': 11.5},
            {'side': 's3', 'px': 11.5},
        ])

    def test_requires_tiebreaker(self):
        with self.assertRaisesCtx(ValueError):
            asof_join(Trade.ts, Quote.ts)

    def test_invalid_direction(self):
        with self.assertRaisesCtx(ValueError):
            asof_join(Trade.ts, Quote.ts, direction='sideways',
                      tiebreaker=Quote.id)

    def test_invalid_group(self):
        with self.assertRaisesCtx(ValueError):
            asof_join(Trade.ts, Quote.ts, group=[Quote.symbol == Trade.symbol],
                      tiebreaker=Quote.id)
