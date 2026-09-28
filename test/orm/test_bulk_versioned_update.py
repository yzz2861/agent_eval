import sqlalchemy as sa
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session
from sqlalchemy.orm import VersionedUpdateResult
from sqlalchemy.orm import VersionedUpdateStatus
from sqlalchemy.testing import config
from sqlalchemy.testing import eq_
from sqlalchemy.testing import expect_raises
from sqlalchemy.testing import fixtures
from sqlalchemy.testing.assertions import assert_raises_message
from sqlalchemy.testing.fixtures import fixture_session
from sqlalchemy.testing.schema import Column
from sqlalchemy.testing.schema import Table


class BulkVersionedUpdateTest(fixtures.MappedTest):
    __requires__ = ("sane_rowcount",)

    run_create_tables = "each"

    @classmethod
    def define_tables(cls, metadata):
        Table(
            "item",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("version_id", Integer, nullable=False),
            Column("name", String(50), nullable=False),
        )
        Table(
            "composite_item",
            metadata,
            Column("id1", Integer, primary_key=True),
            Column("id2", Integer, primary_key=True),
            Column("version_id", Integer, nullable=False),
            Column("name", String(50)),
        )
        Table(
            "plain",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("name", String(50)),
        )

    @classmethod
    def setup_classes(cls):
        class Item(cls.Comparable):
            pass

        class CompositeItem(cls.Comparable):
            pass

        class Plain(cls.Comparable):
            pass

    @classmethod
    def setup_mappers(cls):
        Item, CompositeItem, Plain = cls.classes(
            "Item", "CompositeItem", "Plain"
        )
        cls.mapper_registry.map_imperatively(
            Item,
            cls.tables.item,
            version_id_col=cls.tables.item.c.version_id,
        )
        cls.mapper_registry.map_imperatively(
            CompositeItem,
            cls.tables.composite_item,
            version_id_col=cls.tables.composite_item.c.version_id,
        )
        cls.mapper_registry.map_imperatively(Plain, cls.tables.plain)

    def _seed_items(self, session):
        Item = self.classes.Item
        session.add_all(
            [
                Item(id=1, version_id=1, name="a"),
                Item(id=2, version_id=1, name="b"),
                Item(id=3, version_id=1, name="c"),
            ]
        )
        session.commit()

    def _rows(self, session, table=None):
        table = self.tables.item if table is None else table
        return session.execute(
            sa.select(table).order_by(*table.primary_key.columns)
        ).all()

    def test_success_updates_row_and_identity_map(self):
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        obj = sess.get(Item, 1)
        eq_(obj.name, "a")

        (result,) = sess.bulk_update_versioned(
            Item, [{"id": 1, "version_id": 1, "name": "a1"}]
        )
        eq_(result.status, VersionedUpdateStatus.SUCCEEDED)
        eq_(result.primary_key, (1,))

        # identity map is synchronized to the written state
        eq_(obj.name, "a1")
        eq_(obj.version_id, 2)

        sess.commit()
        eq_(self._rows(sess), [(1, 2, "a1"), (2, 1, "b"), (3, 1, "c")])

    def test_stale_entry_does_not_block_others(self):
        """Two sessions concurrently modify the same version; the
        loser gets a per-entry STALE result while other rows proceed."""
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        obj1 = sess.get(Item, 1)
        obj2 = sess.get(Item, 2)

        other = Session(config.db)
        (res,) = other.bulk_update_versioned(
            Item, [{"id": 2, "version_id": 1, "name": "b-other"}]
        )
        eq_(res.status, VersionedUpdateStatus.SUCCEEDED)
        other.commit()

        results = sess.bulk_update_versioned(
            Item,
            [
                {"id": 1, "version_id": 1, "name": "a1"},
                {"id": 2, "version_id": 1, "name": "stale-attempt"},
                {"id": 3, "version_id": 1, "name": "c1"},
            ],
        )
        eq_(
            [r.status for r in results],
            [
                VersionedUpdateStatus.SUCCEEDED,
                VersionedUpdateStatus.STALE,
                VersionedUpdateStatus.SUCCEEDED,
            ],
        )
        eq_([r.primary_key for r in results], [(1,), (2,), (3,)])

        # successful entries sync the identity map...
        eq_((obj1.name, obj1.version_id), ("a1", 2))
        # ...while the conflicted object is not pseudo-updated
        eq_((obj2.name, obj2.version_id), ("b", 1))

        sess.commit()
        eq_(
            self._rows(sess),
            [(1, 2, "a1"), (2, 2, "b-other"), (3, 2, "c1")],
        )
        other.close()

    def test_deleted_row_is_stale(self):
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        other = Session(config.db)
        other.delete(other.get(Item, 2))
        other.commit()

        (result,) = sess.bulk_update_versioned(
            Item, [{"id": 2, "version_id": 1, "name": "gone"}]
        )
        eq_(result.status, VersionedUpdateStatus.STALE)
        other.close()

    def test_composite_primary_key(self):
        CompositeItem = self.classes.CompositeItem
        sess = fixture_session()
        sess.add_all(
            [
                CompositeItem(id1=1, id2=1, version_id=1, name="x"),
                CompositeItem(id1=1, id2=2, version_id=1, name="y"),
            ]
        )
        sess.commit()

        other = Session(config.db)
        other.bulk_update_versioned(
            CompositeItem,
            [{"id1": 1, "id2": 2, "version_id": 1, "name": "y-other"}],
        )
        other.commit()

        results = sess.bulk_update_versioned(
            CompositeItem,
            [
                {"id1": 1, "id2": 1, "version_id": 1, "name": "x1"},
                {"id1": 1, "id2": 2, "version_id": 1, "name": "y1"},
            ],
        )
        eq_(
            results,
            [
                VersionedUpdateResult(
                    VersionedUpdateStatus.SUCCEEDED, (1, 1)
                ),
                VersionedUpdateResult(VersionedUpdateStatus.STALE, (1, 2)),
            ],
        )
        sess.commit()
        eq_(
            self._rows(sess, self.tables.composite_item),
            [(1, 1, 2, "x1"), (1, 2, 2, "y-other")],
        )
        other.close()

    def test_duplicate_primary_key_rejected(self):
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        assert_raises_message(
            InvalidRequestError,
            r"more than one mapping for primary key \(1,\)",
            sess.bulk_update_versioned,
            Item,
            [
                {"id": 1, "version_id": 1, "name": "a1"},
                {"id": 1, "version_id": 1, "name": "a2"},
            ],
        )
        # nothing was written
        eq_(self._rows(sess), [(1, 1, "a"), (2, 1, "b"), (3, 1, "c")])

    def test_missing_pk_or_version_rejected(self):
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        assert_raises_message(
            InvalidRequestError,
            r"must include the primary key attribute 'id'",
            sess.bulk_update_versioned,
            Item,
            [{"version_id": 1, "name": "a1"}],
        )
        assert_raises_message(
            InvalidRequestError,
            r"must include the expected value of the version attribute",
            sess.bulk_update_versioned,
            Item,
            [{"id": 1, "name": "a1"}],
        )

    def test_heterogeneous_keys_rejected(self):
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        assert_raises_message(
            InvalidRequestError,
            "the same set of keys",
            sess.bulk_update_versioned,
            Item,
            [
                {"id": 1, "version_id": 1, "name": "a1"},
                {"id": 2, "version_id": 1},
            ],
        )

    def test_mapper_without_version_id_col_rejected(self):
        Plain = self.classes.Plain
        sess = fixture_session()

        assert_raises_message(
            InvalidRequestError,
            "requires the target mapper to be configured with a "
            "version_id_col",
            sess.bulk_update_versioned,
            Plain,
            [{"id": 1, "name": "x"}],
        )

    def test_database_errors_propagate(self):
        """A NOT NULL violation is a real error, not a version conflict."""
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        with expect_raises(IntegrityError):
            sess.bulk_update_versioned(
                Item,
                [
                    {"id": 1, "version_id": 1, "name": "a1"},
                    {"id": 2, "version_id": 1, "name": None},
                ],
            )
        sess.rollback()

    def test_caller_owns_transaction_and_can_rollback(self):
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        results = sess.bulk_update_versioned(
            Item,
            [
                {"id": 1, "version_id": 1, "name": "a1"},
                {"id": 2, "version_id": 1, "name": "b1"},
            ],
        )
        eq_(
            [r.status for r in results],
            [VersionedUpdateStatus.SUCCEEDED] * 2,
        )

        sess.rollback()

        check = Session(config.db)
        eq_(
            self._rows(check),
            [(1, 1, "a"), (2, 1, "b"), (3, 1, "c")],
        )
        check.close()

    def test_empty_mappings(self):
        Item = self.classes.Item
        sess = fixture_session()
        eq_(sess.bulk_update_versioned(Item, []), [])

    def test_results_match_input_order(self):
        Item = self.classes.Item
        sess = fixture_session()
        self._seed_items(sess)

        results = sess.bulk_update_versioned(
            Item,
            [
                {"id": 3, "version_id": 1, "name": "c1"},
                {"id": 1, "version_id": 1, "name": "a1"},
                {"id": 2, "version_id": 1, "name": "b1"},
            ],
        )
        eq_([r.primary_key for r in results], [(3,), (1,), (2,)])
        sess.commit()
        eq_(self._rows(sess), [(1, 2, "a1"), (2, 2, "b1"), (3, 2, "c1")])
