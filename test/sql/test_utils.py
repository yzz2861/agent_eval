from itertools import zip_longest

from sqlalchemy import bindparam
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import select
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import update
from sqlalchemy import text
from sqlalchemy import testing
from sqlalchemy import TypeDecorator
from sqlalchemy.sql import base as sql_base
from sqlalchemy.sql import coercions
from sqlalchemy.sql import column
from sqlalchemy.sql import ColumnElement
from sqlalchemy.sql import roles
from sqlalchemy.sql import table
from sqlalchemy.sql import util as sql_util
from sqlalchemy.testing import assert_raises
from sqlalchemy.testing import assert_raises_message
from sqlalchemy.testing import eq_
from sqlalchemy.testing import expect_raises_message
from sqlalchemy.testing import fixtures
from sqlalchemy.testing import is_
from sqlalchemy.testing import is_not_none


class MiscTest(fixtures.TestBase):
    def test_table_dependencies_recursive_cte_update_example(self):
        nodes = Table(
            "nodes",
            MetaData(),
            Column("id", Integer),
            Column("parent_id", Integer),
        )
        edges = Table(
            "edges",
            MetaData(),
            Column("parent_id", Integer),
            Column("child_id", Integer),
        )
        totals = Table(
            "totals",
            MetaData(),
            Column("root_id", Integer),
            Column("value", Integer),
        )

        descendants = select(nodes).where(
            nodes.c.parent_id.is_(None)
        ).cte("descendants", recursive=True)
        recursive_alias = descendants.alias("d")
        descendants = descendants.union_all(
            select(edges).join(
                recursive_alias,
                edges.c.parent_id == recursive_alias.c.id,
            )
        )
        statement = (
            update(totals)
            .where(totals.c.root_id == descendants.c.id)
            .values(value=1)
        )

        analysis = sql_util.analyze_table_dependencies(statement)

        eq_(
            [(item.schema, item.name) for item in analysis.tables_read],
            [(None, "edges"), (None, "nodes")],
        )
        eq_(
            [(item.schema, item.name) for item in analysis.tables_written],
            [(None, "totals")],
        )
        eq_(analysis.unknown, ())
        eq_(analysis.has_unknown, False)

    def test_table_dependencies_select_aliases_subqueries_and_text(self):
        metadata = MetaData()
        orders = Table(
            "orders",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("customer_id", Integer),
        )
        customers = Table(
            "customers",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("name", String(30)),
        )
        order_alias = orders.alias("o")
        nested = select(customers).cte("nested_customer")
        nested_query = select(nested).subquery("nested_query")
        statement = (
            select(order_alias)
            .select_from(
                order_alias.join(
                    nested_query,
                    order_alias.c.customer_id == nested_query.c.id,
                )
            )
            .where(text("unknown predicate"))
        )

        analysis = sql_util.analyze_table_dependencies(statement)

        eq_(
            [(item.schema, item.name) for item in analysis.tables_read],
            [(None, "customers"), (None, "orders")],
        )
        read_paths = {
            item.name: item.paths for item in analysis.tables_read
        }
        assert any(part == "alias:o" for part in read_paths["orders"][0])
        assert any(
            part == "cte:nested_customer"
            for part in read_paths["customers"][0]
        )
        assert any(
            part == "subquery:nested_query"
            for part in read_paths["customers"][0]
        )
        assert "nested_customer" not in dict(
            (item.name, item) for item in analysis.tables_read
        )
        eq_(len(analysis.unknown), 1)
        eq_(analysis.unknown[0].operation, "read")
        eq_(analysis.unknown[0].kind, "TextClause")
        eq_(analysis.unknown[0].text, "unknown predicate")

    def test_table_dependencies_insert_from_select_and_returning(self):
        metadata = MetaData()
        source = Table(
            "source",
            metadata,
            Column("id", Integer, primary_key=True),
        )
        other = Table(
            "other",
            metadata,
            Column("id", Integer, primary_key=True),
        )
        target = Table(
            "target",
            metadata,
            Column("id", Integer, primary_key=True),
        )
        statement = (
            target.insert()
            .from_select(
                [target.c.id],
                select(source.c.id).where(source.c.id == other.c.id),
            )
            .returning(target.c.id)
        )

        analysis = sql_util.analyze_table_dependencies(statement)

        eq_(
            [(item.schema, item.name) for item in analysis.tables_read],
            [(None, "other"), (None, "source")],
        )
        eq_(
            [(item.schema, item.name) for item in analysis.tables_written],
            [(None, "target")],
        )

    def test_table_dependencies_does_not_compile_or_mutate(self):
        metadata = MetaData()
        source = Table(
            "source",
            metadata,
            Column("id", Integer, primary_key=True),
        )
        target = Table(
            "target",
            metadata,
            Column("id", Integer, primary_key=True),
        )
        statement = (
            target.insert()
            .from_select([target.c.id], select(source.c.id))
            .returning(target.c.id)
        )
        cache_key = statement._generate_cache_key()

        analysis = sql_util.analyze_table_dependencies(statement)

        eq_(
            [(item.schema, item.name) for item in analysis.tables_read],
            [(None, "source")],
        )
        eq_(
            [(item.schema, item.name) for item in analysis.tables_written],
            [(None, "target")],
        )
        eq_(statement._generate_cache_key(), cache_key)

    def test_table_dependencies_unknown_text_is_not_empty(self):
        analysis = sql_util.analyze_table_dependencies(
            text("update unknown_table set data = 'value'")
        )

        eq_(analysis.tables_read, ())
        eq_(analysis.tables_written, ())
        eq_(analysis.has_unknown, True)
        eq_(analysis.unknown[0].operation, "read")
        eq_(analysis.unknown[0].kind, "TextClause")
        eq_(
            analysis.unknown[0].text,
            "update unknown_table set data = 'value'",
        )

    def test_table_dependencies_unknown_dml_value_operation(self):
        metadata = MetaData()
        target = Table(
            "target",
            metadata,
            Column("data", String(20)),
        )
        statement = target.update().values(
            data=text("unknown expression")
        )

        analysis = sql_util.analyze_table_dependencies(statement)

        eq_(len(analysis.unknown), 1)
        eq_(analysis.unknown[0].operation, "write")

    def test_table_dependencies_dml_value_subquery_is_read(self):
        metadata = MetaData()
        target = Table(
            "target",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("value", Integer),
        )
        source = Table(
            "source",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("value", Integer),
        )
        value_subquery = select(source.c.value).where(
            source.c.id == target.c.id
        ).scalar_subquery()
        statement = target.update().values(value=value_subquery)

        analysis = sql_util.analyze_table_dependencies(statement)

        eq_(
            [(item.schema, item.name) for item in analysis.tables_read],
            [(None, "source"), (None, "target")],
        )
        eq_(
            [(item.schema, item.name) for item in analysis.tables_written],
            [(None, "target")],
        )
        eq_(analysis.unknown, ())

    def test_column_element_no_visit(self):
        class MyElement(ColumnElement):
            _traverse_internals = []

        eq_(sql_util.find_tables(MyElement(), check_columns=True), [])

    def test_find_tables_selectable(self):
        metadata = MetaData()
        common = Table(
            "common",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("data", Integer),
            Column("extra", String(45)),
        )

        subset_select = select(common.c.id, common.c.data).alias()

        eq_(set(sql_util.find_tables(subset_select)), {common})

    @testing.variation("has_cache_key", [True, False])
    def test_get_embedded_bindparams(self, has_cache_key):
        bp = bindparam("x")

        if not has_cache_key:

            class NotCacheable(TypeDecorator):
                impl = String
                cache_ok = False

            stmt = select(column("q", NotCacheable())).where(column("y") == bp)

        else:
            stmt = select(column("q")).where(column("y") == bp)

        eq_(stmt._get_embedded_bindparams(), [bp])

        if not has_cache_key:
            is_(stmt._generate_cache_key(), None)
        else:
            is_not_none(stmt._generate_cache_key())

    def test_find_tables_aliases(self):
        metadata = MetaData()
        common = Table(
            "common",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("data", Integer),
            Column("extra", String(45)),
        )

        calias = common.alias()
        subset_select = select(common.c.id, calias.c.data).subquery()

        eq_(
            set(sql_util.find_tables(subset_select, include_aliases=True)),
            {common, calias, subset_select},
        )

    def test_incompatible_options_add_clslevel(self):
        class opt1(sql_base.CacheableOptions):
            _cache_key_traversal = []
            foo = "bar"

        with expect_raises_message(
            TypeError,
            "dictionary contains attributes not covered by "
            "Options class .*opt1.* .*'bar'.*",
        ):
            o1 = opt1

            o1 += {"foo": "f", "bar": "b"}

    def test_incompatible_options_add_instancelevel(self):
        class opt1(sql_base.CacheableOptions):
            _cache_key_traversal = []
            foo = "bar"

        o1 = opt1(foo="bat")

        with expect_raises_message(
            TypeError,
            "dictionary contains attributes not covered by "
            "Options class .*opt1.* .*'bar'.*",
        ):
            o1 += {"foo": "f", "bar": "b"}

    def test_options_merge(self):
        class opt1(sql_base.CacheableOptions):
            _cache_key_traversal = []

        class opt2(sql_base.CacheableOptions):
            _cache_key_traversal = []

            foo = "bar"

        class opt3(sql_base.CacheableOptions):
            _cache_key_traversal = []

            foo = "bar"
            bat = "hi"

        o2 = opt2.safe_merge(opt1)
        eq_(o2.__dict__, {})
        eq_(o2.foo, "bar")

        assert_raises_message(
            TypeError,
            r"other element .*opt2.* is not empty, is not of type .*opt1.*, "
            r"and contains attributes not covered here .*'foo'.*",
            opt1.safe_merge,
            opt2,
        )

        o2 = opt2 + {"foo": "bat"}
        o3 = opt2.safe_merge(o2)

        eq_(o3.foo, "bat")

        o4 = opt3.safe_merge(o2)
        eq_(o4.foo, "bat")
        eq_(o4.bat, "hi")

        assert_raises(TypeError, opt2.safe_merge, o4)

    @testing.combinations(
        (column("q"), [column("q")]),
        (column("q").desc(), [column("q")]),
        (column("q").desc().label(None), [column("q")]),
        (column("q").label(None).desc(), [column("q")]),
        (column("q").label(None).desc().label(None), [column("q")]),
        ("foo", []),  # textual label reference
        (
            select(column("q")).scalar_subquery().label(None),
            [select(column("q")).scalar_subquery().label(None)],
        ),
        (
            select(column("q")).scalar_subquery().label(None).desc(),
            [select(column("q")).scalar_subquery().label(None)],
        ),
    )
    def test_unwrap_order_by(self, expr, expected):
        expr = coercions.expect(roles.OrderByRole, expr)

        unwrapped = sql_util.unwrap_order_by(expr)

        for a, b in zip_longest(unwrapped, expected):
            assert a is not None and a.compare(b)

    def test_column_collection_get(self):
        col_id = column("id", Integer)
        col_alt = column("alt", Integer)
        table1 = table("mytable", col_id)

        is_(table1.columns.get("id"), col_id)
        is_(table1.columns.get("alt"), None)
        is_(table1.columns.get("alt", col_alt), col_alt)
