from itertools import zip_longest

from sqlalchemy import bindparam
from sqlalchemy import Column
from sqlalchemy import column
from sqlalchemy import delete
from sqlalchemy import insert
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import select
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import testing
from sqlalchemy import text
from sqlalchemy import TypeDecorator
from sqlalchemy import update
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


class DependencyAnalysisTest(fixtures.TestBase):
    def _tables(self):
        metadata = MetaData()
        nodes = Table(
            "nodes",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("parent_id", Integer),
            Column("active", Integer),
        )
        parents = Table(
            "parents",
            metadata,
            Column("id", Integer, primary_key=True),
        )
        children = Table(
            "children",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("parent_id", Integer),
        )
        return metadata, nodes, parents, children

    def _entry(self, dependencies, table):
        for entry in dependencies.tables:
            if entry.table is table:
                return entry
        return None

    def test_recursive_cte_update(self):
        _, nodes, parents, children = self._tables()

        members = (
            select(nodes.c.id, nodes.c.parent_id)
            .where(nodes.c.id == 1)
            .cte("members", recursive=True)
        )
        members = members.union_all(
            select(children.c.id, children.c.parent_id).join(
                members, children.c.parent_id == members.c.id
            )
        )
        statement = (
            update(nodes)
            .where(
                nodes.c.id.in_(
                    select(members.c.id).join(
                        parents, parents.c.id == members.c.id
                    )
                )
            )
            .values(active=1)
        )

        dependencies = sql_util.analyze_dependencies(statement)

        eq_(
            sorted(dependencies.read_tables, key=lambda table: table.name),
            [children, nodes, parents],
        )
        eq_(dependencies.write_tables, (nodes,))
        eq_(dependencies.unknown, ())

        nodes_entry = self._entry(dependencies, nodes)
        is_not_none(nodes_entry)
        eq_(len(nodes_entry.read_paths), 1)
        eq_(
            nodes_entry.read_paths[0],
            (
                "update",
                "binary",
                "grouping",
                "select",
                "cte:members",
                "compound_select",
                "select",
                "table:nodes",
            ),
        )
        eq_(
            nodes_entry.write_paths,
            (("update", "table:nodes"),),
        )

    def test_aliases_subqueries_and_cte_names_are_not_physical(self):
        _, nodes, parents, children = self._tables()
        parent_alias = parents.alias("p_alias")
        child_subquery = (
            select(children.c.parent_id)
            .where(children.c.id == 2)
            .subquery("child_subquery")
        )
        parent_cte = select(parent_alias.c.id).cte("parent_cte")
        statement = select(nodes.c.id).join(
            child_subquery,
            child_subquery.c.parent_id == nodes.c.id,
        ).where(nodes.c.id.in_(select(parent_cte)))

        dependencies = sql_util.analyze_dependencies(statement)

        eq_(
            sorted(dependencies.read_tables, key=lambda table: table.name),
            [children, nodes, parents],
        )
        eq_(dependencies.write_tables, ())
        parents_entry = self._entry(dependencies, parents)
        is_not_none(parents_entry)
        joined_path = parents_entry.paths[0]
        assert "alias:p_alias" in joined_path
        assert "cte:parent_cte" in joined_path
        assert "subquery:child_subquery" not in joined_path

    def test_insert_from_select_and_returning(self):
        metadata = MetaData()
        source = Table(
            "source",
            metadata,
            Column("id", Integer),
            Column("data", Integer),
        )
        target = Table(
            "target",
            metadata,
            Column("id", Integer),
            Column("data", Integer),
        )
        related = Table(
            "related",
            metadata,
            Column("id", Integer),
            Column("target_id", Integer),
        )
        insert_statement = insert(target).from_select(
            ["id", "data"], select(source.c.id, source.c.data)
        )

        dependencies = sql_util.analyze_dependencies(insert_statement)
        eq_(dependencies.read_tables, (source,))
        eq_(dependencies.write_tables, (target,))

        returning_statement = insert(target).values(id=1).returning(
            target.c.id,
            select(related.c.id).where(
                related.c.target_id == target.c.id
            ).scalar_subquery(),
        )
        dependencies = sql_util.analyze_dependencies(returning_statement)
        eq_(dependencies.read_tables, (related,))
        eq_(dependencies.write_tables, (target,))

    def test_delete_extra_from_correlation(self):
        metadata = MetaData()
        target = Table(
            "target", metadata, Column("id", Integer), Column("keep", Integer)
        )
        related = Table(
            "related",
            metadata,
            Column("id", Integer),
            Column("target_id", Integer),
        )
        statement = delete(target).where(
            target.c.id.in_(
                select(related.c.target_id).where(related.c.id == target.c.keep)
            )
        )

        dependencies = sql_util.analyze_dependencies(statement)
        eq_(dependencies.read_tables, (related,))
        eq_(dependencies.write_tables, (target,))

    def test_text_is_unknown(self):
        metadata = MetaData()
        known = Table("known", metadata, Column("id", Integer))
        statement = select(known).where(text("opaque = true"))

        dependencies = sql_util.analyze_dependencies(statement)
        eq_(dependencies.read_tables, (known,))
        eq_(len(dependencies.unknown), 1)
        eq_(dependencies.unknown[0].kind, "text")
        assert dependencies.unknown[0].paths

        dependencies = sql_util.analyze_dependencies(text("select * from hidden"))
        eq_(dependencies.tables, ())
        eq_(len(dependencies.unknown), 1)

        textual_subquery = (
            text("select id from hidden")
            .columns(column("id"))
            .subquery()
        )
        dependencies = sql_util.analyze_dependencies(
            select(known).select_from(textual_subquery)
        )
        eq_(dependencies.read_tables, (known,))
        eq_(len(dependencies.unknown), 1)
        eq_(dependencies.unknown[0].kind, "text")

    def test_duplicate_physical_tables_use_schema_and_name(self):
        metadata = MetaData()
        first = Table("same", metadata, Column("id", Integer), schema="one")
        second = Table("same", metadata, Column("id", Integer), schema="two")
        same = Table("same", metadata, Column("id", Integer))

        dependencies = sql_util.analyze_dependencies(
            select(first).join(second, second.c.id == first.c.id).where(
                first.c.id.in_(select(same.c.id))
            )
        )

        eq_(
            sorted(
                (
                    (entry.table.schema, entry.table.name)
                    for entry in dependencies.tables
                ),
                key=lambda item: (item[0] or "", item[1]),
            ),
            [(None, "same"), ("one", "same"), ("two", "same")],
        )

    def test_does_not_mutate_statement_or_cache_key(self):
        _, nodes, parents, children = self._tables()
        members = select(nodes.c.id).cte("members", recursive=True)
        members = members.union_all(
            select(children.c.id).join(members, children.c.id == members.c.id)
        )
        statement = update(nodes).where(nodes.c.id.in_(select(members)))
        before = statement._generate_cache_key()

        sql_util.analyze_dependencies(statement)

        after = statement._generate_cache_key()
        eq_(after, before)
        eq_(statement.table, nodes)
