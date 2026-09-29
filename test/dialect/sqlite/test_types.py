"""SQLite-specific tests."""

import datetime
import json

from sqlalchemy import bindparam
from sqlalchemy import Column
from sqlalchemy import exc
from sqlalchemy import func
from sqlalchemy import MetaData
from sqlalchemy import select
from sqlalchemy import Table
from sqlalchemy import testing
from sqlalchemy import text
from sqlalchemy import types as sqltypes
from sqlalchemy.dialects.sqlite import base as sqlite
from sqlalchemy.testing import assert_raises
from sqlalchemy.testing import assert_raises_message
from sqlalchemy.testing import AssertsCompiledSQL
from sqlalchemy.testing import AssertsExecutionResults
from sqlalchemy.testing import engines
from sqlalchemy.testing import eq_
from sqlalchemy.testing import fixtures
from sqlalchemy.testing import is_
from sqlalchemy.testing import mock
from sqlalchemy.types import Boolean
from sqlalchemy.types import Date
from sqlalchemy.types import DateTime
from sqlalchemy.types import Integer
from sqlalchemy.types import String
from sqlalchemy.types import Time


def exec_sql(engine, sql, *args, **kwargs):
    # TODO: convert all tests to not use this
    with engine.begin() as conn:
        conn.exec_driver_sql(sql, *args, **kwargs)


class TestTypes(fixtures.TestBase, AssertsExecutionResults):
    __only_on__ = "sqlite"

    __backend__ = True

    def test_boolean(self, connection, metadata):
        """Test that the boolean only treats 1 as True"""

        t = Table(
            "bool_table",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("boo", Boolean(create_constraint=False)),
        )
        metadata.create_all(connection)
        for stmt in [
            "INSERT INTO bool_table (id, boo) VALUES (1, 'false');",
            "INSERT INTO bool_table (id, boo) VALUES (2, 'true');",
            "INSERT INTO bool_table (id, boo) VALUES (3, '1');",
            "INSERT INTO bool_table (id, boo) VALUES (4, '0');",
            "INSERT INTO bool_table (id, boo) VALUES (5, 1);",
            "INSERT INTO bool_table (id, boo) VALUES (6, 0);",
        ]:
            connection.exec_driver_sql(stmt)

        eq_(
            connection.execute(
                t.select().where(t.c.boo).order_by(t.c.id)
            ).fetchall(),
            [(3, True), (5, True)],
        )

    def test_string_dates_passed_raise(self, connection):
        assert_raises(
            exc.StatementError,
            connection.execute,
            select(1).where(bindparam("date", type_=Date)),
            dict(date=str(datetime.date(2007, 10, 30))),
        )

    def test_cant_parse_datetime_message(self, connection):
        for typ, disp in [
            (Time, "time"),
            (DateTime, "datetime"),
            (Date, "date"),
        ]:
            assert_raises_message(
                ValueError,
                "Invalid isoformat string:",
                lambda: connection.execute(
                    text("select 'ASDF' as value").columns(value=typ)
                ).scalar(),
            )

    @testing.provide_metadata
    def test_native_datetime(self):
        dbapi = testing.db.dialect.dbapi
        connect_args = {
            "detect_types": dbapi.PARSE_DECLTYPES | dbapi.PARSE_COLNAMES
        }
        engine = engines.testing_engine(
            options={"connect_args": connect_args, "native_datetime": True}
        )
        t = Table(
            "datetest",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("d1", Date),
            Column("d2", sqltypes.TIMESTAMP),
        )
        t.create(engine)
        with engine.begin() as conn:
            conn.execute(
                t.insert(),
                {
                    "d1": datetime.date(2010, 5, 10),
                    "d2": datetime.datetime(2010, 5, 10, 12, 15, 25),
                },
            )
            row = conn.execute(t.select()).first()
            eq_(
                row,
                (
                    1,
                    datetime.date(2010, 5, 10),
                    datetime.datetime(2010, 5, 10, 12, 15, 25),
                ),
            )
            r = conn.execute(func.current_date()).scalar()
            assert isinstance(r, str)

    @testing.provide_metadata
    def test_custom_datetime(self, connection):
        sqlite_date = sqlite.DATETIME(
            # 2004-05-21T00:00:00
            storage_format="%(year)04d-%(month)02d-%(day)02d"
            "T%(hour)02d:%(minute)02d:%(second)02d",
            regexp=r"^(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)$",
        )
        t = Table("t", self.metadata, Column("d", sqlite_date))
        self.metadata.create_all(connection)
        connection.execute(
            t.insert().values(d=datetime.datetime(2010, 10, 15, 12, 37, 0))
        )
        connection.exec_driver_sql(
            "insert into t (d) values ('2004-05-21T00:00:00')"
        )
        eq_(
            connection.exec_driver_sql(
                "select * from t order by d"
            ).fetchall(),
            [("2004-05-21T00:00:00",), ("2010-10-15T12:37:00",)],
        )
        eq_(
            connection.execute(select(t.c.d).order_by(t.c.d)).fetchall(),
            [
                (datetime.datetime(2004, 5, 21, 0, 0),),
                (datetime.datetime(2010, 10, 15, 12, 37),),
            ],
        )

    @testing.provide_metadata
    def test_custom_datetime_text_affinity(self, connection):
        sqlite_date = sqlite.DATETIME(
            storage_format="%(year)04d%(month)02d%(day)02d"
            "%(hour)02d%(minute)02d%(second)02d",
            regexp=r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$",
        )
        t = Table("t", self.metadata, Column("d", sqlite_date))
        self.metadata.create_all(connection)
        connection.execute(
            t.insert().values(d=datetime.datetime(2010, 10, 15, 12, 37, 0))
        )
        connection.exec_driver_sql(
            "insert into t (d) values ('20040521000000')"
        )
        eq_(
            connection.exec_driver_sql(
                "select * from t order by d"
            ).fetchall(),
            [("20040521000000",), ("20101015123700",)],
        )
        eq_(
            connection.execute(select(t.c.d).order_by(t.c.d)).fetchall(),
            [
                (datetime.datetime(2004, 5, 21, 0, 0),),
                (datetime.datetime(2010, 10, 15, 12, 37),),
            ],
        )

    @testing.provide_metadata
    def test_custom_date_text_affinity(self, connection):
        sqlite_date = sqlite.DATE(
            storage_format="%(year)04d%(month)02d%(day)02d",
            regexp=r"(\d{4})(\d{2})(\d{2})",
        )
        t = Table("t", self.metadata, Column("d", sqlite_date))
        self.metadata.create_all(connection)
        connection.execute(t.insert().values(d=datetime.date(2010, 10, 15)))
        connection.exec_driver_sql("insert into t (d) values ('20040521')")
        eq_(
            connection.exec_driver_sql(
                "select * from t order by d"
            ).fetchall(),
            [("20040521",), ("20101015",)],
        )
        eq_(
            connection.execute(select(t.c.d).order_by(t.c.d)).fetchall(),
            [(datetime.date(2004, 5, 21),), (datetime.date(2010, 10, 15),)],
        )

    @testing.provide_metadata
    def test_custom_date(self, connection):
        sqlite_date = sqlite.DATE(
            # 2004-05-21T00:00:00
            storage_format="%(year)04d|%(month)02d|%(day)02d",
            regexp=r"(\d+)\|(\d+)\|(\d+)",
        )
        t = Table("t", self.metadata, Column("d", sqlite_date))
        self.metadata.create_all(connection)
        connection.execute(t.insert().values(d=datetime.date(2010, 10, 15)))

        connection.exec_driver_sql("insert into t (d) values ('2004|05|21')")

        eq_(
            connection.exec_driver_sql(
                "select * from t order by d"
            ).fetchall(),
            [("2004|05|21",), ("2010|10|15",)],
        )
        eq_(
            connection.execute(select(t.c.d).order_by(t.c.d)).fetchall(),
            [(datetime.date(2004, 5, 21),), (datetime.date(2010, 10, 15),)],
        )

    def test_no_convert_unicode(self):
        """test no utf-8 encoding occurs"""

        dialect = sqlite.dialect()
        for t in (
            String(),
            sqltypes.CHAR(),
            sqltypes.Unicode(),
            sqltypes.UnicodeText(),
            String(),
            sqltypes.CHAR(),
            sqltypes.Unicode(),
            sqltypes.UnicodeText(),
        ):
            bindproc = t.dialect_impl(dialect).bind_processor(dialect)
            assert not bindproc or isinstance(bindproc("some string"), str)


class JSONTest(fixtures.TestBase):
    __requires__ = ("json_type",)
    __only_on__ = "sqlite"
    __backend__ = True

    @testing.requires.reflects_json_type
    def test_reflection(self, connection, metadata):
        Table("json_test", metadata, Column("foo", sqlite.JSON))
        metadata.create_all(connection)

        reflected = Table("json_test", MetaData(), autoload_with=connection)
        is_(reflected.c.foo.type._type_affinity, sqltypes.JSON)
        assert isinstance(reflected.c.foo.type, sqlite.JSON)

    def test_rudimentary_roundtrip(self, metadata, connection):
        sqlite_json = Table("json_test", metadata, Column("foo", sqlite.JSON))

        metadata.create_all(connection)

        value = {"json": {"foo": "bar"}, "recs": ["one", "two"]}

        connection.execute(sqlite_json.insert(), dict(foo=value))

        eq_(connection.scalar(select(sqlite_json.c.foo)), value)

    def test_extract_subobject(self, connection, metadata):
        sqlite_json = Table("json_test", metadata, Column("foo", sqlite.JSON))

        metadata.create_all(connection)

        value = {"json": {"foo": "bar"}}

        connection.execute(sqlite_json.insert(), dict(foo=value))

        eq_(
            connection.scalar(select(sqlite_json.c.foo["json"])), value["json"]
        )

    def test_serializer_args(self, metadata):
        sqlite_json = Table("json_test", metadata, Column("foo", sqlite.JSON))
        data_element = {"foo": "bar"}

        js = mock.Mock(side_effect=json.dumps)
        jd = mock.Mock(side_effect=json.loads)

        engine = engines.testing_engine(
            options=dict(json_serializer=js, json_deserializer=jd)
        )
        metadata.create_all(engine)

        with engine.begin() as conn:
            conn.execute(sqlite_json.insert(), {"foo": data_element})

            row = conn.execute(select(sqlite_json.c.foo)).first()

            eq_(row, (data_element,))
            eq_(js.mock_calls, [mock.call(data_element)])
            eq_(jd.mock_calls, [mock.call(json.dumps(data_element))])


class JSONPathModifierCompileTest(fixtures.TestBase, AssertsCompiledSQL):
    __dialect__ = "sqlite"

    def setup_test(self):
        self.test_table = Table(
            "t", MetaData(), Column("data", sqltypes.JSON)
        )
        self.jsoncol = self.test_table.c.data

    def test_json_set_select(self):
        self.assert_compile(
            select(self.jsoncol.json_set(("a", "b", 1), 5)),
            "SELECT JSON_SET(t.data, ?, JSON(?)) AS anon_1 FROM t",
        )

    def test_json_delete_select(self):
        self.assert_compile(
            select(self.jsoncol.json_delete(("a", "b"))),
            "SELECT JSON_REMOVE(t.data, ?) AS anon_1 FROM t",
        )

    def test_json_set_update(self):
        self.assert_compile(
            self.test_table.update().values(
                data=self.jsoncol.json_set(("a",), {"x": 1})
            ),
            "UPDATE t SET data=JSON_SET(t.data, ?, JSON(?))",
        )

    def test_json_set_nested(self):
        self.assert_compile(
            select(
                self.jsoncol.json_set(("a",), {"x": 1}).json_set(
                    ("a", "x"), 2
                )
            ),
            "SELECT JSON_SET(JSON_SET(t.data, ?, JSON(?)), ?, JSON(?)) "
            "AS anon_1 FROM t",
        )

    def test_json_set_null_value(self):
        from sqlalchemy import null

        self.assert_compile(
            select(self.jsoncol.json_set(("a",), null())),
            "SELECT JSON_SET(t.data, ?, NULL) AS anon_1 FROM t",
        )

    def test_negative_index_not_supported(self):
        assert_raises_message(
            exc.CompileError,
            "SQLite JSON paths do not support negative array indexes",
            select(self.jsoncol.json_set(("a", -1), 5)).compile,
            dialect=sqlite.dialect(),
        )
        assert_raises_message(
            exc.CompileError,
            "SQLite JSON paths do not support negative array indexes",
            select(self.jsoncol.json_delete(("a", -1))).compile,
            dialect=sqlite.dialect(),
        )

    def test_unsupported_dialect(self):
        from sqlalchemy.dialects import mysql

        assert_raises(
            exc.UnsupportedCompilationError,
            select(self.jsoncol.json_set(("a",), 5)).compile,
            dialect=mysql.dialect(),
        )
        assert_raises(
            exc.UnsupportedCompilationError,
            select(self.jsoncol.json_delete(("a",))).compile,
            dialect=mysql.dialect(),
        )

    def test_invalid_path(self):
        for path in ((), "ab", ("a", 1.5), ("a", True), ("a", None)):
            assert_raises(exc.ArgumentError, self.jsoncol.json_set, path, 5)
            assert_raises(exc.ArgumentError, self.jsoncol.json_delete, path)

    def test_cache_key(self):
        eq_(
            self.jsoncol.json_set(("a", "b"), 1)._generate_cache_key(),
            self.jsoncol.json_set(("a", "b"), 1)._generate_cache_key(),
        )
        # paths and values are bound parameters and do not take part in
        # the cache key, consistent with other literal binds
        eq_(
            self.jsoncol.json_set(("a", "b"), 1)._generate_cache_key(),
            self.jsoncol.json_set(("c", "d"), 2)._generate_cache_key(),
        )
        assert (
            self.jsoncol.json_set(("a",), 1)._generate_cache_key()
            != self.jsoncol.json_delete(("a",))._generate_cache_key()
        )
        assert (
            self.jsoncol.json_set(("a",), 1)._generate_cache_key()
            != self.jsoncol.json_set(("a",), 1)
            .json_set(("b",), 2)
            ._generate_cache_key()
        )


class JSONPathModifierTest(fixtures.TestBase):
    __requires__ = ("json_type",)
    __only_on__ = "sqlite"
    __backend__ = True

    @testing.fixture
    def json_table(self, connection, metadata):
        t = Table(
            "json_test",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("data", sqltypes.JSON),
        )
        metadata.create_all(connection)
        connection.execute(
            t.insert(),
            [
                {"id": 1, "data": {"a": {"b": [1, 2, 3]}, "s": "x"}},
                {"id": 2, "data": None},
            ],
        )
        return t

    def _data(self, connection, t, id_=1):
        return connection.scalar(select(t.c.data).where(t.c.id == id_))

    def test_set_nested_object_key(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(data=json_table.c.data.json_set(("a", "c"), 9))
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [1, 2, 3], "c": 9}, "s": "x"},
        )

    def test_set_array_index(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(data=json_table.c.data.json_set(("a", "b", 1), 9))
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [1, 9, 3]}, "s": "x"},
        )

    def test_set_creates_missing_intermediate_levels(
        self, connection, json_table
    ):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(
                data=json_table.c.data.json_set(("new", "deep", 0), True)
            )
        )
        eq_(
            self._data(connection, json_table),
            {
                "a": {"b": [1, 2, 3]},
                "s": "x",
                "new": {"deep": [True]},
            },
        )

    def test_set_json_null_value(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(data=json_table.c.data.json_set(("a", "b", 0), None))
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [None, 2, 3]}, "s": "x"},
        )

    def test_set_json_null_constant(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(
                data=json_table.c.data.json_set(
                    ("a", "b", 0), sqltypes.JSON.NULL
                )
            )
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [None, 2, 3]}, "s": "x"},
        )

    def test_set_sql_null_expression(self, connection, json_table):
        from sqlalchemy import null

        # a SQL NULL expression as the value stores JSON null at the path
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(data=json_table.c.data.json_set(("s",), null()))
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [1, 2, 3]}, "s": None},
        )

    def test_sql_null_document_stays_null(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 2)
            .values(data=json_table.c.data.json_set(("a",), 1))
        )
        is_(self._data(connection, json_table, 2), None)

    def test_delete_object_key(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(data=json_table.c.data.json_delete(("s",)))
        )
        eq_(self._data(connection, json_table), {"a": {"b": [1, 2, 3]}})

    def test_delete_array_element(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(data=json_table.c.data.json_delete(("a", "b", 2)))
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [1, 2]}, "s": "x"},
        )

    def test_delete_missing_path_is_noop(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(data=json_table.c.data.json_delete(("a", "nope", 5)))
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [1, 2, 3]}, "s": "x"},
        )

    def test_nested_modification_order(self, connection, json_table):
        # innermost modification applies first; the outermost one wins
        # when the same path is modified twice
        expr = json_table.c.data.json_set(("a", "b", 0), 1).json_set(
            ("a", "b", 0), 2
        )
        eq_(
            connection.scalar(select(expr).where(json_table.c.id == 1)),
            {"a": {"b": [2, 2, 3]}, "s": "x"},
        )

    def test_set_after_delete(self, connection, json_table):
        expr = json_table.c.data.json_delete(("a", "b")).json_set(
            ("a", "b"), {"fresh": True}
        )
        eq_(
            connection.scalar(select(expr).where(json_table.c.id == 1)),
            {"a": {"b": {"fresh": True}}, "s": "x"},
        )

    def test_scalar_value_types(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(
                data=json_table.c.data.json_set(("s",), "plain")
                .json_set(("f",), 2.5)
                .json_set(("flag",), False)
            )
        )
        eq_(
            self._data(connection, json_table),
            {
                "a": {"b": [1, 2, 3]},
                "s": "plain",
                "f": 2.5,
                "flag": False,
            },
        )

    def test_value_as_sql_expression(self, connection, json_table):
        connection.execute(
            json_table.update()
            .where(json_table.c.id == 1)
            .values(
                data=json_table.c.data.json_set(
                    ("s",), func.upper(json_table.c.data["s"].as_string())
                )
            )
        )
        eq_(
            self._data(connection, json_table),
            {"a": {"b": [1, 2, 3]}, "s": "X"},
        )

    def test_expression_in_select(self, connection, json_table):
        eq_(
            connection.scalar(
                select(json_table.c.data.json_set(("z",), [1, 2])).where(
                    json_table.c.id == 1
                )
            ),
            {"a": {"b": [1, 2, 3]}, "s": "x", "z": [1, 2]},
        )


class JSONBTest(fixtures.TestBase, AssertsCompiledSQL):
    __requires__ = ("sqlite_jsonb",)
    __only_on__ = "sqlite"
    __backend__ = True
    __dialect__ = "sqlite"

    def test_ddl(self, metadata, connection):
        Table("jsonb_test", metadata, Column("foo", sqlite.JSONB))
        metadata.create_all(connection)
        result = connection.exec_driver_sql(
            "select sql from sqlite_master where name='jsonb_test'"
        ).scalar()
        assert "JSONB" in result

    def test_reflection(self, metadata, connection):
        Table("jsonb_test", metadata, Column("foo", sqlite.JSONB))
        metadata.create_all(connection)
        reflected = Table("jsonb_test", MetaData(), autoload_with=connection)
        is_(reflected.c.foo.type._type_affinity, sqltypes.JSON)
        assert isinstance(reflected.c.foo.type, sqlite.JSONB)

    def test_roundtrip(self, metadata, connection):
        t = Table("jsonb_test", metadata, Column("foo", sqlite.JSONB))
        metadata.create_all(connection)
        value = {"json": {"foo": "bar"}, "recs": ["one", "two"]}
        connection.execute(t.insert(), {"foo": value})
        eq_(connection.scalar(select(t.c.foo)), value)

    def test_roundtrip_none(self, metadata, connection):
        t = Table("jsonb_test", metadata, Column("foo", sqlite.JSONB))
        metadata.create_all(connection)
        connection.execute(t.insert(), {"foo": None})
        eq_(connection.scalar(select(t.c.foo)), None)

    def test_extract_subobject(self, metadata, connection):
        t = Table("jsonb_test", metadata, Column("foo", sqlite.JSONB))
        metadata.create_all(connection)
        value = {"json": {"foo": "bar"}}
        connection.execute(t.insert(), {"foo": value})
        eq_(connection.scalar(select(t.c.foo["json"])), value["json"])

    def test_bind_expression_renders_jsonb_func(self):
        t = Table("jsonb_test", MetaData(), Column("foo", sqlite.JSONB))
        self.assert_compile(
            t.insert().values(foo={"key": "val"}),
            "INSERT INTO jsonb_test (foo) VALUES (jsonb(?))",
        )

    def test_column_expression_renders_json_func(self):
        t = Table("jsonb_test", MetaData(), Column("foo", sqlite.JSONB))
        self.assert_compile(
            select(t.c.foo),
            "SELECT json(jsonb_test.foo) AS foo FROM jsonb_test",
        )

    def test_storage_is_binary(self, metadata, connection):
        """JSONB data is stored as BLOB, not text."""
        t = Table("jsonb_test", metadata, Column("foo", sqlite.JSONB))
        metadata.create_all(connection)
        connection.execute(t.insert(), {"foo": {"key": "val"}})
        raw = connection.exec_driver_sql(
            "select typeof(foo) from jsonb_test"
        ).scalar()
        eq_(raw, "blob")


class DateTimeTest(fixtures.TestBase, AssertsCompiledSQL):
    def test_time_microseconds(self):
        dt = datetime.datetime(2008, 6, 27, 12, 0, 0, 125)
        eq_(str(dt), "2008-06-27 12:00:00.000125")
        sldt = sqlite.DATETIME()
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "2008-06-27 12:00:00.000125")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt)

    def test_truncate_microseconds(self):
        dt = datetime.datetime(2008, 6, 27, 12, 0, 0, 125)
        dt_out = datetime.datetime(2008, 6, 27, 12, 0, 0)
        eq_(str(dt), "2008-06-27 12:00:00.000125")
        sldt = sqlite.DATETIME(truncate_microseconds=True)
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "2008-06-27 12:00:00")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt_out)

    def test_custom_format_compact(self):
        dt = datetime.datetime(2008, 6, 27, 12, 0, 0, 125)
        eq_(str(dt), "2008-06-27 12:00:00.000125")
        sldt = sqlite.DATETIME(
            storage_format=(
                "%(year)04d%(month)02d%(day)02d"
                "%(hour)02d%(minute)02d%(second)02d%(microsecond)06d"
            ),
            regexp=r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{6})",
        )
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "20080627120000000125")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt)


class DateTest(fixtures.TestBase, AssertsCompiledSQL):
    def test_default(self):
        dt = datetime.date(2008, 6, 27)
        eq_(str(dt), "2008-06-27")
        sldt = sqlite.DATE()
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "2008-06-27")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt)

    def test_custom_format(self):
        dt = datetime.date(2008, 6, 27)
        eq_(str(dt), "2008-06-27")
        sldt = sqlite.DATE(
            storage_format="%(month)02d/%(day)02d/%(year)04d",
            regexp=r"(?P<month>\d+)/(?P<day>\d+)/(?P<year>\d+)",
        )
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "06/27/2008")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt)


class TimeTest(fixtures.TestBase, AssertsCompiledSQL):
    def test_default(self):
        dt = datetime.date(2008, 6, 27)
        eq_(str(dt), "2008-06-27")
        sldt = sqlite.DATE()
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "2008-06-27")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt)

    def test_truncate_microseconds(self):
        dt = datetime.time(12, 0, 0, 125)
        dt_out = datetime.time(12, 0, 0)
        eq_(str(dt), "12:00:00.000125")
        sldt = sqlite.TIME(truncate_microseconds=True)
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "12:00:00")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt_out)

    def test_custom_format(self):
        dt = datetime.date(2008, 6, 27)
        eq_(str(dt), "2008-06-27")
        sldt = sqlite.DATE(
            storage_format="%(year)04d%(month)02d%(day)02d",
            regexp=r"(\d{4})(\d{2})(\d{2})",
        )
        bp = sldt.bind_processor(None)
        eq_(bp(dt), "20080627")
        rp = sldt.result_processor(None, None)
        eq_(rp(bp(dt)), dt)
