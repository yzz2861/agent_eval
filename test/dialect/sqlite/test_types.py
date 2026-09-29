"""SQLite-specific tests."""

import datetime
import json

from sqlalchemy import bindparam
from sqlalchemy import Column
from sqlalchemy import exc
from sqlalchemy import func
from sqlalchemy import MetaData
from sqlalchemy import null
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


class JSONPathUpdateCompileTest(fixtures.TestBase, AssertsCompiledSQL):
    __dialect__ = "sqlite"

    def test_set_path_compile(self):
        t = Table("t", MetaData(), Column("data", sqlite.JSON))
        self.assert_compile(
            t.c.data.set_path(("meta", "views"), 4),
            "JSON_SET(t.data, ?, JSON(?))",
        )

    def test_remove_path_compile(self):
        t = Table("t", MetaData(), Column("data", sqlite.JSON))
        self.assert_compile(
            t.c.data.remove_path(("tags", 1)),
            "JSON_REMOVE(t.data, ?)",
        )

    def test_nested_compile(self):
        t = Table("t", MetaData(), Column("data", sqlite.JSON))
        self.assert_compile(
            t.c.data.set_path(("a",), 1).remove_path(("b",)),
            "JSON_REMOVE(JSON_SET(t.data, ?, JSON(?)), ?)",
        )

    def test_default_dialect_not_supported(self):
        t = Table("t", MetaData(), Column("data", sqltypes.JSON))
        expr = t.c.data.set_path(("a",), 1)
        assert_raises_message(
            exc.UnsupportedCompilationError,
            "are not supported by the 'default' dialect",
            expr.compile,
        )

    def test_mysql_dialect_not_supported(self):
        from sqlalchemy.dialects import mysql

        t = Table("t", MetaData(), Column("data", sqltypes.JSON))
        expr = t.c.data.remove_path(("a",))
        assert_raises_message(
            exc.UnsupportedCompilationError,
            "are not supported by the 'mysql' dialect",
            expr.compile,
            dialect=mysql.dialect(),
        )


class JSONPathUpdateTest(fixtures.TestBase):
    """Round trip tests for JSON.Comparator.set_path() and
    JSON.Comparator.remove_path() on SQLite."""

    __backend__ = True
    __only_on__ = "sqlite"
    __requires__ = ("json_type",)

    @testing.fixture
    def json_table(self, metadata, connection):
        table = Table(
            "json_path_test",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("data", sqlite.JSON),
        )
        table.create(connection)
        connection.execute(
            table.insert(),
            [
                {
                    "id": 1,
                    "data": {
                        "name": "ann",
                        "tags": ["a", "b"],
                        "meta": {"views": 3, "note": None},
                    },
                },
                {"id": 2, "data": null()},
            ],
        )
        return table

    def _update(self, connection, table, expr, id_=1):
        connection.execute(
            table.update().where(table.c.id == id_).values(data=expr)
        )
        return connection.scalar(select(table.c.data).where(table.c.id == id_))

    def test_set_nested_key(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.set_path(("meta", "views"), 4),
            ),
            {
                "name": "ann",
                "tags": ["a", "b"],
                "meta": {"views": 4, "note": None},
            },
        )

    def test_set_array_element(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.set_path(("tags", 0), "z"),
            ),
            {
                "name": "ann",
                "tags": ["z", "b"],
                "meta": {"views": 3, "note": None},
            },
        )

    def test_set_creates_missing_intermediate_levels(
        self, connection, json_table
    ):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.set_path(("meta", "new", "deep"), True),
            ),
            {
                "name": "ann",
                "tags": ["a", "b"],
                "meta": {
                    "views": 3,
                    "note": None,
                    "new": {"deep": True},
                },
            },
        )

    def test_set_json_null_keeps_key(self, connection, json_table):
        result = self._update(
            connection, json_table, json_table.c.data.set_path(("name",), None)
        )
        eq_(
            result,
            {
                "name": None,
                "tags": ["a", "b"],
                "meta": {"views": 3, "note": None},
            },
        )
        # the key is still present, holding JSON null
        is_(
            connection.scalar(
                select(json_table.c.data["name"].as_string()).where(
                    json_table.c.id == 1
                )
            ),
            None,
        )
        eq_(
            connection.scalar(
                select(func.json_type(json_table.c.data, "$.name")).where(
                    json_table.c.id == 1
                )
            ),
            "null",
        )

    def test_set_json_null_constant(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.set_path(("name",), sqltypes.JSON.NULL),
            ),
            {
                "name": None,
                "tags": ["a", "b"],
                "meta": {"views": 3, "note": None},
            },
        )

    def test_set_structured_value(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.set_path(("meta",), {"x": [1, 2]}),
            ),
            {"name": "ann", "tags": ["a", "b"], "meta": {"x": [1, 2]}},
        )

    def test_remove_key(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.remove_path(("meta", "note")),
            ),
            {"name": "ann", "tags": ["a", "b"], "meta": {"views": 3}},
        )

    def test_remove_array_element(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.remove_path(("tags", 1)),
            ),
            {
                "name": "ann",
                "tags": ["a"],
                "meta": {"views": 3, "note": None},
            },
        )

    def test_remove_missing_path_is_noop(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.remove_path(("meta", "missing", "path")),
            ),
            {
                "name": "ann",
                "tags": ["a", "b"],
                "meta": {"views": 3, "note": None},
            },
        )

    def test_sql_null_document_stays_null(self, connection, json_table):
        is_(
            self._update(
                connection,
                json_table,
                json_table.c.data.set_path(("a",), 1),
                id_=2,
            ),
            None,
        )

    def test_repeated_set_same_path_last_wins(self, connection, json_table):
        expr = json_table.c.data.set_path(("name",), "x")
        expr = expr.set_path(("name",), "y")
        result = self._update(connection, json_table, expr)
        eq_(result["name"], "y")

    def test_nested_set_and_remove(self, connection, json_table):
        expr = json_table.c.data.set_path(("meta", "views"), 10)
        expr = expr.remove_path(("meta", "note"))
        eq_(
            self._update(connection, json_table, expr),
            {"name": "ann", "tags": ["a", "b"], "meta": {"views": 10}},
        )

    def test_expression_in_select(self, connection, json_table):
        eq_(
            connection.scalar(
                select(json_table.c.data.set_path(("tags", 1), "z")).where(
                    json_table.c.id == 1
                )
            ),
            {
                "name": "ann",
                "tags": ["a", "z"],
                "meta": {"views": 3, "note": None},
            },
        )
        # the stored row is unchanged
        eq_(
            connection.scalar(
                select(json_table.c.data).where(json_table.c.id == 1)
            ),
            {
                "name": "ann",
                "tags": ["a", "b"],
                "meta": {"views": 3, "note": None},
            },
        )

    def test_value_as_sql_expression(self, connection, json_table):
        eq_(
            self._update(
                connection,
                json_table,
                json_table.c.data.set_path(
                    ("meta",), json_table.c.data["meta"]
                ),
            ),
            {
                "name": "ann",
                "tags": ["a", "b"],
                "meta": {"views": 3, "note": None},
            },
        )

    def test_negative_index_rejected(self, json_table):
        assert_raises_message(
            exc.ArgumentError,
            "Negative array indexes are not supported",
            json_table.c.data.set_path,
            ("tags", -1),
            9,
        )

    def test_empty_path_rejected(self, json_table):
        assert_raises_message(
            exc.ArgumentError,
            "must contain at least one key or array index",
            json_table.c.data.set_path,
            (),
            9,
        )

    def test_non_sequence_path_rejected(self, json_table):
        assert_raises_message(
            exc.ArgumentError,
            "must be a sequence of string keys",
            json_table.c.data.remove_path,
            "meta",
        )

    def test_invalid_path_element_rejected(self, json_table):
        assert_raises_message(
            exc.ArgumentError,
            "must be string keys or integer array indexes",
            json_table.c.data.set_path,
            ("a", 1.5),
            9,
        )

    def test_sql_null_value_rejected(self, json_table):
        assert_raises_message(
            exc.ArgumentError,
            "SQL NULL cannot be stored at a JSON path",
            json_table.c.data.set_path,
            ("a",),
            null(),
        )


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
