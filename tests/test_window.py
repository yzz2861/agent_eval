import pytest
import pytest_asyncio

from tests.testmodels import Event, Tournament
from tortoise.exceptions import FieldError, OperationalError
from tortoise.expressions import RowsFrame, Window
from tortoise.functions import Avg, Count, Lag, Lead, RowNumber


@pytest_asyncio.fixture
async def window_data(db):
    t1 = await Tournament.create(name="T1")
    t2 = await Tournament.create(name="T2")
    events = []
    for i, (tournament, value) in enumerate([(t1, 10), (t1, 20), (t1, 30), (t2, 40), (t2, 50)]):
        events.append(await Event.create(name=f"event{i}", tournament=tournament, alias=value))
    return events


def row_number(**kwargs):
    return Window(RowNumber(), **kwargs)


@pytest.mark.asyncio
async def test_row_number_partition_by(db, window_data):
    rows = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .order_by("tournament_id", "alias")
        .values("alias", "rn")
    )
    assert rows == [
        {"alias": 10, "rn": 1},
        {"alias": 20, "rn": 2},
        {"alias": 30, "rn": 3},
        {"alias": 40, "rn": 1},
        {"alias": 50, "rn": 2},
    ]


@pytest.mark.asyncio
async def test_row_number_no_partition(db, window_data):
    rows = (
        await Event.all()
        .annotate(rn=row_number(order_by="alias"))
        .order_by("alias")
        .values("alias", "rn")
    )
    assert [row["rn"] for row in rows] == [1, 2, 3, 4, 5]


@pytest.mark.asyncio
async def test_window_order_by_desc(db, window_data):
    rows = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="-alias"))
        .order_by("tournament_id", "alias")
        .values("alias", "rn")
    )
    assert [row["rn"] for row in rows] == [3, 2, 1, 2, 1]


@pytest.mark.asyncio
async def test_lag_lead(db, window_data):
    rows = (
        await Event.all()
        .annotate(
            prev=Window(Lag("alias"), partition_by="tournament_id", order_by="alias"),
            next=Window(Lead("alias"), partition_by="tournament_id", order_by="alias"),
        )
        .order_by("tournament_id", "alias")
        .values("alias", "prev", "next")
    )
    assert rows == [
        {"alias": 10, "prev": None, "next": 20},
        {"alias": 20, "prev": 10, "next": 30},
        {"alias": 30, "prev": 20, "next": None},
        {"alias": 40, "prev": None, "next": 50},
        {"alias": 50, "prev": 40, "next": None},
    ]


@pytest.mark.asyncio
async def test_moving_average_rows_frame(db, window_data):
    queryset = Event.all().annotate(
        ma=Window(
            Avg("alias"),
            partition_by="tournament_id",
            order_by="alias",
            frame=RowsFrame(-1, 0),
        )
    )
    sql = queryset.sql(params_inline=True)
    assert "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW" in sql
    rows = await queryset.order_by("tournament_id", "alias").values("alias", "ma")
    assert rows == [
        {"alias": 10, "ma": 10},
        {"alias": 20, "ma": 15},
        {"alias": 30, "ma": 25},
        {"alias": 40, "ma": 40},
        {"alias": 50, "ma": 45},
    ]


@pytest.mark.asyncio
async def test_window_does_not_add_group_by(db, window_data):
    sql = (
        Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .order_by("alias")
        .sql()
    )
    assert "GROUP BY" not in sql.upper()


@pytest.mark.asyncio
async def test_window_with_aggregate(db, window_data):
    # a plain aggregate must not gain a GROUP BY just because a window is present
    sql = (
        Event.all()
        .annotate(
            total=Count("event_id"),
            rn=row_number(partition_by="tournament_id", order_by="alias"),
        )
        .sql()
    )
    assert "GROUP BY" not in sql.upper()
    assert "ROW_NUMBER" in sql.upper()


@pytest.mark.asyncio
async def test_filter_on_window_wraps_subquery(db, window_data):
    queryset = (
        Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .filter(rn__lte=2)
    )
    sql = queryset.sql()
    # the window function is computed in a subquery and filtered in the outer query
    assert "ROW_NUMBER" in sql.upper()
    assert "OVER" in sql.upper()
    assert sql.upper().index("WHERE") > sql.upper().index("ROW_NUMBER")
    # the filter bound is parameterized
    assert sql.rstrip().endswith("<=?")
    assert "<=2" in queryset.sql(params_inline=True)

    rows = await queryset.order_by("tournament_id", "alias").values("alias", "rn")
    assert rows == [
        {"alias": 10, "rn": 1},
        {"alias": 20, "rn": 2},
        {"alias": 40, "rn": 1},
        {"alias": 50, "rn": 2},
    ]


@pytest.mark.asyncio
async def test_filter_on_window_model_instances(db, window_data):
    events = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .filter(rn=1)
        .order_by("alias")
    )
    assert [event.alias for event in events] == [10, 40]
    assert [event.rn for event in events] == [1, 1]


@pytest.mark.asyncio
async def test_filter_on_window_not_selected(db, window_data):
    # the window annotation is filtered on but not part of the values() projection
    rows = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .filter(rn__lte=2)
        .order_by("tournament_id", "alias")
        .values("alias")
    )
    assert rows == [{"alias": 10}, {"alias": 20}, {"alias": 40}, {"alias": 50}]


@pytest.mark.asyncio
async def test_filter_on_window_with_limit(db, window_data):
    queryset = (
        Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .filter(rn__lte=2)
        .order_by("-alias")
        .limit(3)
    )
    sql = queryset.sql()
    # LIMIT applies to the outer query, after the window filter
    assert sql.rstrip().endswith("LIMIT ?")
    rows = await queryset.values("alias", "rn")
    assert rows == [
        {"alias": 50, "rn": 2},
        {"alias": 40, "rn": 1},
        {"alias": 20, "rn": 2},
    ]


@pytest.mark.asyncio
async def test_window_order_by_vs_query_order_by(db, window_data):
    # the window order_by decides the computation, the query order_by the display
    rows = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .order_by("-alias")
        .values("alias", "rn")
    )
    assert rows == [
        {"alias": 50, "rn": 2},
        {"alias": 40, "rn": 1},
        {"alias": 30, "rn": 3},
        {"alias": 20, "rn": 2},
        {"alias": 10, "rn": 1},
    ]


@pytest.mark.asyncio
async def test_window_filter_and_query_order_by(db, window_data):
    # both orderings stay independent when the query is wrapped for filtering
    rows = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .filter(rn__lte=2)
        .order_by("-alias")
        .values("alias", "rn")
    )
    assert rows == [
        {"alias": 50, "rn": 2},
        {"alias": 40, "rn": 1},
        {"alias": 20, "rn": 2},
        {"alias": 10, "rn": 1},
    ]


@pytest.mark.asyncio
async def test_values_list(db, window_data):
    rows = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .filter(rn=1)
        .order_by("alias")
        .values_list("alias", "rn")
    )
    assert rows == [(10, 1), (40, 1)]


@pytest.mark.asyncio
async def test_window_filter_combined_with_regular_filter(db, window_data):
    rows = (
        await Event.all()
        .annotate(rn=row_number(partition_by="tournament_id", order_by="alias"))
        .filter(rn__lte=2, tournament__name="T1")
        .order_by("alias")
        .values("alias", "rn")
    )
    assert rows == [{"alias": 10, "rn": 1}, {"alias": 20, "rn": 2}]


@pytest.mark.asyncio
async def test_frame_on_unsupported_function(db, window_data):
    with pytest.raises(FieldError, match="does not support a ROWS frame"):
        await (
            Event.all()
            .annotate(rn=row_number(order_by="alias", frame=RowsFrame(-1, 0)))
            .values("rn")
        )


@pytest.mark.asyncio
async def test_invalid_frame_bound(db, window_data):
    with pytest.raises(FieldError, match="must be integers or None"):
        RowsFrame("1", 0)


@pytest.mark.asyncio
async def test_update_with_window_filter_raises(db, window_data):
    with pytest.raises(OperationalError, match="window function"):
        await Event.all().annotate(rn=row_number(order_by="alias")).filter(rn=1).update(name="x")


@pytest.mark.asyncio
async def test_delete_with_window_filter_raises(db, window_data):
    with pytest.raises(OperationalError, match="window function"):
        await Event.all().annotate(rn=row_number(order_by="alias")).filter(rn=1).delete()
