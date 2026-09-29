import pytest
import pytest_asyncio

from tests.testmodels import DeviceEvent
from tortoise.expressions import Q, Window
from tortoise.functions import Avg, Count, Lag, Lead, RowNumber, Sum

DATA = [
    ("a", 1, 10.0),
    ("a", 2, 20.0),
    ("a", 3, 30.0),
    ("b", 1, 5.0),
    ("b", 2, 7.0),
]


@pytest_asyncio.fixture
async def device_events(db):
    for device, ts, value in DATA:
        await DeviceEvent.create(device=device, ts=ts, value=value)


@pytest.mark.asyncio
async def test_row_number_partitioned(device_events):
    rows = (
        await DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="ts"))
        .order_by("device", "ts")
    )
    assert [(r.device, r.ts, r.rn) for r in rows] == [
        ("a", 1, 1),
        ("a", 2, 2),
        ("a", 3, 3),
        ("b", 1, 1),
        ("b", 2, 2),
    ]


@pytest.mark.asyncio
async def test_lag_lead(device_events):
    rows = (
        await DeviceEvent.all()
        .annotate(
            prev=Window(Lag("value"), partition_by="device", order_by="ts"),
            next=Window(Lead("value"), partition_by="device", order_by="ts"),
        )
        .order_by("device", "ts")
    )
    assert [(r.device, r.prev, r.next) for r in rows] == [
        ("a", None, 20.0),
        ("a", 10.0, 30.0),
        ("a", 20.0, None),
        ("b", None, 7.0),
        ("b", 5.0, None),
    ]


@pytest.mark.asyncio
async def test_moving_average_rows_frame(device_events):
    qs = DeviceEvent.all().annotate(
        ma=Window(Avg("value"), partition_by="device", order_by="ts", rows=(-1, 0))
    )
    sql = qs.sql()
    assert "ROWS BETWEEN ? PRECEDING AND CURRENT ROW" in sql
    assert "GROUP BY" not in sql
    rows = await qs.order_by("device", "ts")
    assert [(r.device, r.ts, r.ma) for r in rows] == [
        ("a", 1, 10.0),
        ("a", 2, 15.0),
        ("a", 3, 25.0),
        ("b", 1, 5.0),
        ("b", 2, 6.0),
    ]


@pytest.mark.asyncio
async def test_rows_frame_unbounded(device_events):
    qs = DeviceEvent.all().annotate(
        running=Window(Sum("value"), partition_by="device", order_by="ts", rows=(None, 0))
    )
    sql = qs.sql(params_inline=True)
    assert "ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW" in sql
    rows = await qs.order_by("device", "ts")
    assert [r.running for r in rows] == [10.0, 30.0, 60.0, 5.0, 12.0]


@pytest.mark.asyncio
async def test_window_with_aggregate_no_group_by(device_events):
    # a window around an aggregate is not an aggregate itself: no GROUP BY
    qs = (
        DeviceEvent.all()
        .annotate(
            rn=Window(RowNumber(), partition_by="device", order_by="ts"),
            ma=Window(Avg("value"), order_by="ts"),
        )
        .order_by("device", "ts")
    )
    assert "GROUP BY" not in qs.sql()
    rows = await qs
    assert len(rows) == 5


@pytest.mark.asyncio
async def test_window_and_aggregate_together(device_events):
    # a real aggregate still triggers grouping; the window is computed after it
    qs = (
        DeviceEvent.all()
        .annotate(
            total=Count("id"),
            rn=Window(RowNumber(), order_by="device"),
        )
        .group_by("device")
        .values("device", "total", "rn")
    )
    rows = sorted(await qs, key=lambda r: r["device"])
    assert rows == [
        {"device": "a", "total": 3, "rn": 1},
        {"device": "b", "total": 2, "rn": 2},
    ]


@pytest.mark.asyncio
async def test_filter_on_window_uses_outer_query(device_events):
    qs = (
        DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="ts"))
        .filter(rn__lte=2)
        .order_by("device", "ts")
    )
    sql = qs.sql()
    # the window function stays in the inner SELECT, the filter is applied outside
    assert sql.startswith("SELECT * FROM (SELECT")
    assert "WHERE" not in sql.split(') "deviceevent"')[0]
    rows = await qs
    assert [(r.device, r.ts, r.rn) for r in rows] == [
        ("a", 1, 1),
        ("a", 2, 2),
        ("b", 1, 1),
        ("b", 2, 2),
    ]


@pytest.mark.asyncio
async def test_filter_on_window_q_objects(device_events):
    rows = await (
        DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="ts"))
        .filter(Q(rn=1) | Q(device="c"))
        .order_by("device", "ts")
    )
    assert [(r.device, r.ts) for r in rows] == [("a", 1), ("b", 1)]

    rows = await (
        DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="ts"))
        .filter(~Q(rn=1))
        .order_by("device", "ts")
    )
    assert [(r.device, r.ts) for r in rows] == [("a", 2), ("a", 3), ("b", 2)]


@pytest.mark.asyncio
async def test_window_order_vs_display_order(device_events):
    # the OVER() ordering computes the window; order_by() only sorts the output
    rows = await (
        DeviceEvent.filter(device="a")
        .annotate(rn=Window(RowNumber(), order_by="ts"))
        .order_by("-value")
    )
    assert [(r.ts, r.value, r.rn) for r in rows] == [(3, 30.0, 3), (2, 20.0, 2), (1, 10.0, 1)]


@pytest.mark.asyncio
async def test_window_desc_order(device_events):
    rows = (
        await DeviceEvent.filter(device="a")
        .annotate(rn=Window(RowNumber(), order_by="-ts"))
        .order_by("ts")
    )
    assert [r.rn for r in rows] == [3, 2, 1]


@pytest.mark.asyncio
async def test_window_values_and_limit(device_events):
    qs = (
        DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="ts"))
        .filter(rn__lte=2)
        .order_by("device", "ts")
        .limit(3)
        .values("device", "ts", "rn")
    )
    sql = qs.sql()
    assert sql.rstrip().endswith("LIMIT ?")
    assert await qs == [
        {"device": "a", "ts": 1, "rn": 1},
        {"device": "a", "ts": 2, "rn": 2},
        {"device": "b", "ts": 1, "rn": 1},
    ]


@pytest.mark.asyncio
async def test_window_values_list(device_events):
    rows = await (
        DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="ts"))
        .filter(rn=1)
        .order_by("device")
        .values_list("device", "rn")
    )
    assert rows == [("a", 1), ("b", 1)]

    # filtering on a window annotation that is not selected
    rows = await (
        DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="ts"))
        .filter(rn=1)
        .order_by("device")
        .values_list("device", "ts")
    )
    assert rows == [("a", 1), ("b", 1)]


@pytest.mark.asyncio
async def test_window_count_first_exists(device_events):
    qs = DeviceEvent.all().annotate(rn=Window(RowNumber(), order_by="ts")).filter(rn__gt=3)
    assert await qs.count() == 2
    assert await qs.exists()

    first = await (
        DeviceEvent.all()
        .annotate(rn=Window(RowNumber(), partition_by="device", order_by="-ts"))
        .filter(rn=1)
        .order_by("device")
        .first()
    )
    assert (first.device, first.ts, first.rn) == ("a", 3, 1)


@pytest.mark.asyncio
async def test_window_annotation_alias(device_events):
    qs = DeviceEvent.all().annotate(
        my_rank=Window(RowNumber(), partition_by="device", order_by="ts")
    )
    assert '"my_rank"' in qs.sql()
    rows = await qs.order_by("device", "ts")
    assert rows[0].my_rank == 1
