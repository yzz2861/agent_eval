"""
Tests for QuerySet.stream() / ValuesQuery.stream() / ValuesListQuery.stream().
"""

import asyncio
import contextlib

import pytest
import pytest_asyncio

from tests.testmodels import Event, IntFields, Tournament
from tortoise import connections
from tortoise.functions import Count
from tortoise.transactions import in_transaction


class _Rollback(Exception):
    pass


@contextlib.contextmanager
def track_stream(db_conn):
    """Wrap db_conn.execute_query_stream to record batch sizes and closure."""
    state = {"batches": [], "closed": False}
    original = db_conn.execute_query_stream

    def wrapper(query, values=None, batch_size=100):
        async def gen():
            try:
                async for batch in original(query, values, batch_size):
                    state["batches"].append(len(batch))
                    yield batch
            finally:
                state["closed"] = True

        return gen()

    db_conn.execute_query_stream = wrapper
    try:
        yield state
    finally:
        del db_conn.execute_query_stream


@contextlib.contextmanager
def count_queries(db_conn):
    """Count non-streaming queries executed on the connection."""
    state = {"count": 0}
    original = db_conn.execute_query

    async def wrapper(query, values=None):
        state["count"] += 1
        return await original(query, values)

    db_conn.execute_query = wrapper
    try:
        yield state
    finally:
        del db_conn.execute_query


@pytest_asyncio.fixture
async def intfields(db):
    for val in range(10):
        await IntFields.create(intnum=val, intnum_null=val if val % 2 else None)


@pytest.mark.asyncio
async def test_stream_returns_all_rows(db, intfields):
    streamed = [obj.intnum async for obj in IntFields.all().order_by("id").stream(batch_size=3)]
    assert streamed == list(range(10))


@pytest.mark.asyncio
async def test_stream_matches_awaited_results(db, intfields):
    expected = [obj.intnum for obj in await IntFields.all().order_by("id")]
    streamed = [obj.intnum async for obj in IntFields.all().order_by("id").stream(batch_size=4)]
    assert streamed == expected


@pytest.mark.asyncio
async def test_stream_fetches_lazily_in_batches(db, intfields):
    db_conn = connections.get("models")
    with track_stream(db_conn) as state:
        stream = IntFields.all().order_by("id").stream(batch_size=3)
        iterator = stream.__aiter__()
        first = await iterator.__anext__()
        assert first.intnum == 0
        # Only the first batch has been read from the cursor so far.
        assert state["batches"] == [3]
        rest = [obj.intnum async for obj in stream]
        assert rest == list(range(1, 10))
        assert state["batches"] == [3, 3, 3, 1]
        assert state["closed"]


@pytest.mark.asyncio
async def test_stream_empty(db):
    assert [obj async for obj in IntFields.all().stream()] == []


@pytest.mark.asyncio
async def test_stream_values(db, intfields):
    expected = await IntFields.all().order_by("id").values("id", "intnum")
    streamed = [
        row async for row in IntFields.all().order_by("id").values("id", "intnum").stream(4)
    ]
    assert streamed == expected


@pytest.mark.asyncio
async def test_stream_values_list(db, intfields):
    expected = await IntFields.all().order_by("id").values_list("id", "intnum")
    streamed = [
        row async for row in IntFields.all().order_by("id").values_list("id", "intnum").stream(4)
    ]
    assert streamed == expected


@pytest.mark.asyncio
async def test_stream_values_list_flat(db, intfields):
    streamed = [
        val
        async for val in IntFields.all().order_by("id").values_list("intnum", flat=True).stream(4)
    ]
    assert streamed == list(range(10))


@pytest.mark.asyncio
async def test_stream_values_related_field(db):
    tournament = await Tournament.create(name="T1")
    await Event.create(name="E1", tournament=tournament)
    streamed = [row async for row in Event.all().values("name", "tournament__name").stream(1)]
    assert streamed == [{"name": "E1", "tournament__name": "T1"}]


@pytest.mark.asyncio
async def test_stream_annotations(db):
    tournament = await Tournament.create(name="T1")
    await Event.create(name="E1", tournament=tournament)
    await Event.create(name="E2", tournament=tournament)
    streamed = [
        obj async for obj in Tournament.all().annotate(events_count=Count("events")).stream(1)
    ]
    assert len(streamed) == 1
    assert streamed[0].events_count == 2


@pytest.mark.asyncio
async def test_stream_select_related(db):
    tournament = await Tournament.create(name="T1")
    await Event.create(name="E1", tournament=tournament)
    streamed = [obj async for obj in Event.all().select_related("tournament").stream(1)]
    assert len(streamed) == 1
    assert isinstance(streamed[0].tournament, Tournament)
    assert streamed[0].tournament.name == "T1"


@pytest.mark.asyncio
async def test_stream_prefetch_per_batch(db):
    for i in range(5):
        tournament = await Tournament.create(name=f"T{i}")
        await Event.create(name=f"E{i}a", tournament=tournament)
        await Event.create(name=f"E{i}b", tournament=tournament)

    db_conn = connections.get("models")
    with track_stream(db_conn) as stream_state, count_queries(db_conn) as query_state:
        streamed = [
            obj
            async for obj in Tournament.all()
            .order_by("id")
            .prefetch_related("events")
            .stream(batch_size=2)
        ]

    assert [t.name for t in streamed] == [f"T{i}" for i in range(5)]
    for tournament in streamed:
        assert tournament.events._fetched
        assert len(tournament.events) == 2
    # 3 batches of 2/2/1 rows, one prefetch query per batch (no per-row queries)
    assert stream_state["batches"] == [2, 2, 1]
    assert query_state["count"] == 3


@pytest.mark.asyncio
async def test_stream_close_releases_connection(db, intfields):
    db_conn = connections.get("models")
    with track_stream(db_conn) as state:
        stream = IntFields.all().order_by("id").stream(batch_size=3)
        async for obj in stream:
            assert obj.intnum == 0
            break
        await stream.aclose()
        assert state["closed"]
    # The connection is usable for the next query.
    assert await IntFields.all().count() == 10


@pytest.mark.asyncio
async def test_stream_context_manager(db, intfields):
    db_conn = connections.get("models")
    with track_stream(db_conn) as state:
        async with IntFields.all().order_by("id").stream(batch_size=3) as stream:
            async for obj in stream:
                assert obj.intnum == 0
                break
        assert state["closed"]
    assert await IntFields.all().count() == 10


@pytest.mark.asyncio
async def test_stream_conversion_error_closes_cursor(db, intfields):
    await Tournament.create(name="T1")
    field = Tournament._meta.fields_map["created"]

    def boom(value):
        raise ValueError("cannot convert")

    original = field.to_python_value
    field.to_python_value = boom
    try:
        db_conn = connections.get("models")
        with track_stream(db_conn) as state:
            with pytest.raises(ValueError, match="cannot convert"):
                async for _ in Tournament.all().values_list("created", flat=True).stream(2):
                    pass
            assert state["closed"]
    finally:
        field.to_python_value = original
    # The cursor was closed and the connection is usable again.
    assert await Tournament.all().count() == 1


@pytest.mark.asyncio
async def test_stream_cancel_releases_connection(db, intfields):
    db_conn = connections.get("models")
    started = asyncio.Event()
    with track_stream(db_conn) as state:

        async def consume():
            async with IntFields.all().stream(batch_size=2) as stream:
                async for _ in stream:
                    started.set()
                    await asyncio.sleep(60)

        task = asyncio.create_task(consume())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert state["closed"]
    assert await IntFields.all().count() == 10


@pytest.mark.asyncio
async def test_stream_transaction_rollback(db):
    with pytest.raises(_Rollback):
        async with in_transaction():
            await IntFields.create(intnum=42)
            streamed = [obj.intnum async for obj in IntFields.all().stream(batch_size=1)]
            assert 42 in streamed
            raise _Rollback
    assert 42 not in [obj.intnum for obj in await IntFields.all()]


@pytest.mark.asyncio
async def test_stream_first(db, intfields):
    streamed = [obj async for obj in IntFields.all().order_by("id").first().stream()]
    assert len(streamed) == 1
    assert streamed[0].intnum == 0


@pytest.mark.asyncio
async def test_stream_filter(db, intfields):
    streamed = [
        obj.intnum async for obj in IntFields.filter(intnum__gte=8).order_by("id").stream(1)
    ]
    assert streamed == [8, 9]


@pytest.mark.asyncio
async def test_stream_allows_interleaved_queries(db, intfields):
    stream = IntFields.all().order_by("id").stream(batch_size=3)
    iterator = stream.__aiter__()
    first = await iterator.__anext__()
    assert first.intnum == 0
    # Other queries can run on the connection while the stream is open.
    assert await IntFields.all().count() == 10
    rest = [obj.intnum async for obj in stream]
    assert rest == list(range(1, 10))


@pytest.mark.asyncio
async def test_stream_invalid_batch_size(db):
    with pytest.raises(ValueError, match="batch_size"):
        IntFields.all().stream(batch_size=0)
    with pytest.raises(ValueError, match="batch_size"):
        IntFields.all().values("id").stream(batch_size=-1)
    with pytest.raises(ValueError, match="batch_size"):
        IntFields.all().values_list("id").stream(batch_size=0)
