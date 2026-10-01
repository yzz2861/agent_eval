import asyncio

import pytest

from tests.testmodels import DecimalFields, Event, IntFields, Team, Tournament
from tortoise.backends.sqlite.client import SqliteStreamingCursor
from tortoise.exceptions import ParamsError
from tortoise.query_utils import Prefetch
from tortoise.transactions import in_transaction


@pytest.mark.asyncio
async def test_stream_batches(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(5)])
    batches = []
    async for batch in Tournament.all().order_by("id").stream(2):
        batches.append([t.name for t in batch])
    assert batches == [["t0", "t1"], ["t2", "t3"], ["t4"]]


@pytest.mark.asyncio
async def test_stream_returns_model_instances(db):
    await Tournament.create(name="x")
    async for batch in Tournament.all().stream():
        assert len(batch) == 1
        assert isinstance(batch[0], Tournament)
        assert batch[0].pk is not None


@pytest.mark.asyncio
async def test_stream_empty(db):
    batches = []
    async for batch in Tournament.filter(id__gt=10_000).stream(10):
        batches.append(batch)
    assert batches == []


@pytest.mark.asyncio
async def test_stream_values(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(3)])
    batches = []
    async with Tournament.all().order_by("id").values("id", "name").stream(2) as stream:
        async for batch in stream:
            batches.append(batch)
    assert batches == [
        [{"id": 1, "name": "t0"}, {"id": 2, "name": "t1"}],
        [{"id": 3, "name": "t2"}],
    ]


@pytest.mark.asyncio
async def test_stream_values_list(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(3)])
    seen = []
    async for batch in (
        Tournament.all().order_by("id").values_list("name", flat=True).stream(2)
    ):
        seen.extend(batch)
    assert seen == ["t0", "t1", "t2"]

    tuples = []
    async for batch in Tournament.all().order_by("id").values_list("id", "name").stream(2):
        tuples.extend(batch)
    assert tuples == [(1, "t0"), (2, "t1"), (3, "t2")]


@pytest.mark.asyncio
async def test_stream_values_type_conversion(db):
    await IntFields.create(intnum=42)
    async for batch in IntFields.all().values_list("intnum", flat=True).stream(10):
        assert batch == [42]
        assert isinstance(batch[0], int)


@pytest.mark.asyncio
async def test_stream_prefetch_forward_per_batch(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(4)])
    tournaments = await Tournament.all().order_by("id")
    for i, tournament in enumerate(tournaments):
        await Event.bulk_create(
            [
                Event(name=f"e{i}-1", tournament=tournament),
                Event(name=f"e{i}-2", tournament=tournament),
            ]
        )

    fetched = {}
    async with Tournament.all().order_by("id").prefetch_related("events").stream(2) as stream:
        async for batch in stream:
            for tournament in batch:
                # Prefetch is complete for the whole batch before it is yielded,
                # so the relation is already populated (no lazy per-row query).
                fetched[tournament.name] = [e.name for e in tournament.events]

    assert fetched == {
        "t0": ["e0-1", "e0-2"],
        "t1": ["e1-1", "e1-2"],
        "t2": ["e2-1", "e2-2"],
        "t3": ["e3-1", "e3-2"],
    }


@pytest.mark.asyncio
async def test_stream_prefetch_m2m_no_per_row_queries(db):
    tournament = await Tournament.create(name="t")
    event = await Event.create(name="e", tournament=tournament)
    await Team.bulk_create([Team(name=f"team{i}") for i in range(3)])
    teams = await Team.all().order_by("id")
    await event.participants.add(*teams)

    aio_connection = Event._meta.db._connection
    statements = []
    await aio_connection.set_trace_callback(lambda sql: statements.append(sql))

    event_stream = (
        Event.all().order_by("event_id").prefetch_related("participants").stream(10)
    )
    async with event_stream as stream:
        async for batch in stream:
            for e in batch:
                assert {t.name for t in e.participants} == {"team0", "team1", "team2"}

    # Main select + one prefetch query through the m2m table; nothing per row.
    await aio_connection.set_trace_callback(None)
    select_like = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(select_like) == 2


@pytest.mark.asyncio
async def test_stream_prefetch_custom_queryset(db):
    tournament = await Tournament.create(name="t")
    await Event.create(name="keep", tournament=tournament)
    await Event.create(name="skip", tournament=tournament)

    async with (
        Tournament.all()
        .prefetch_related(Prefetch("events", queryset=Event.filter(name="keep")))
        .stream(10)
    ) as stream:
        async for batch in stream:
            for t in batch:
                assert [e.name for e in t.events] == ["keep"]


@pytest.mark.asyncio
async def test_stream_prefetch_is_scoped_per_batch(db):
    await Tournament.bulk_create([Tournament(name="t0"), Tournament(name="t1")])
    tournaments = await Tournament.all().order_by("id")
    await Event.create(name="e0", tournament=tournaments[0])
    await Event.create(name="e1", tournament=tournaments[1])

    async with Tournament.all().order_by("id").prefetch_related("events").stream(1) as stream:
        first = (await stream.__anext__())[0]
        assert [e.name for e in first.events] == ["e0"]
        second = (await stream.__anext__())[0]
        assert [e.name for e in second.events] == ["e1"]


@pytest.mark.asyncio
async def test_stream_nested_prefetch_multiple_batches(db):
    for i in range(4):
        tournament = await Tournament.create(name=f"t{i}")
        event = await Event.create(name=f"e{i}", tournament=tournament)
        teams = [await Team.create(name=f"t{i}-team{j}") for j in range(2)]
        await event.participants.add(*teams)

    result = {}
    async with (
        Tournament.all()
        .order_by("id")
        .prefetch_related("events__participants")
        .stream(2)
    ) as stream:
        async for batch in stream:
            for tournament in batch:
                for event in tournament.events:
                    result[(tournament.name, event.name)] = sorted(
                        team.name for team in event.participants
                    )

    for i in range(4):
        assert result[(f"t{i}", f"e{i}")] == [f"t{i}-team0", f"t{i}-team1"]


@pytest.mark.asyncio
async def test_stream_backpressure(db, monkeypatch):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(6)])
    fetch_sizes = []
    original = SqliteStreamingCursor.fetchmany

    def spy(self, size):
        async def run():
            rows = await original(self, size)
            fetch_sizes.append(len(rows))
            return rows

        return run()

    monkeypatch.setattr(SqliteStreamingCursor, "fetchmany", spy)

    stream = Tournament.all().order_by("id").stream(2)
    iterator = stream.__aiter__()
    first = await iterator.__anext__()
    assert [t.name for t in first] == ["t0", "t1"]
    # Only the first batch (2 rows) has been read; later batches are pending.
    assert fetch_sizes == [2]
    await iterator.aclose()


@pytest.mark.asyncio
async def test_stream_close_releases_connection(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(4)])
    db_client = Tournament._meta.db

    async with Tournament.all().stream(2) as stream:
        async for batch in stream:
            assert batch
            break
    # Cursor closed and the connection lock released: another query can run.
    assert not db_client._lock.locked()
    assert await Tournament.all().count() == 4


@pytest.mark.asyncio
async def test_stream_explicit_aclose_releases_connection(db):
    await Tournament.create(name="t")
    db_client = Tournament._meta.db

    stream = Tournament.all().stream(2)
    iterator = stream.__aiter__()
    await iterator.__anext__()
    assert db_client._lock.locked()
    await iterator.aclose()
    assert not db_client._lock.locked()


@pytest.mark.asyncio
async def test_stream_cancellation_releases_connection(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(4)])
    db_client = Tournament._meta.db

    reached = asyncio.Event()

    async def consume():
        async for batch in Tournament.all().stream(1):
            if batch[0].name == "t1":
                reached.set()
                await asyncio.Event().wait()

    task = asyncio.create_task(consume())
    await reached.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The detached cleanup closes the aiosqlite cursor via a thread round trip.
    for _ in range(10):
        await asyncio.sleep(0)
    assert not db_client._lock.locked()


@pytest.mark.asyncio
async def test_stream_inside_transaction(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(3)])
    async with in_transaction() as connection:
        names = []
        async with (
            Tournament.all()
            .using_db(connection)
            .order_by("id")
            .prefetch_related("events")
            .stream(2)
        ) as stream:
            async for batch in stream:
                names.extend(t.name for t in batch)
        # Stream is closed; the same transaction connection serves more queries.
        assert await Tournament.all().using_db(connection).count() == 3
    assert names == ["t0", "t1", "t2"]


@pytest.mark.asyncio
async def test_stream_transaction_lock_released_on_close(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(3)])
    async with in_transaction() as connection:
        async with Tournament.all().using_db(connection).stream(1) as stream:
            first = await stream.__anext__()
            assert first[0].name == "t0"
            # While open the transaction connection is busy.
            assert connection._lock.locked()
        # Closing the stream released the wrapper lock; connection retained.
        assert not connection._lock.locked()
        assert await Tournament.all().using_db(connection).count() == 3


@pytest.mark.asyncio
async def test_stream_closes_on_transaction_exit(db):
    await Tournament.create(name="t")
    captured = {}

    async with in_transaction() as connection:
        stream = Tournament.all().using_db(connection).stream(1)
        iterator = stream.__aiter__()
        await iterator.__anext__()
        captured["iterator"] = iterator
    # Transaction ended; the iterator must not outlive it holding a cursor.
    await captured["iterator"].aclose()


@pytest.mark.asyncio
async def test_stream_invalid_batch_size(db):
    with pytest.raises(ParamsError):
        Tournament.all().stream(0)
    with pytest.raises(ParamsError):
        Tournament.all().values().stream(-1)


@pytest.mark.asyncio
async def test_stream_filter_order_limit(db):
    await Tournament.bulk_create([Tournament(name=f"t{i}") for i in range(6)])
    names = []
    qs = Tournament.filter(name__in=[f"t{i}" for i in range(4)]).order_by("-id").limit(3)
    async for batch in qs.stream(2):
        names.extend(t.name for t in batch)
    assert names == ["t3", "t2", "t1"]


@pytest.mark.asyncio
async def test_stream_conversion_error_closes_cursor(db):
    db_client = DecimalFields._meta.db
    async with db_client.acquire_connection() as connection:
        await connection.execute_insert(
            "INSERT INTO decimalfields (\"decimal\", decimal_nodec) VALUES (?, ?)",
            ["not-a-decimal", 1],
        )

    with pytest.raises(Exception):  # noqa: B017, PT011 - InvalidOperation/ValueError
        async for _batch in DecimalFields.all().values_list("decimal", flat=True).stream(10):
            pass

    # The cursor is closed and its connection returned despite the bad value.
    assert not db_client._lock.locked()
    assert await DecimalFields.all().count() == 1
