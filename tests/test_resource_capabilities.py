from __future__ import annotations

from types import SimpleNamespace

import pytest

from apscheduler import Job
from apscheduler.datastores.sqlalchemy import SQLAlchemyDataStore


@pytest.mark.parametrize(
    ("dialect", "supported"), [("sqlite", True), ("postgresql", False)]
)
def test_sqlalchemy_named_resource_capability(dialect: str, supported: bool) -> None:
    engine = SimpleNamespace(dialect=SimpleNamespace(name=dialect), url="sqlite://")
    store = SQLAlchemyDataStore.__new__(SQLAlchemyDataStore)
    store._engine = engine
    assert store.supports_named_resources is supported


@pytest.mark.anyio
async def test_non_sqlite_sqlalchemy_rejects_resource_job() -> None:
    engine = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"), url="pg://")
    store = SQLAlchemyDataStore.__new__(SQLAlchemyDataStore)
    store._engine = engine
    with pytest.raises(NotImplementedError, match="postgresql"):
        await store.add_job(
            Job(task_id="task", executor="threadpool", required_resources={"cpu": 1})
        )
