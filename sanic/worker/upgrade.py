from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from time import monotonic
from typing import Any, Callable

from sanic.log import error_logger
from sanic.worker.process import ProcessState, WorkerProcess


ReadinessCheck = Callable[[WorkerProcess, dict[str, Any]], bool]


class UpgradeStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class UpgradeItemStatus(str, Enum):
    PENDING = "PENDING"
    REPLACING = "REPLACING"
    COMMITTED = "COMMITTED"
    FAILED = "FAILED"


@dataclass
class UpgradeItem:
    process: WorkerProcess
    status: UpgradeItemStatus = UpgradeItemStatus.PENDING
    generation: int = 0
    candidate_pid: int | None = None
    error: str = ""

    @property
    def name(self) -> str:
        return self.process.name


@dataclass
class UpgradeOperation:
    operation_id: str
    items: list[UpgradeItem]
    max_unavailable: int
    timeout: float
    readiness_check: ReadinessCheck | None
    config: dict[str, Any] = field(default_factory=dict)
    status: UpgradeStatus = UpgradeStatus.PENDING
    created_at: float = field(default_factory=monotonic)
    finished_at: float | None = None
    error: str = ""

    def run(self) -> None:
        self.status = UpgradeStatus.RUNNING
        try:
            for start in range(0, len(self.items), self.max_unavailable):
                batch = self.items[start : start + self.max_unavailable]
                if any(
                    item.status is UpgradeItemStatus.FAILED
                    for item in self.items
                ):
                    for item in batch:
                        item.status = UpgradeItemStatus.PENDING
                    break
                self._run_batch(batch)
            failed = [item for item in self.items if item.error]
            if failed:
                self.status = UpgradeStatus.FAILED
                self.error = failed[0].error
            else:
                self.status = UpgradeStatus.COMPLETED
        finally:
            self.finished_at = monotonic()

    def snapshot(self, generations: dict[str, int]) -> dict[str, Any]:
        return {
            "id": self.operation_id,
            "status": self.status.value,
            "targets": [item.name for item in self.items],
            "completed": [
                item.name
                for item in self.items
                if item.status is UpgradeItemStatus.COMMITTED
            ],
            "pending": [
                item.name
                for item in self.items
                if item.status is UpgradeItemStatus.PENDING
            ],
            "failed": {
                item.name: item.error for item in self.items if item.error
            },
            "candidate_pids": {
                item.name: item.candidate_pid
                for item in self.items
                if item.candidate_pid is not None
            },
            "generations": dict(generations),
            "max_unavailable": self.max_unavailable,
            "error": self.error,
        }

    def _run_batch(self, batch: list[UpgradeItem]) -> None:
        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            futures = {
                executor.submit(self._replace_one, item): item
                for item in batch
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    item = futures[future]
                    item.status = UpgradeItemStatus.FAILED
                    item.error = str(exc)
                    error_logger.error(
                        "Worker upgrade %s failed for %s: %s",
                        self.operation_id,
                        item.name,
                        exc,
                    )

    def _replace_one(self, item: UpgradeItem) -> None:
        item.status = UpgradeItemStatus.REPLACING
        try:
            item.process.begin_startup_first(**self.config)
            item.candidate_pid = item.process.pid
            self._wait_until_ready(item.process)
            item.process.commit_startup_first()
            item.generation = item.process.generation
            item.status = UpgradeItemStatus.COMMITTED
        except BaseException as exc:
            item.status = UpgradeItemStatus.FAILED
            item.error = str(exc)
            item.process.rollback_startup_first()
            raise

    def _wait_until_ready(self, process: WorkerProcess) -> None:
        deadline = monotonic() + self.timeout
        while monotonic() < deadline:
            if not process.is_alive():
                raise RuntimeError(
                    "Worker "
                    f"{process.name} exited with code {process.exitcode}"
                )

            state = process.current_state()
            if self.readiness_check:
                ready = self.readiness_check(process, state)
            else:
                ready = self._default_ready(state)

            if ready:
                return
        raise TimeoutError(
            "Worker "
            f"{process.name} did not become ready within {self.timeout}s"
        )

    @staticmethod
    def _default_ready(state: dict[str, Any]) -> bool:
        if state.get("state") != ProcessState.ACKED.name:
            return False
        if state.get("server"):
            return state.get("serving") is True
        return True
