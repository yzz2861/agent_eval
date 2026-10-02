from __future__ import annotations

import os

from collections.abc import MutableMapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import auto
from itertools import count
from signal import SIGINT
from time import monotonic, sleep
from typing import TYPE_CHECKING, Any, Callable

from sanic.compat import OS_IS_WINDOWS, UpperStrEnum
from sanic.log import error_logger, logger
from sanic.worker.constants import ProcessState
from sanic.worker.process import Worker, WorkerProcess


if TYPE_CHECKING:
    from sanic.worker.manager import WorkerManager


SIGKILL: int
if not OS_IS_WINDOWS:
    from signal import SIGKILL
else:
    SIGKILL = SIGINT


ReadinessCheck = Callable[[WorkerProcess, MutableMapping[str, Any]], bool]


class UpgradePhase(UpperStrEnum):
    """Phases of a rolling upgrade operation."""

    IDLE = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()


class UpgradeItemState(UpperStrEnum):
    """States of a single worker replacement inside an upgrade."""

    PENDING = auto()
    STARTING = auto()
    SWAPPED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class UpgradeItem:
    """A single old-generation process to be replaced."""

    old_worker_name: str
    old_process_name: str
    new_worker_name: str
    state: UpgradeItemState = UpgradeItemState.PENDING
    failure_reason: str | None = None
    old_pid: int | None = None
    new_pid: int | None = None
    new_process_name: str | None = None
    old_worker: Worker | None = None
    old_process: WorkerProcess | None = None
    new_worker: Worker | None = None
    new_process: WorkerProcess | None = None
    started_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "old_worker": self.old_worker_name,
            "old_process": self.old_process_name,
            "old_pid": self.old_pid,
            "new_worker": self.new_worker_name,
            "new_process": self.new_process_name,
            "new_pid": self.new_pid,
            "state": self.state.value,
            "failure_reason": self.failure_reason,
        }


class RollingUpgrader:
    """Rolling, observable, and rollback-safe worker upgrades.

    The upgrader replaces server processes one generation at a time.
    New-generation processes get generation-tagged names so the old
    generation can never be mistaken for the new one. Each new process
    must ACK and pass an optional readiness check before the
    corresponding old process is retired. At most "max_concurrent"
    replacements are in flight at any moment, so serving capacity
    never drops below the configured worker count.

    If a new process crashes, fails to ACK in time, or fails the
    readiness check, the operation stops advancing: pending items are
    cancelled, the still-healthy old generation keeps serving, and
    any new-generation children that did not take over are terminated
    and reaped.
    """

    STATUS_KEY = "Sanic-Upgrade"
    ACK_TIMEOUT = WorkerProcess.THRESHOLD / 10
    TERMINATE_GRACE = 10.0

    def __init__(self, manager: WorkerManager):
        self.manager = manager
        self.generation = 0
        self.phase = UpgradePhase.IDLE
        self.operation_id: str | None = None
        self.target_generation: int | None = None
        self.failure_reason: str | None = None
        self.max_concurrent = 1
        self.items: list[UpgradeItem] = []
        self._op_counter = count(1)
        self._readiness_check: ReadinessCheck | None = None
        self._ack_timeout = self.ACK_TIMEOUT
        self._started_at: datetime | None = None
        self._retiring: list[tuple[str, WorkerProcess, float]] = []
        self._publish()

    def begin(
        self,
        process_names: list[str] | None = None,
        max_concurrent: int = 1,
        readiness_check: ReadinessCheck | None = None,
        ack_timeout: float | None = None,
    ) -> str:
        """Begin a rolling upgrade of the server processes.

        If an upgrade is already running, the request is treated as a
        duplicate: the in-flight operation id is returned and no
        second rollout is stacked on top of it.

        Args:
            process_names (Optional[List[str]], optional): Limit the
                upgrade to these process names. Defaults to all server
                processes.
            max_concurrent (int, optional): Maximum number of
                simultaneous replacements. Defaults to 1.
            readiness_check (Optional[Callable], optional): Callable
                receiving the new WorkerProcess and the worker state
                mapping. The old process is only retired once the new
                process has ACKed *and* this returns True.
            ack_timeout (Optional[float], optional): Seconds to wait
                for a new process to become ready before failing the
                operation. Defaults to 30 seconds.

        Returns:
            str: The stable id of the upgrade operation.
        """
        if self.phase is UpgradePhase.RUNNING:
            logger.info(
                "Upgrade %s is already running; ignoring duplicate "
                "upgrade request",
                self.operation_id,
            )
            return self.operation_id  # type: ignore
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")

        targets: list[tuple[Worker, WorkerProcess]] = []
        for worker in self.manager.transient.values():
            if not worker.name.startswith(WorkerProcess.SERVER_LABEL):
                continue
            for process in worker.processes:
                if process_names and process.name not in process_names:
                    continue
                if not process.is_alive():
                    continue
                targets.append((worker, process))
        if not targets:
            raise RuntimeError("No server processes available to upgrade")

        generation = self.generation + 1
        self.operation_id = f"upgrade-{next(self._op_counter)}"
        self.target_generation = generation
        self.items = [
            UpgradeItem(
                old_worker_name=worker.name,
                old_process_name=process.name,
                new_worker_name=f"{worker.name}-G{generation}",
                old_pid=process.pid,
                old_worker=worker,
                old_process=process,
            )
            for worker, process in targets
        ]
        self.phase = UpgradePhase.RUNNING
        self.failure_reason = None
        self.max_concurrent = max_concurrent
        self._readiness_check = readiness_check
        self._ack_timeout = (
            ack_timeout if ack_timeout is not None else self.ACK_TIMEOUT
        )
        self._started_at = datetime.now(tz=timezone.utc)
        logger.info(
            "Starting rolling upgrade %s to generation %s of %d "
            "worker(s) (max_concurrent=%d)",
            self.operation_id,
            generation,
            len(self.items),
            max_concurrent,
        )
        self._publish()
        return self.operation_id

    def tick(self) -> None:
        """Advance the upgrade by one step.

        Called once per monitor cycle by the WorkerManager.
        """
        self._reap()
        if self.phase is not UpgradePhase.RUNNING:
            return
        try:
            for item in self.items:
                if item.state is UpgradeItemState.STARTING:
                    self._check_item(item)
            if self.phase is UpgradePhase.RUNNING:
                self._launch_pending()
                if all(
                    item.state is UpgradeItemState.SWAPPED
                    for item in self.items
                ):
                    self._complete()
        finally:
            self._publish()

    def drain(self, timeout: float | None = None) -> None:
        """Terminate and reap any remaining retired processes.

        Called by the WorkerManager on shutdown so that no orphaned
        or zombie processes are left behind.
        """
        deadline = monotonic() + (timeout or self.TERMINATE_GRACE)
        for _, process, _ in self._retiring:
            if process.is_alive():
                process.terminate()
        while self._retiring and monotonic() < deadline:
            self._reap()
            if self._retiring:
                sleep(0.05)
        for _, process, _ in self._retiring:
            with suppress(ProcessLookupError, OSError):
                if process.pid:
                    os.kill(process.pid, SIGKILL)
        self._reap()

    @property
    def status(self) -> dict[str, Any]:
        """A JSON-safe snapshot of the current upgrade operation."""
        return {
            "operation_id": self.operation_id,
            "phase": self.phase.value,
            "generation": self.generation,
            "target_generation": self.target_generation,
            "max_concurrent": self.max_concurrent,
            "failure_reason": self.failure_reason,
            "started_at": (
                self._started_at.isoformat() if self._started_at else None
            ),
            "updated_at": datetime.now(tz=timezone.utc).isoformat(),
            "completed": [
                item.old_process_name
                for item in self.items
                if item.state is UpgradeItemState.SWAPPED
            ],
            "items": [item.as_dict() for item in self.items],
        }

    def _start_item(self, item: UpgradeItem) -> None:
        # Clear any stale state left under the new process name (for
        # example from a previous failed attempt at the same
        # generation) so the old generation's state can never be
        # mistaken for the new one.
        self.manager.worker_state.pop(
            f"{Worker.WORKER_PREFIX}-{item.new_worker_name}-0", None
        )
        worker = self.manager.manage(
            item.new_worker_name,
            self.manager._serve,
            self.manager._server_settings,
            transient=True,
            restartable=True,
            ident=(
                f"{item.old_worker.ident}-G{self.target_generation}"
                if item.old_worker
                else ""
            ),
        )
        process = next(iter(worker.processes))
        item.new_worker = worker
        item.new_process = process
        item.new_process_name = process.name
        process.start()
        item.new_pid = process.pid
        item.state = UpgradeItemState.STARTING
        item.started_at = monotonic()
        logger.info(
            "Upgrade %s: started %s [%s] to replace %s [%s]",
            self.operation_id,
            item.new_process_name,
            item.new_pid,
            item.old_process_name,
            item.old_pid,
        )

    def _check_item(self, item: UpgradeItem) -> None:
        process = item.new_process
        if process is None:
            return
        if not process.is_alive():
            self._fail_item(
                item,
                f"New process {item.new_process_name} terminated before "
                f"becoming ready (exitcode={process.exitcode})",
            )
            return
        state = self.manager.worker_state.get(item.new_process_name) or {}
        acked = (
            state.get("state") == ProcessState.ACKED.name
            and state.get("pid") == process.pid
        )
        ready = False
        if acked:
            if self._readiness_check is None:
                ready = True
            else:
                try:
                    ready = bool(
                        self._readiness_check(
                            process, self.manager.worker_state
                        )
                    )
                except Exception as exc:
                    self._fail_item(
                        item,
                        f"Readiness check for {item.new_process_name} "
                        f"raised {exc!r}",
                    )
                    return
        if ready:
            self._swap(item)
        elif monotonic() - (item.started_at or 0) > self._ack_timeout:
            reason = (
                f"New process {item.new_process_name} did not ACK "
                f"within {self._ack_timeout}s"
                if not acked
                else f"Readiness check for {item.new_process_name} did "
                f"not pass within {self._ack_timeout}s"
            )
            self._fail_item(item, reason)

    def _swap(self, item: UpgradeItem) -> None:
        old = item.old_process
        if old is not None:
            logger.info(
                "Upgrade %s: %s [%s] is ready; retiring %s [%s]",
                self.operation_id,
                item.new_process_name,
                item.new_pid,
                item.old_process_name,
                item.old_pid,
            )
            old.terminate()
            self._retiring.append(
                (
                    item.old_worker_name,
                    old,
                    monotonic() + self.TERMINATE_GRACE,
                )
            )
        # The old worker is no longer managed: global restarts and
        # scaling operations must not revive it.
        self.manager.transient.pop(item.old_worker_name, None)
        item.state = UpgradeItemState.SWAPPED

    def _fail_item(self, item: UpgradeItem, reason: str) -> None:
        item.state = UpgradeItemState.FAILED
        item.failure_reason = reason
        self.failure_reason = reason
        self.phase = UpgradePhase.FAILED
        error_logger.error(
            "Rolling upgrade %s failed: %s. Keeping the healthy old "
            "generation and cleaning up this round's children.",
            self.operation_id,
            reason,
        )
        for other in self.items:
            if other.state is UpgradeItemState.PENDING:
                other.state = UpgradeItemState.CANCELLED
            elif other.state is UpgradeItemState.STARTING:
                if other is not item:
                    other.state = UpgradeItemState.CANCELLED
                self._discard_new(other)
        self._discard_new(item)

    def _discard_new(self, item: UpgradeItem) -> None:
        if item.new_process is not None:
            item.new_process.terminate()
            self._retiring.append(
                (
                    item.new_worker_name,
                    item.new_process,
                    monotonic() + self.TERMINATE_GRACE,
                )
            )
        self.manager.transient.pop(item.new_worker_name, None)

    def _launch_pending(self) -> None:
        inflight = sum(
            1 for item in self.items if item.state is UpgradeItemState.STARTING
        )
        for item in self.items:
            if inflight >= self.max_concurrent:
                break
            if item.state is not UpgradeItemState.PENDING:
                continue
            self._start_item(item)
            inflight += 1

    def _complete(self) -> None:
        self.phase = UpgradePhase.COMPLETED
        self.generation = self.target_generation or self.generation
        logger.info(
            "Rolling upgrade %s completed. Now serving generation %s.",
            self.operation_id,
            self.generation,
        )

    def _reap(self) -> None:
        remaining: list[tuple[str, WorkerProcess, float]] = []
        for worker_name, process, deadline in self._retiring:
            if process.is_alive():
                if monotonic() > deadline:
                    with suppress(ProcessLookupError, OSError):
                        if process.pid:
                            os.kill(process.pid, SIGKILL)
                    remaining.append((worker_name, process, monotonic() + 2))
                else:
                    remaining.append((worker_name, process, deadline))
                continue
            with suppress(Exception):
                process.reap()
            with suppress(KeyError):
                self.manager.worker_state.pop(process.name)
            self.manager.transient.pop(worker_name, None)
        self._retiring = remaining

    def _publish(self) -> None:
        with suppress(
            BrokenPipeError,
            ConnectionRefusedError,
            ConnectionResetError,
            EOFError,
        ):
            self.manager.worker_state[self.STATUS_KEY] = self.status
