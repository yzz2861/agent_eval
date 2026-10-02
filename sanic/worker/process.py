from __future__ import annotations

import os

from collections.abc import MutableMapping
from contextlib import suppress
from datetime import datetime, timezone
from inspect import signature
from multiprocessing.context import BaseContext
from signal import SIGINT
from threading import Thread
from time import sleep
from typing import Any

from sanic.log import Colors, logger
from sanic.worker.constants import ProcessState, RestartOrder


def get_now():
    now = datetime.now(tz=timezone.utc)
    return now


def _worker_entry(target, kwargs, name, ident, state_name):
    os.environ["SANIC_WORKER_NAME"] = name
    os.environ["SANIC_WORKER_IDENTIFIER"] = ident
    os.environ["SANIC_WORKER_STATE_NAME"] = state_name
    try:
        return target(**kwargs)
    finally:
        os.environ.pop("SANIC_WORKER_NAME", None)
        os.environ.pop("SANIC_WORKER_IDENTIFIER", None)
        os.environ.pop("SANIC_WORKER_STATE_NAME", None)


class WorkerProcess:
    """A worker process."""

    THRESHOLD = 300  # == 30 seconds
    SERVER_LABEL = "Server"
    SERVER_IDENTIFIER = "Srv"

    def __init__(
        self,
        factory,
        name,
        ident,
        target,
        kwargs,
        worker_state,
        restartable: bool = False,
    ):
        self.state = ProcessState.IDLE
        self.factory = factory
        self.name = name
        self.ident = ident
        self.target = target
        self.kwargs = kwargs
        self.worker_state = worker_state
        self.restartable = restartable
        self.generation = 0
        self.state_name = self.name
        self._current_process: Any
        self._old_process = None
        self._old_state_name = ""
        self._previous_kwargs: dict[str, Any] | None = None
        if self.state_name not in self.worker_state:
            self.worker_state[self.state_name] = self._initial_state()
        self.spawn()

    def _initial_state(self) -> dict[str, Any]:
        return {
            "server": self.SERVER_LABEL in self.name,
            "generation": self.generation,
        }

    def set_state(self, state: ProcessState, force=False):
        if not force and state < self.state:
            raise Exception("...")
        self.state = state
        self.worker_state[self.state_name] = {
            **self.worker_state.get(self.state_name, {}),
            "state": self.state.name,
        }

    def start(self):
        logger.debug(
            f"{Colors.BLUE}Starting a process: {Colors.BOLD}"
            f"{Colors.SANIC}%s{Colors.END}",
            self.name,
        )
        self.set_state(ProcessState.STARTING)
        self._current_process.start()
        self.set_state(ProcessState.STARTED)
        if not self.worker_state[self.state_name].get("starts"):
            self.worker_state[self.state_name] = {
                **self.worker_state[self.state_name],
                "pid": self.pid,
                "start_at": get_now(),
                "starts": 1,
            }

    def exit(self):
        limit = 100
        while self.is_alive() and limit > 0:
            sleep(0.1)
            limit -= 1

        if not self.is_alive():
            try:
                del self.worker_state[self.state_name]
                if self.name != self.state_name:
                    del self.worker_state[self.name]
            except (
                BrokenPipeError,
                ConnectionRefusedError,
                ConnectionResetError,
                EOFError,
            ):
                logger.debug("Monitor process has already exited.")
            except KeyError:
                logger.debug("Could not find worker state to delete.")

    def terminate(self):
        if self.state is not ProcessState.TERMINATED:
            logger.debug(
                f"{Colors.BLUE}Terminating a process: "
                f"{Colors.BOLD}{Colors.SANIC}"
                f"%s {Colors.BLUE}[%s]{Colors.END}",
                self.name,
                self.pid,
            )
            try:
                self.set_state(ProcessState.TERMINATED, force=True)
            except (BrokenPipeError, ConnectionResetError, EOFError):
                pass
            try:
                os.kill(self.pid, SIGINT)
            except (KeyError, AttributeError, ProcessLookupError):
                ...
        if self._old_process and self._old_process.is_alive():
            try:
                os.kill(self._old_process.pid, SIGINT)
            except (KeyError, AttributeError, ProcessLookupError):
                self._old_process.terminate()

    def join(self, timeout: float | None = None):
        self.set_state(ProcessState.JOINED)
        self._current_process.join(timeout)
        if self._old_process:
            self._old_process.join(timeout)

    def restart(self, restart_order=RestartOrder.SHUTDOWN_FIRST, **kwargs):
        logger.debug(
            f"{Colors.BLUE}Restarting a process: {Colors.BOLD}{Colors.SANIC}"
            f"%s {Colors.BLUE}[%s]{Colors.END}",
            self.name,
            self.pid,
        )
        self.set_state(ProcessState.RESTARTING, force=True)
        if restart_order is RestartOrder.SHUTDOWN_FIRST:
            self._terminate_now()
        else:
            self._old_process = self._current_process
        if self._add_config():
            current = self.kwargs.get("config", {})
            self.kwargs.update(
                {
                    "config": {
                        **current,
                        **{k.upper(): v for k, v in kwargs.items()},
                    }
                }
            )
        try:
            self.spawn()
            self.start()
        except AttributeError:
            raise RuntimeError("Restart failed")

        if restart_order is RestartOrder.STARTUP_FIRST:
            self._terminate_soon()

        self.worker_state[self.state_name] = {
            **self.worker_state[self.state_name],
            "pid": self.pid,
            "starts": self.worker_state[self.state_name]["starts"] + 1,
            "restart_at": get_now(),
        }

    def begin_startup_first(self, **kwargs) -> str:
        if self._old_process is not None:
            raise RuntimeError(f"Worker {self.name} is already restarting")

        old_process: Any = self._current_process
        old_state_name = self.state_name
        self._previous_kwargs = dict(self.kwargs)
        self.generation += 1
        self._old_process = old_process
        self._old_state_name = old_state_name
        self.state_name = f"{self.name}#generation-{self.generation}"
        self.worker_state[self.state_name] = {
            **self._initial_state(),
            "state": ProcessState.RESTARTING.name,
        }
        self.state = ProcessState.RESTARTING

        if self._add_config():
            current = self.kwargs.get("config", {})
            self.kwargs.update(
                {
                    "config": {
                        **current,
                        **{k.upper(): v for k, v in kwargs.items()},
                    }
                }
            )

        try:
            self.spawn()
            self.start()
        except BaseException:
            self.rollback_startup_first()
            raise

        return self.state_name

    def commit_startup_first(self) -> None:
        old_process = self._old_process
        if old_process is None:
            raise RuntimeError(f"Worker {self.name} is not restarting")

        candidate_state = dict(self.worker_state.get(self.state_name, {}))
        self._stop_process(old_process)
        self.worker_state.pop(self._old_state_name, None)

        self._old_process = None
        self._old_state_name = ""
        self._previous_kwargs = None
        self.worker_state[self.name] = {
            **candidate_state,
            "pid": self.pid,
            "starts": candidate_state.get("starts", 1),
            "restart_at": get_now(),
            "generation": self.generation,
        }
        self.set_state(ProcessState.ACKED, force=True)
        with suppress(Exception):
            old_process.close()

    def rollback_startup_first(self, timeout: float = 1.0) -> None:
        candidate: Any = self._current_process
        candidate_state_name = self.state_name
        failed_generation = self.generation
        try:
            self._stop_process(candidate, timeout=timeout)
            self.worker_state.pop(candidate_state_name, None)
        finally:
            if self._old_process is not None:
                self._current_process = self._old_process
                self.state_name = self._old_state_name
                self.kwargs = self._previous_kwargs or self.kwargs
                state = self.worker_state.get(self.state_name, {})
                state_name = state.get("state", ProcessState.ACKED.name)
                self.state = ProcessState[state_name]
                self.generation = failed_generation - 1
            self._old_process = None
            self._old_state_name = ""
            self._previous_kwargs = None

    def current_state(self) -> dict[str, Any]:
        return dict(self.worker_state.get(self.state_name, {}))

    def mirror_logical_state(self) -> None:
        if self.state_name == self.name or self._old_process is not None:
            return
        state = self.current_state()
        if state:
            self.worker_state[self.name] = state
        else:
            self.worker_state.pop(self.name, None)

    def is_alive(self):
        try:
            return self._current_process.is_alive()
        except AssertionError:
            return False

    def spawn(self):
        if self.state not in (ProcessState.IDLE, ProcessState.RESTARTING):
            raise Exception("Cannot spawn a worker process until it is idle.")
        self._current_process = self.factory(
            name=self.name,
            target=_worker_entry,
            kwargs={
                "target": self.target,
                "kwargs": self.kwargs,
                "name": self.name,
                "ident": self.ident,
                "state_name": self.state_name,
            },
            daemon=True,
        )

    @property
    def pid(self):
        return self._current_process.pid

    @property
    def exitcode(self):
        return self._current_process.exitcode

    @property
    def pids(self) -> tuple[int, ...]:
        pids = [self.pid]
        if self._old_process is not None:
            pids.append(self._old_process.pid)
        return tuple(pid for pid in pids if pid)

    @property
    def is_replacing(self) -> bool:
        return self._old_process is not None

    def _terminate_now(self):
        if not self._current_process.is_alive():
            return
        logger.debug(
            f"{Colors.BLUE}Begin restart termination: "
            f"{Colors.BOLD}{Colors.SANIC}"
            f"%s {Colors.BLUE}[%s]{Colors.END}",
            self.name,
            self._current_process.pid,
        )
        self._current_process.terminate()

    def _terminate_soon(self):
        logger.debug(
            f"{Colors.BLUE}Begin restart termination: "
            f"{Colors.BOLD}{Colors.SANIC}"
            f"%s {Colors.BLUE}[%s]{Colors.END}",
            self.name,
            self._current_process.pid,
        )
        termination_thread = Thread(target=self._wait_to_terminate)
        termination_thread.start()

    def _wait_to_terminate(self):
        logger.debug(
            f"{Colors.BLUE}Waiting for process to be acked: "
            f"{Colors.BOLD}{Colors.SANIC}"
            f"%s {Colors.BLUE}[%s]{Colors.END}",
            self.name,
            self._old_process.pid,
        )
        misses = 0
        while self.state is not ProcessState.ACKED:
            sleep(0.1)
            misses += 1
            if misses > self.THRESHOLD:
                raise TimeoutError(
                    f"Worker {self.name} failed to come ack within "
                    f"{self.THRESHOLD / 10} seconds"
                )
        else:
            logger.debug(
                f"{Colors.BLUE}Process acked. Terminating: "
                f"{Colors.BOLD}{Colors.SANIC}"
                f"%s {Colors.BLUE}[%s]{Colors.END}",
                self.name,
                self._old_process.pid,
            )
            self._old_process.terminate()
        delattr(self, "_old_process")

    def _add_config(self) -> bool:
        sig = signature(self.target)
        if "config" in sig.parameters or any(
            param.kind == param.VAR_KEYWORD
            for param in sig.parameters.values()
        ):
            return True
        return False

    @staticmethod
    def _stop_process(process, timeout: float = 5.0) -> None:
        if process.is_alive():
            try:
                os.kill(process.pid, SIGINT)
            except (AttributeError, ProcessLookupError):
                process.terminate()
        process.join(timeout)
        if process.is_alive():
            process.kill()
            process.join(timeout)


class Worker:
    WORKER_PREFIX = "Sanic"

    def __init__(
        self,
        ident: str,
        name: str,
        serve,
        server_settings,
        context: BaseContext,
        worker_state: MutableMapping[str, Any],
        num: int = 1,
        restartable: bool = False,
        tracked: bool = True,
        auto_start: bool = True,
    ):
        self.ident = ident
        self.name = name
        self.num = num
        self.context = context
        self.serve = serve
        self.server_settings = server_settings
        self.worker_state = worker_state
        self.processes: set[WorkerProcess] = set()
        self.restartable = restartable
        self.tracked = tracked
        self.auto_start = auto_start
        for _ in range(num):
            self.create_process()

    def create_process(self) -> WorkerProcess:
        process = WorkerProcess(
            # Need to ignore this typing error - The problem is the
            # BaseContext itself has no Process. But, all of its
            # implementations do. We can safely ignore as it is a typing
            # issue in the standard lib.
            factory=self.context.Process,  # type: ignore
            name="-".join(
                [self.WORKER_PREFIX, self.name, str(len(self.processes))]
            ),
            ident=self.ident,
            target=self.serve,
            kwargs={**self.server_settings},
            worker_state=self.worker_state,
            restartable=self.restartable,
        )
        self.processes.add(process)
        return process

    def has_alive_processes(self) -> bool:
        return any(process.is_alive() for process in self.processes)
