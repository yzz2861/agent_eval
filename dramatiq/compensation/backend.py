from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from typing import Any, Optional

from ..message import Message, generate_unique_id
from .errors import CompensationStateNotFound

RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
COMPENSATING = "compensating"
COMPENSATION_FAILED = "compensation_failed"
COMPENSATED = "compensated"


@dataclass(frozen=True)
class CompensationTransition:
    """The result of an atomic compensation state transition."""

    state: dict[str, Any]
    message: Optional[Message] = None


class CompensationBackend:
    """ABC for compensation pipeline state backends."""

    def create_pipeline(
        self, pipeline_id: str, steps: list[dict[str, Any]]
    ) -> CompensationTransition:  # pragma: no cover
        raise NotImplementedError

    def succeed_step(
        self, pipeline_id: str, step_index: int, message_id: str, result: Any
    ) -> CompensationTransition:  # pragma: no cover
        raise NotImplementedError

    def fail_step(
        self,
        pipeline_id: str,
        step_index: int,
        message_id: str,
        exception: BaseException,
        *,
        traceback: Optional[str] = None,
    ) -> CompensationTransition:  # pragma: no cover
        raise NotImplementedError

    def succeed_compensation(
        self, pipeline_id: str, step_index: int, message_id: str, result: Any = None
    ) -> CompensationTransition:  # pragma: no cover
        raise NotImplementedError

    def fail_compensation(
        self,
        pipeline_id: str,
        step_index: int,
        message_id: str,
        exception: BaseException,
        *,
        traceback: Optional[str] = None,
    ) -> CompensationTransition:  # pragma: no cover
        raise NotImplementedError

    def resume(self, pipeline_id: str) -> CompensationTransition:  # pragma: no cover
        raise NotImplementedError

    def get_state(self, pipeline_id: str) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError


class LocalCompensationBackend(CompensationBackend):
    """A thread-safe, in-process compensation state backend."""

    def __init__(self) -> None:
        self.states: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def create_pipeline(self, pipeline_id: str, steps: list[dict[str, Any]]) -> CompensationTransition:
        with self._lock:
            if pipeline_id in self.states:
                raise ValueError(f"Compensation pipeline {pipeline_id!r} already exists.")

            state = {
                "pipeline_id": pipeline_id,
                "status": RUNNING,
                "steps": copy.deepcopy(steps),
                "completed_steps": 0,
                "results": [None] * len(steps),
                "failed_step": None,
                "compensation_step": None,
                "compensated_steps": [],
                "skipped_compensation_steps": [],
                "active_message": None,
                "active_message_id": None,
                "error": None,
            }
            message = self._build_forward_message(state, 0)
            self._set_active_message(state, message)
            self.states[pipeline_id] = state
            return self._transition(state, message)

    def succeed_step(self, pipeline_id: str, step_index: int, message_id: str, result: Any) -> CompensationTransition:
        with self._lock:
            state = self._get_locked(pipeline_id)
            if not self._is_active_forward_message(state, step_index, message_id):
                return self._transition(state)

            state["results"][step_index] = copy.deepcopy(result)
            state["completed_steps"] = step_index + 1
            state["error"] = None

            if step_index + 1 == len(state["steps"]):
                state["status"] = COMPLETED
                self._clear_active_message(state)
                return self._transition(state)

            message = self._build_forward_message(state, step_index + 1, previous_result=result)
            self._set_active_message(state, message)
            return self._transition(state, message)

    def fail_step(
        self,
        pipeline_id: str,
        step_index: int,
        message_id: str,
        exception: BaseException,
        *,
        traceback: Optional[str] = None,
    ) -> CompensationTransition:
        with self._lock:
            state = self._get_locked(pipeline_id)
            if not self._is_active_forward_message(state, step_index, message_id):
                return self._transition(state)

            state["status"] = FAILED
            state["failed_step"] = step_index
            state["error"] = self._error(exception, traceback)
            self._clear_active_message(state)

            message = self._next_compensation_message(state, step_index - 1)
            if message is None:
                return self._transition(state)

            state["status"] = COMPENSATING
            self._set_active_message(state, message)
            return self._transition(state, message)

    def succeed_compensation(
        self, pipeline_id: str, step_index: int, message_id: str, result: Any = None
    ) -> CompensationTransition:
        with self._lock:
            state = self._get_locked(pipeline_id)
            if not self._is_active_compensation_message(state, step_index, message_id):
                return self._transition(state)

            state["compensated_steps"].append(step_index)
            state["error"] = None
            self._clear_active_message(state)

            message = self._next_compensation_message(state, step_index - 1)
            if message is None:
                state["status"] = COMPENSATED
                return self._transition(state)

            state["status"] = COMPENSATING
            self._set_active_message(state, message)
            return self._transition(state, message)

    def fail_compensation(
        self,
        pipeline_id: str,
        step_index: int,
        message_id: str,
        exception: BaseException,
        *,
        traceback: Optional[str] = None,
    ) -> CompensationTransition:
        with self._lock:
            state = self._get_locked(pipeline_id)
            if not self._is_active_compensation_message(state, step_index, message_id):
                return self._transition(state)

            state["status"] = COMPENSATION_FAILED
            state["error"] = self._error(exception, traceback)
            return self._transition(state)

    def resume(self, pipeline_id: str) -> CompensationTransition:
        with self._lock:
            state = self._get_locked(pipeline_id)
            active_message = state.get("active_message")
            if state["status"] not in {RUNNING, COMPENSATING, COMPENSATION_FAILED} or active_message is None:
                return self._transition(state)

            if state["status"] == COMPENSATION_FAILED:
                state["status"] = COMPENSATING

            return self._transition(state, Message(**active_message))

    def get_state(self, pipeline_id: str) -> dict[str, Any]:
        with self._lock:
            return self._copy_state(self._get_locked(pipeline_id))

    def _get_locked(self, pipeline_id):
        try:
            return self.states[pipeline_id]
        except KeyError:
            raise CompensationStateNotFound(pipeline_id) from None

    @staticmethod
    def _is_active_forward_message(state, step_index, message_id):
        return (
            state["status"] == RUNNING
            and step_index == state["completed_steps"]
            and message_id == state["active_message_id"]
        )

    @staticmethod
    def _is_active_compensation_message(state, step_index, message_id):
        return (
            state["status"] == COMPENSATING
            and step_index == state["compensation_step"]
            and message_id == state["active_message_id"]
        )

    def _build_forward_message(self, state, step_index, *, previous_result=None):
        template = Message(**state["steps"][step_index]["message"])
        args = template.args
        if step_index > 0 and not template.options.get("pipe_ignore"):
            args = args + (previous_result,)

        return template.copy(
            args=args,
            options={
                "compensation_pipeline_id": state["pipeline_id"],
                "compensation_pipeline_step": step_index,
            },
            message_id=generate_unique_id(),
        )

    def _next_compensation_message(self, state, start_index):
        for step_index in range(start_index, -1, -1):
            compensation_data = state["steps"][step_index].get("compensation")
            if compensation_data is None:
                if step_index not in state["skipped_compensation_steps"]:
                    state["skipped_compensation_steps"].append(step_index)
                continue

            if step_index in state["compensated_steps"]:
                continue

            template = Message(**compensation_data)
            message = template.copy(
                args=template.args + (state["results"][step_index],),
                options={
                    "compensation_pipeline_id": state["pipeline_id"],
                    "compensation_pipeline_compensation_step": step_index,
                },
                message_id=generate_unique_id(),
            )
            state["compensation_step"] = step_index
            return message

        state["compensation_step"] = None
        return None

    @staticmethod
    def _set_active_message(state, message):
        state["active_message"] = message.asdict()
        state["active_message_id"] = message.message_id

    @staticmethod
    def _clear_active_message(state):
        state["active_message"] = None
        state["active_message_id"] = None

    @staticmethod
    def _error(exception, traceback):
        return {
            "type": type(exception).__name__,
            "message": str(exception),
            "traceback": traceback,
        }

    def _transition(self, state, message=None):
        return CompensationTransition(self._copy_state(state), message)

    @staticmethod
    def _copy_state(state):
        return copy.deepcopy(state)
