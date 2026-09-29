from __future__ import annotations

import traceback
from typing import TYPE_CHECKING, Any, Optional

from ..middleware import Middleware, Retries
from .backend import CompensationBackend, CompensationTransition

if TYPE_CHECKING:
    from ..broker import MessageProxy

PIPELINE_ID_OPTION = "compensation_pipeline_id"
STEP_OPTION = "compensation_pipeline_step"
COMPENSATION_STEP_OPTION = "compensation_pipeline_compensation_step"


class Compensations(Middleware):
    """Coordinate a compensating pipeline through an atomic state backend."""

    def __init__(
        self,
        backend: Optional[CompensationBackend] = None,
        *,
        backends: Optional[dict[Any, CompensationBackend]] = None,
    ):
        if backend is not None and backends is not None:
            raise ValueError("Provide either backend or backends, but not both.")
        self.backend = backend
        self.backends = backends

    @property
    def actor_options(self):
        return {
            PIPELINE_ID_OPTION,
            STEP_OPTION,
            COMPENSATION_STEP_OPTION,
        }

    def get_backend(self, broker) -> CompensationBackend:
        if self.backend is not None:
            return self.backend
        if self.backends is not None:
            backend = self.backends.get(broker)
            if backend is None:
                raise RuntimeError("No compensation state backend is configured for this broker.")
            return backend
        raise RuntimeError("Compensations middleware has no state backend.")

    def after_process_message(self, broker, message: MessageProxy, *, result=None, exception=None):
        pipeline_id = message.options.get(PIPELINE_ID_OPTION)
        if pipeline_id is None:
            return

        backend = self.get_backend(broker)
        if COMPENSATION_STEP_OPTION in message.options:
            transition = self._process_compensation(backend, broker, message, result, exception)
        else:
            transition = self._process_step(backend, broker, message, result, exception)

        if transition.message is not None:
            broker.enqueue(transition.message, delay=transition.message.options.get("delay"))

    def _process_step(self, backend, broker, message, result, exception):
        pipeline_id = message.options[PIPELINE_ID_OPTION]
        step_index = message.options[STEP_OPTION]
        if message.failed:
            return backend.fail_step(
                pipeline_id,
                step_index,
                message.message_id,
                exception or RuntimeError("Compensation pipeline step was marked as failed."),
                traceback=self._format_traceback(exception),
            )
        if exception is None:
            return backend.succeed_step(pipeline_id, step_index, message.message_id, result)
        if not self._has_retries(broker):
            return backend.fail_step(
                pipeline_id,
                step_index,
                message.message_id,
                exception,
                traceback=self._format_traceback(exception),
            )
        return CompensationTransition(backend.get_state(pipeline_id))

    def _process_compensation(self, backend, broker, message, result, exception):
        pipeline_id = message.options[PIPELINE_ID_OPTION]
        step_index = message.options[COMPENSATION_STEP_OPTION]
        if message.failed:
            return backend.fail_compensation(
                pipeline_id,
                step_index,
                message.message_id,
                exception or RuntimeError("Compensation was marked as failed."),
                traceback=self._format_traceback(exception),
            )
        if exception is None:
            return backend.succeed_compensation(pipeline_id, step_index, message.message_id, result)
        if not self._has_retries(broker):
            return backend.fail_compensation(
                pipeline_id,
                step_index,
                message.message_id,
                exception,
                traceback=self._format_traceback(exception),
            )
        return CompensationTransition(backend.get_state(pipeline_id))

    @staticmethod
    def _has_retries(broker):
        return any(isinstance(middleware, Retries) for middleware in broker.middleware)

    @staticmethod
    def _format_traceback(exception):
        if exception is None:
            return None
        return "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
