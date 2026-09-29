from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Optional, Union
from uuid import uuid4

from ..actor import Actor
from ..broker import get_broker
from ..message import Message
from ..middleware import Retries
from .backend import CompensationBackend, CompensationTransition
from .middleware import Compensations

if TYPE_CHECKING:
    from .middleware import Compensations as CompensationsMiddleware

Step = Union[Message, tuple[Message], tuple[Message, Optional[Union[Actor, Message]]]]


class compensating_pipeline:
    """Run a sequential pipeline with reverse-order compensations."""

    def __init__(self, children: Iterable[Step], *, backend: CompensationBackend, broker=None) -> None:
        self.broker = broker or get_broker()
        self.backend = backend
        self.pipeline_id = str(uuid4())
        self.messages: list[Message] = []
        self.compensations: list[Optional[Message]] = []

        for child in children:
            message, compensation = self._normalize_step(child)
            self.messages.append(message)
            self.compensations.append(compensation)

        if not self.messages:
            raise ValueError("A compensation pipeline must contain at least one step.")

    @staticmethod
    def _normalize_step(child) -> tuple[Message, Optional[Message]]:
        if isinstance(child, Message):
            return child.copy(), None

        if not isinstance(child, tuple):
            raise TypeError("Compensation pipeline children must be messages or (message, compensation) pairs.")

        if len(child) == 1:
            return child[0].copy(), None

        if len(child) != 2:
            raise ValueError("Compensation pipeline steps must contain a message and an optional compensation.")

        message, compensation_seed = child
        message = message.copy()
        if compensation_seed is None:
            compensation = None
        elif isinstance(compensation_seed, Actor):
            compensation = compensation_seed.message()
        elif isinstance(compensation_seed, Message):
            compensation = compensation_seed.copy()
        else:
            raise TypeError("Compensations must be actors, messages, or None.")

        return message, compensation

    def __len__(self) -> int:
        return len(self.messages)

    def run(self, *, delay: Optional[int] = None) -> compensating_pipeline:
        """Create the pipeline state and enqueue its first step."""
        self._require_middleware()
        steps = [
            {
                "message": message.asdict(),
                "compensation": compensation.asdict() if compensation is not None else None,
            }
            for message, compensation in zip(self.messages, self.compensations)
        ]
        transition = self.backend.create_pipeline(self.pipeline_id, steps)
        self._enqueue(transition, delay=delay)
        return self

    def resume(self, *, delay: Optional[int] = None) -> compensating_pipeline:
        """Re-enqueue the current forward or compensation message."""
        self._require_middleware()
        self._enqueue(self.backend.resume(self.pipeline_id), delay=delay)
        return self

    def get_state(self) -> dict:
        """Return a snapshot of the pipeline state."""
        return self.backend.get_state(self.pipeline_id)

    def _require_middleware(self) -> None:
        middleware: CompensationsMiddleware
        for middleware in self.broker.middleware:
            if isinstance(middleware, Compensations):
                try:
                    if middleware.get_backend(self.broker) is self.backend:
                        return
                except RuntimeError:
                    continue
                return

        kwargs = {"before": Retries} if any(isinstance(m, Retries) for m in self.broker.middleware) else {}
        self.broker.add_middleware(Compensations(backend=self.backend), **kwargs)

    def _enqueue(self, transition: CompensationTransition, *, delay: Optional[int]) -> None:
        if transition.message is not None:
            self.broker.enqueue(
                transition.message,
                delay=delay or transition.message.options.get("delay"),
            )
