from __future__ import annotations

from ..errors import DramatiqError


class CompensationError(DramatiqError):
    """Base class for compensation pipeline errors."""


class CompensationStateNotFound(CompensationError, KeyError):
    """Raised when a compensation pipeline state does not exist."""

    def __init__(self, pipeline_id: str):
        super().__init__(pipeline_id)
        self.pipeline_id = pipeline_id

    def __str__(self) -> str:
        return f"Compensation pipeline {self.pipeline_id!r} was not found."
