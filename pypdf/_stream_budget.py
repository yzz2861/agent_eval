"""Shared decoding budget used while decoding streams of a single PDF document.

All stream decoding paths (plain streams, object streams and page content
streams) go through the budget defined here so that a malicious PDF cannot
hide its resource consumption across many individually small streams.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

from .errors import LimitReachedError

# Absolute, non-negotiable ceilings. Explicit configuration values are clamped
# down to these limits, so callers can never disable the protections entirely.
ABSOLUTE_MAXIMUM_COMPRESSED_INPUT_BYTES = 500_000_000
ABSOLUTE_MAXIMUM_DECOMPRESSED_BYTES = 2_000_000_000
ABSOLUTE_MAXIMUM_FILTER_STEPS = 100
ABSOLUTE_MAXIMUM_SINGLE_STEP_RATIO = 100_000
ABSOLUTE_MAXIMUM_CUMULATIVE_TIME_SECONDS = 300.0

# A compressed stream shorter than this many bytes is allowed to exceed the
# per-step expansion ratio. Without the grace window even a few bytes of
# highly compressible data would trip the ratio check.
RATIO_GRACE_BYTES = 1_024


@dataclass
class StreamDecodingBudget:
    """Tracks the resources consumed while decoding the streams of one reader.

    A budget instance is owned by exactly one ``PdfReader`` and is shared by
    every stream of that reader. Different readers always use independent
    budgets. Standalone stream decoding (without a reader) creates a fresh
    budget for the single call.
    """

    maximum_compressed_input_bytes: int
    maximum_decompressed_bytes: int
    maximum_filter_steps: int
    maximum_single_step_ratio: int
    maximum_cumulative_time_seconds: float

    compressed_input_bytes: int = 0
    decompressed_bytes: int = 0
    filter_steps: int = 0
    elapsed_time_seconds: float = 0.0
    filter_decoding_counts: dict[str, int] = field(default_factory=dict)
    peak_buffer_bytes: int = 0

    def remaining_input_budget(self) -> int:
        """Return the number of compressed bytes that may still be consumed."""
        return self.maximum_compressed_input_bytes - self.compressed_input_bytes

    def remaining_output_budget(self) -> int:
        """Return the number of decompressed bytes that may still be produced."""
        return self.maximum_decompressed_bytes - self.decompressed_bytes

    def require_output_capacity(self) -> None:
        """Reject decoding once no decompressed output budget remains.

        Some codecs treat a limit of ``0`` as "unlimited" (e.g. zlib's
        ``max_length``), so the zero case must be caught explicitly.
        """
        if self.remaining_output_budget() <= 0:
            raise LimitReachedError(
                "Stream decoding exceeded the maximum decompressed output budget "
                f"of {self.maximum_decompressed_bytes} bytes."
            )

    def charge_input(self, amount: int) -> None:
        """Reserve ``amount`` compressed input bytes before they are decoded.

        The check happens before the data is handed to a filter, so oversized
        compressed input never reaches the decoder.
        """
        if amount < 0:
            return
        if self.compressed_input_bytes + amount > self.maximum_compressed_input_bytes:
            raise LimitReachedError(
                "Stream decoding exceeded the maximum compressed input budget "
                f"of {self.maximum_compressed_input_bytes} bytes."
            )
        self.compressed_input_bytes += amount
        self._update_peak()

    def check_output(self, output_length: int) -> None:
        """Validate that ``output_length`` fits into the remaining output budget."""
        if output_length > self.remaining_output_budget():
            raise LimitReachedError(
                "Stream decoding exceeded the maximum decompressed output budget "
                f"of {self.maximum_decompressed_bytes} bytes."
            )

    def charge_output(self, amount: int) -> None:
        """Account for ``amount`` decompressed bytes produced by a filter step."""
        if amount < 0:
            return
        self.check_output(self.decompressed_bytes + amount)
        self.decompressed_bytes += amount
        self._update_peak()

    def begin_filter_step(
        self,
        filter_name: str,
        input_length: int,
        expected_output_length: int | None = None,
    ) -> None:
        """Validate and account for the start of one filter application.

        Args:
            filter_name: The PDF filter name, used for the per-filter stats.
            input_length: Length of the data fed into this filter step.
            expected_output_length: If the filter can determine its output
                length up-front (e.g. ASCII filters), validate it against the
                ratio and output budgets before allocating anything.
        """
        if self.filter_steps >= self.maximum_filter_steps:
            raise LimitReachedError(
                f"Stream decoding exceeded the maximum of {self.maximum_filter_steps} filter steps."
            )
        self.filter_steps += 1
        self.filter_decoding_counts[filter_name] = (
            self.filter_decoding_counts.get(filter_name, 0) + 1
        )
        if expected_output_length is not None:
            self.check_output(self.decompressed_bytes + expected_output_length)
            if input_length > RATIO_GRACE_BYTES and input_length > 0:
                ratio = expected_output_length / input_length
                if ratio > self.maximum_single_step_ratio:
                    raise LimitReachedError(
                        "Stream decoding exceeded the single-step expansion ratio of "
                        f"{self.maximum_single_step_ratio}: {ratio:.1f} from {input_length} "
                        f"to {expected_output_length} bytes."
                    )

    def check_actual_ratio(self, filter_name: str, input_length: int, output_length: int) -> None:
        """Validate the achieved expansion ratio once a filter step finished."""
        if input_length > RATIO_GRACE_BYTES and output_length > input_length:
            ratio = output_length / input_length
            if ratio > self.maximum_single_step_ratio:
                raise LimitReachedError(
                    f"Filter {filter_name} exceeded the single-step expansion ratio of "
                    f"{self.maximum_single_step_ratio}: {ratio:.1f} from {input_length} "
                    f"to {output_length} bytes."
                )

    def add_elapsed_time(self, seconds: float) -> None:
        """Account for time spent inside a filter and enforce the total limit."""
        if seconds < 0:
            return
        self.elapsed_time_seconds += seconds
        if self.elapsed_time_seconds > self.maximum_cumulative_time_seconds:
            raise LimitReachedError(
                "Stream decoding exceeded the maximum cumulative decoding time of "
                f"{self.maximum_cumulative_time_seconds:g} seconds."
            )

    @contextmanager
    def time_step(self) -> Iterator[None]:
        """Measure and charge the wall-clock time of one filter step."""
        started = time.monotonic()
        try:
            yield
        finally:
            self.add_elapsed_time(time.monotonic() - started)

    def _update_peak(self) -> None:
        current = self.compressed_input_bytes + self.decompressed_bytes
        self.peak_buffer_bytes = max(self.peak_buffer_bytes, current)


# Budget explicitly installed for the current execution context (e.g. while a
# reader resolves an object stream). Stream decoding without a reader falls
# back to a fresh per-call budget.
CURRENT_STREAM_BUDGET: ContextVar[StreamDecodingBudget | None] = ContextVar(
    "pypdf_stream_decoding_budget",
    default=None,
)


def get_current_stream_budget() -> StreamDecodingBudget | None:
    return CURRENT_STREAM_BUDGET.get()


class StreamBudgetContext:
    """Context manager installing a shared budget for nested stream decoding."""

    def __init__(self, budget: StreamDecodingBudget) -> None:
        self._budget = budget
        self._token: Any = None

    def __enter__(self) -> StreamDecodingBudget:
        self._token = CURRENT_STREAM_BUDGET.set(self._budget)
        return self._budget

    def __exit__(self, *exc: object) -> None:
        CURRENT_STREAM_BUDGET.reset(self._token)


def create_stream_decoding_budget(configuration: Any) -> StreamDecodingBudget:
    """Build a fresh budget, clamping configuration to the absolute ceilings."""

    def clamped(value: int, ceiling: int) -> int:
        return max(1, min(int(value), ceiling))

    return StreamDecodingBudget(
        maximum_compressed_input_bytes=clamped(
            configuration.stream_maximum_compressed_input_bytes,
            ABSOLUTE_MAXIMUM_COMPRESSED_INPUT_BYTES,
        ),
        maximum_decompressed_bytes=clamped(
            configuration.stream_maximum_decompressed_bytes,
            ABSOLUTE_MAXIMUM_DECOMPRESSED_BYTES,
        ),
        maximum_filter_steps=clamped(
            configuration.stream_maximum_filter_steps,
            ABSOLUTE_MAXIMUM_FILTER_STEPS,
        ),
        maximum_single_step_ratio=clamped(
            configuration.stream_maximum_single_step_ratio,
            ABSOLUTE_MAXIMUM_SINGLE_STEP_RATIO,
        ),
        maximum_cumulative_time_seconds=min(
            max(float(configuration.stream_maximum_cumulative_time_seconds), 0.001),
            ABSOLUTE_MAXIMUM_CUMULATIVE_TIME_SECONDS,
        ),
    )


# Guards the lazy per-reader budget creation.
_BUDGET_LOCK = threading.Lock()


def get_budget_for_stream(stream: Any, configuration: Any) -> StreamDecodingBudget:
    """Resolve the shared budget of the owning reader or create a call budget.

    Streams read through a :class:`~pypdf.PdfReader` carry an
    ``indirect_reference`` whose ``pdf`` owns the shared budget. Streams built
    by application code (or written through a ``PdfWriter``) have no reader and
    therefore get an isolated budget for the single decoding call.
    """
    indirect_reference = getattr(stream, "indirect_reference", None)
    pdf = getattr(indirect_reference, "pdf", None)
    reader_budget = getattr(pdf, "_stream_decoding_budget", None)
    if reader_budget is not None:
        return reader_budget

    context_budget = get_current_stream_budget()
    if context_budget is not None:
        return context_budget

    # Lazily create and remember the per-reader budget.
    if pdf is not None and hasattr(pdf, "_initialize_stream_decoding_budget"):
        with _BUDGET_LOCK:
            reader_budget = getattr(pdf, "_stream_decoding_budget", None)
            if reader_budget is None:
                reader_budget = create_stream_decoding_budget(configuration)
                pdf._stream_decoding_budget = reader_budget
            return reader_budget

    return create_stream_decoding_budget(configuration)
