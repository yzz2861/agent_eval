"""
Isolated execution of plugins, plus aggregation of their failures.

A single misbehaving plugin (e.g. one that raises while evaluating a malformed
regular expression) must not abort an entire scan: the remaining files and
plugins still need to be examined, and the incomplete outcome has to be
surfaced so that CI does not silently pass a partial scan.

This module deliberately keeps the existing plugin interface unchanged. Every
recorded failure captures only the file and plugin names plus a generic
description -- raw exception text (and therefore any secret it may contain) is
never written to the logs.
"""
import os
import resource
import threading
from dataclasses import dataclass
from typing import Any
from typing import Callable
from typing import List
from typing import Optional

from .log import log


class PluginExecutionError(Exception):
    """Base class for failures encountered while running a plugin."""


class PluginTimeoutError(PluginExecutionError):
    """Raised when a plugin takes longer than the configured time limit."""


class PluginMemoryLimitError(PluginExecutionError):
    """Raised when a plugin exceeds the configured memory limit."""


@dataclass(frozen=True)
class PluginError:
    """
    A serializable summary of a single plugin failure.

    The plugin file and name are recorded deliberately, but the underlying
    exception message is intentionally omitted: it could quote the line being
    scanned, which may itself contain a secret.
    """

    filename: str
    plugin: str
    error_type: str
    message: str
    line_number: int = 0


class PluginErrorSink:
    """Collects :class:`PluginError` instances produced during a scan."""

    def __init__(self) -> None:
        self.errors: List[PluginError] = []

    def record(
        self,
        filename: str,
        plugin: str,
        error: BaseException,
        line_number: int = 0,
    ) -> PluginError:
        if isinstance(error, PluginTimeoutError):
            error_type = 'timeout'
            message = 'plugin timed out while scanning file'
        elif isinstance(error, (MemoryError, PluginMemoryLimitError)):
            error_type = 'memory'
            message = 'plugin exceeded its memory limit while scanning file'
        else:
            error_type = 'error'
            message = 'plugin raised an exception while scanning file'

        summary = PluginError(
            filename=filename,
            plugin=plugin,
            error_type=error_type,
            message=message,
            line_number=line_number,
        )
        self.errors.append(summary)
        return summary

    def extend(self, errors: List[PluginError]) -> None:
        self.errors.extend(errors)

    def __bool__(self) -> bool:
        return bool(self.errors)

    def __len__(self) -> int:
        return len(self.errors)


# Process-global stack of active sinks. We deliberately avoid both
# contextvars and thread-local storage:
#   * The scanners are generators, and Python snapshots a generator's context
#     at creation time, so context changes made inside a generator are hidden
#     from the caller that supplied the sink.
#   * A timed-out plugin runs on a worker thread, which would not inherit
#     thread-local state from the scanning thread.
# A plain module-level stack is visible across both boundaries. Multiprocessing
# workers use spawn/fork and therefore get their own fresh process state, so
# parallel scans still aggregate errors without cross-talk.
_sink_stack: List[PluginErrorSink] = []


def get_plugin_error_sink() -> Optional[PluginErrorSink]:
    return _sink_stack[-1] if _sink_stack else None


def bind_plugin_error_sink(sink: PluginErrorSink) -> PluginErrorSink:
    """Attaches the given sink and returns a token for later reset.

    This is used by generator-based scanners, whose suspended frames outlive a
    regular plugin_error_context block. Pair with
    reset_plugin_error_sink.
    """
    _sink_stack.append(sink)
    return sink


def reset_plugin_error_sink(token: Any) -> None:
    """Reverts a sink previously installed by bind_plugin_error_sink."""
    if _sink_stack and _sink_stack[-1] is token:
        _sink_stack.pop()


class plugin_error_context:
    """Runs a block with a shared :class:`PluginErrorSink` attached."""

    def __init__(self, sink: Optional[PluginErrorSink] = None) -> None:
        self.sink = sink if sink is not None else PluginErrorSink()
        self._token: Any = None

    def __enter__(self) -> PluginErrorSink:
        self._token = bind_plugin_error_sink(self.sink)
        return self.sink

    def __exit__(self, *args: Any) -> None:
        reset_plugin_error_sink(self._token)
        self._token = None


def get_plugin_timeout() -> Optional[float]:
    """Per-plugin time limit in seconds, configurable via environment variable."""
    value = os.environ.get('DETECT_SECRETS_PLUGIN_TIMEOUT')
    if not value:
        return None

    try:
        timeout = float(value)
    except ValueError:
        return None

    return timeout if timeout > 0 else None


def get_plugin_memory_limit() -> Optional[int]:
    """Per-plugin address-space limit in bytes, configurable via env variable."""
    value = os.environ.get('DETECT_SECRETS_PLUGIN_MEMORY_LIMIT')
    if not value:
        return None

    try:
        limit = int(value)
    except ValueError:
        return None

    return limit if limit > 0 else None


def run_plugin(
    plugin_name: str,
    function: Callable[..., Any],
    *args: Any,
    filename: str = '',
    line_number: int = 0,
    **kwargs: Any,
) -> Any:
    """
    Runs ``function`` in isolation.

    Resource limits are opt-in through environment variables, so scans that do
    not configure them pay no threading overhead. Any failure (a regular
    exception, a timeout or a memory-limit breach) is converted into a
    :class:`PluginError` and written to the active :class:`PluginErrorSink`;
    ``None`` is returned instead of propagating, so that sibling plugins and
    files keep being scanned.
    """
    timeout = get_plugin_timeout()
    if timeout is None:
        try:
            return _run_with_memory_guard(function, args, kwargs)
        except BaseException as error:
            _capture_error(
                plugin_name=plugin_name,
                filename=filename,
                error=error,
                line_number=line_number,
            )
            return None

    outcome = _ExecutionOutcome()
    thread = threading.Thread(
        target=_run_in_worker,
        args=(function, args, kwargs, outcome),
        name=f'plugin-{plugin_name}',
        daemon=True,
    )
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        # The daemon thread is abandoned rather than force-killed: Python does
        # not support safely terminating threads, and it will not block process
        # exit.
        error = PluginTimeoutError('plugin timed out')
        _capture_error(
            plugin_name=plugin_name,
            filename=filename,
            error=error,
            line_number=line_number,
        )
        return None

    if outcome.error is not None:
        _capture_error(
            plugin_name=plugin_name,
            filename=filename,
            error=outcome.error,
            line_number=line_number,
        )
        return None

    return outcome.result


@dataclass
class _ExecutionOutcome:
    result: Any = None
    error: Optional[BaseException] = None


def _run_in_worker(
    function: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    outcome: _ExecutionOutcome,
) -> None:
    try:
        outcome.result = _run_with_memory_guard(function, args, kwargs)
    except BaseException as error:  # noqa: B036 - reported through the sink
        outcome.error = error


def _run_with_memory_guard(
    function: Callable[..., Any],
    args: tuple,
    kwargs: dict,
) -> Any:
    limit = get_plugin_memory_limit()
    if limit is None:
        return function(*args, **kwargs)

    if _apply_address_space_limit(limit):
        original_soft, original_hard = resource.getrlimit(resource.RLIMIT_AS)
        try:
            return function(*args, **kwargs)
        except MemoryError as error:
            raise PluginMemoryLimitError(
                'plugin exceeded its memory limit',
            ) from error
        finally:
            resource.setrlimit(
                resource.RLIMIT_AS,
                (original_soft, original_hard),
            )

    # Some platforms (notably macOS) reject finite address-space limits. Fall
    # back to a cooperative soft cap driven by a swappable usage probe rather
    # than failing the scan for a platform limitation outside the plugin.
    def guarded(*inner_args: Any, **inner_kwargs: Any) -> Any:
        usage = _memory_usage_probe()
        if usage is not None and usage >= limit:
            raise PluginMemoryLimitError('plugin exceeded its memory limit')
        return function(*inner_args, **inner_kwargs)

    return guarded(*args, **kwargs)


def _apply_address_space_limit(limit: int) -> bool:
    """Best-effort hard cap. Returns False when the platform forbids it."""
    if not hasattr(resource, 'RLIMIT_AS'):
        return False

    _soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_AS)
    effective_limit = min(
        limit,
        hard_limit if hard_limit != resource.RLIM_INFINITY else limit,
    )
    try:
        resource.setrlimit(resource.RLIMIT_AS, (effective_limit, hard_limit))
    except (ValueError, OSError):
        return False
    return True


def _memory_usage_probe() -> Optional[int]:
    """
    Returns the current address-space footprint in bytes, or None when it
    cannot be determined on this platform. Indirection keeps the soft-limit
    fallback deterministic and testable without allocating real memory.
    """
    return None


def _capture_error(
    plugin_name: str,
    filename: str,
    error: BaseException,
    line_number: int,
) -> PluginError:
    owns_sink = get_plugin_error_sink() is None
    if owns_sink:
        # No scanner registered a sink (e.g. adhoc string scanning): use a
        # temporary one and detach it immediately so global state stays clean.
        sink = bind_plugin_error_sink(PluginErrorSink())
    else:
        sink = get_plugin_error_sink()

    try:
        summary = sink.record(
            filename=filename,
            plugin=plugin_name,
            error=error,
            line_number=line_number,
        )
    finally:
        if owns_sink:
            reset_plugin_error_sink(sink)

    # Only generic, sanitized metadata is logged -- never the exception text.
    log.error(
        (
            'Plugin "{plugin}" failed while scanning "{filename}"{location} '
            '({error_type}). The failure was isolated; scanning continued.'
        ).format(
            plugin=plugin_name,
            filename=filename,
            location=f' at line {line_number}' if line_number else '',
            error_type=summary.error_type,
        ),
    )
    return summary
