from __future__ import annotations

import math
import os
from collections.abc import AsyncIterable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from io import BytesIO
from os import PathLike
from subprocess import PIPE, CalledProcessError, CompletedProcess
from typing import IO, TYPE_CHECKING, Any, TypeAlias, cast

from ..abc import AsyncResource, ByteReceiveStream, ByteSendStream
from ._concurrency_utils import gather
from ._eventloop import current_time, get_async_backend
from ._synchronization import Event
from ._tasks import (
    CancelScope,
    create_task_group,
    current_effective_deadline,
    move_on_at,
)

if TYPE_CHECKING:
    from ..abc import Process
    from ._tasks import TaskHandle

StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]
PipelineArgv: TypeAlias = Sequence[StrOrBytesPath]


@dataclass(frozen=True)
class ProcessPipelineResult:
    """Result of a completed process pipeline."""

    commands: tuple[tuple[StrOrBytesPath, ...], ...]
    returncodes: tuple[int, ...]
    stderr: tuple[bytes | None, ...]
    stderr_truncated: tuple[bool | None, ...]
    pipefail: bool

    @property
    def returncode(self) -> int:
        """Return the effective return code according to the selected semantics."""
        nonzero = [code for code in self.returncodes if code != 0]
        if not nonzero:
            return 0

        return nonzero[-1] if self.pipefail else self.returncodes[-1]

    def check_returncode(self) -> None:
        """Raise ``CalledProcessError`` if the pipeline failed."""
        if self.returncode != 0:
            raise ProcessPipelineError(self)


class ProcessPipelineError(CalledProcessError):
    """Raised when a checked process pipeline exits with a failure code."""

    def __init__(self, result: ProcessPipelineResult) -> None:
        self.result = result
        super().__init__(
            result.returncode,
            tuple(result.commands),
            output=None,
            stderr=tuple(result.stderr),
        )


class ProcessPipeline(AsyncResource):
    """A sequence of processes connected with operating system pipes."""

    def __init__(
        self,
        *,
        commands: tuple[tuple[StrOrBytesPath, ...], ...],
        processes: tuple[Process, ...],
        stderr_limits: tuple[int | None, ...],
        pipefail: bool,
        grace_period: float,
    ) -> None:
        self._commands = commands
        self._processes = processes
        self._stderr_limits = stderr_limits
        self._pipefail = pipefail
        self._grace_period = grace_period
        self._monitor_group = create_task_group()
        self._monitor_group_entered = False
        self._monitor_handle: TaskHandle[None] | None = None
        self._stdin = cast(ByteSendStream, processes[0].stdin)
        self._stdout = cast(ByteReceiveStream, processes[-1].stdout)
        self._stderr: list[ByteReceiveStream | None] = []
        self._stderr_contents: list[bytes | None] = [None] * len(processes)
        self._stderr_truncated: list[bool | None] = [None] * len(processes)
        self._returncodes: list[int | None] = [None] * len(processes)
        self._stderr_events = [Event() for _ in processes]
        self._exited = Event()
        self._closed = False
        self._closing = False

    @property
    def stdin(self) -> ByteSendStream:
        """The standard input stream of the first pipeline process."""
        return self._stdin

    @property
    def stdout(self) -> ByteReceiveStream:
        """The standard output stream of the last pipeline process."""
        return self._stdout

    @property
    def stderr(self) -> tuple[ByteReceiveStream | None, ...]:
        """Standard error streams not consumed by bounded collectors."""
        return tuple(self._stderr)

    @property
    def processes(self) -> tuple[Process, ...]:
        """The processes in pipeline order."""
        return self._processes

    @property
    def returncodes(self) -> tuple[int | None, ...]:
        """Return codes in pipeline order, with ``None`` for running processes."""
        return tuple(self._returncodes)

    def terminate(self) -> None:
        """Terminate every process in the pipeline."""
        for process in self._processes:
            if process.returncode is None:
                _terminate_process(process)

    def kill(self) -> None:
        """Kill every process in the pipeline."""
        for process in self._processes:
            if process.returncode is None:
                _kill_process(process)

    async def wait(
        self,
        *,
        check: bool = True,
        pipefail: bool | None = None,
    ) -> ProcessPipelineResult:
        """
        Wait for every process and stderr collector to finish.

        :param check: if ``True``, raise when the effective pipeline return code is
            non-zero
        :param pipefail: if ``True``, use the rightmost non-zero return code; if
            ``False``, use only the final process return code
        :return: the pipeline result

        """
        await self._exited.wait()
        result = self._build_result(self._pipefail if pipefail is None else pipefail)
        if check:
            result.check_returncode()

        return result

    async def aclose(self) -> None:
        """Close stdin, terminate the pipeline, and close all process resources."""
        if self._closed:
            return

        self._closed = True
        should_force_close = current_effective_deadline() == -math.inf
        if should_force_close:
            await self._force_close()
            return

        self._closing = True
        with CancelScope(shield=True):
            try:
                await self._stdin.aclose()
            except Exception:
                pass

            for process in self._processes:
                if process.returncode is None:
                    _terminate_process(process)

            termination_deadline = current_time() + self._grace_period
            with move_on_at(termination_deadline):
                await self._exited.wait()

            for process in self._processes:
                if process.returncode is None:
                    _kill_process(process)

            await self._exited.wait()

        if self._monitor_group_entered:
            await self._monitor_group.__aexit__(None, None, None)
            self._monitor_group_entered = False

        with CancelScope(shield=True):
            for process in self._processes:
                await process.aclose()

    async def _force_close(self) -> None:
        with CancelScope(shield=True):
            try:
                await self._stdin.aclose()
            except Exception:
                pass

            if self._monitor_handle is not None:
                self._monitor_handle.cancel()

            for process in self._processes:
                if process.returncode is None:
                    _kill_process(process)

            if self._monitor_handle is not None:
                await self._exited.wait()

            for index, process in enumerate(self._processes):
                await process.aclose()
                if process.returncode is not None:
                    self._returncodes[index] = process.returncode

        if self._monitor_group_entered:
            await self._monitor_group.__aexit__(None, None, None)
            self._monitor_group_entered = False

    async def _start_tasks(self) -> None:
        try:
            for index, limit in enumerate(self._stderr_limits):
                stream = self._processes[index].stderr
                if limit is None:
                    self._stderr.append(stream)
                    self._stderr_events[index].set()
                else:
                    self._stderr.append(None)
                    if stream is None:
                        raise RuntimeError("process stderr was not captured")

            await self._monitor_group.__aenter__()
            self._monitor_group_entered = True
            self._monitor_handle = self._monitor_group.create_task(self._monitor())
        except BaseException:
            await self._force_close()
            raise

    async def _monitor(self) -> None:
        try:
            await gather(
                *(self._watch_process(index) for index in range(len(self._processes))),
                *(
                    self._collect_stderr(
                        index,
                        cast(ByteReceiveStream, self._processes[index].stderr),
                        limit,
                    )
                    for index, limit in enumerate(self._stderr_limits)
                    if limit is not None
                ),
            )
        finally:
            self._exited.set()

    async def _collect_stderr(
        self, index: int, stream: ByteReceiveStream, limit: int
    ) -> None:
        buffer = BytesIO()
        truncated = False
        try:
            async for chunk in stream:
                if limit == 0:
                    if chunk:
                        truncated = True
                    continue

                remaining = limit - buffer.tell()
                if remaining > 0:
                    if len(chunk) <= remaining:
                        buffer.write(chunk)
                    else:
                        buffer.write(chunk[:remaining])
                        truncated = True
                elif chunk:
                    truncated = True
        except Exception:
            pass
        finally:
            self._stderr_contents[index] = buffer.getvalue()
            self._stderr_truncated[index] = truncated
            self._stderr_events[index].set()

    async def _watch_process(self, index: int) -> None:
        process = self._processes[index]
        returncode = await process.wait()
        self._returncodes[index] = returncode

        if not self._closing and index > 0 and self._returncodes[index - 1] is None:
            if index == 1:
                with CancelScope(shield=True):
                    await self._stdin.aclose()

            _terminate_process(self._processes[index - 1])

        if self._stderr_limits[index] is not None:
            await self._stderr_events[index].wait()

    def _build_result(self, pipefail: bool) -> ProcessPipelineResult:
        return ProcessPipelineResult(
            commands=self._commands,
            returncodes=cast(tuple[int, ...], tuple(self._returncodes)),
            stderr=tuple(self._stderr_contents),
            stderr_truncated=tuple(self._stderr_truncated),
            pipefail=pipefail,
        )


def _terminate_process(process: Process) -> None:
    try:
        process.terminate()
    except ProcessLookupError:
        pass


def _kill_process(process: Process) -> None:
    try:
        process.kill()
    except ProcessLookupError:
        pass


async def run_process(
    command: StrOrBytesPath | Sequence[StrOrBytesPath],
    *,
    input: bytes | None = None,
    stdin: int | IO[Any] | None = None,
    stdout: int | IO[Any] | None = PIPE,
    stderr: int | IO[Any] | None = PIPE,
    check: bool = True,
    cwd: StrOrBytesPath | None = None,
    env: Mapping[str, str] | None = None,
    startupinfo: Any = None,
    creationflags: int = 0,
    start_new_session: bool = False,
    pass_fds: Sequence[int] = (),
    user: str | int | None = None,
    group: str | int | None = None,
    extra_groups: Iterable[str | int] | None = None,
    umask: int = -1,
) -> CompletedProcess[bytes]:
    """
    Run an external command in a subprocess and wait until it completes.

    .. seealso:: :func:`subprocess.run`

    :param command: either a string to pass to the shell, or an iterable of strings
        containing the executable name or path and its arguments
    :param input: bytes passed to the standard input of the subprocess
    :param stdin: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
        a file-like object, or `None`; ``input`` overrides this
    :param stdout: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
        a file-like object, or `None`
    :param stderr: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
        :data:`subprocess.STDOUT`, a file-like object, or `None`
    :param check: if ``True``, raise :exc:`~subprocess.CalledProcessError` if the
        process terminates with a return code other than 0
    :param cwd: If not ``None``, change the working directory to this before running the
        command
    :param env: if not ``None``, this mapping replaces the inherited environment
        variables from the parent process
    :param startupinfo: an instance of :class:`subprocess.STARTUPINFO` that can be used
        to specify process startup parameters (Windows only)
    :param creationflags: flags that can be used to control the creation of the
        subprocess (see :class:`subprocess.Popen` for the specifics)
    :param start_new_session: if ``true`` the setsid() system call will be made in the
        child process prior to the execution of the subprocess. (POSIX only)
    :param pass_fds: sequence of file descriptors to keep open between the parent and
        child processes. (POSIX only)
    :param user: effective user to run the process as (Python >= 3.9, POSIX only)
    :param group: effective group to run the process as (Python >= 3.9, POSIX only)
    :param extra_groups: supplementary groups to set in the subprocess (Python >= 3.9,
        POSIX only)
    :param umask: if not negative, this umask is applied in the child process before
        running the given command (Python >= 3.9, POSIX only)
    :return: an object representing the completed process
    :raises ~subprocess.CalledProcessError: if ``check`` is ``True`` and the process
        exits with a nonzero return code

    """

    async def drain_stream(stream: AsyncIterable[bytes], index: int) -> None:
        buffer = BytesIO()
        async for chunk in stream:
            buffer.write(chunk)

        stream_contents[index] = buffer.getvalue()

    if stdin is not None and input is not None:
        raise ValueError("only one of stdin and input is allowed")

    async with await open_process(
        command,
        stdin=PIPE if input else stdin,
        stdout=stdout,
        stderr=stderr,
        cwd=cwd,
        env=env,
        startupinfo=startupinfo,
        creationflags=creationflags,
        start_new_session=start_new_session,
        pass_fds=pass_fds,
        user=user,
        group=group,
        extra_groups=extra_groups,
        umask=umask,
    ) as process:
        stream_contents: list[bytes | None] = [None, None]
        async with create_task_group() as tg:
            if process.stdout:
                tg.start_soon(drain_stream, process.stdout, 0)

            if process.stderr:
                tg.start_soon(drain_stream, process.stderr, 1)

            if process.stdin and input:
                await process.stdin.send(input)
                await process.stdin.aclose()

            await process.wait()

    output, errors = stream_contents
    if check and process.returncode != 0:
        raise CalledProcessError(cast(int, process.returncode), command, output, errors)

    return CompletedProcess(command, cast(int, process.returncode), output, errors)


async def open_pipeline(
    commands: Sequence[PipelineArgv],
    *,
    stderr_buffer_size: int | None | Sequence[int | None] = 65536,
    pipefail: bool = False,
    grace_period: float = 5.0,
    cwd: StrOrBytesPath | None = None,
    env: Mapping[str, str] | None = None,
    startupinfo: Any = None,
    creationflags: int = 0,
    start_new_session: bool = False,
    pass_fds: Sequence[int] = (),
    user: str | int | None = None,
    group: str | int | None = None,
    extra_groups: Iterable[str | int] | None = None,
    umask: int = -1,
) -> ProcessPipeline:
    """
    Start a pipeline of processes connected by standard output and input pipes.

    Each command must be an argv sequence; shell strings are intentionally not
    accepted. The first process's standard input and the last process's standard
    output are exposed as byte streams. Standard error is independently captured up
    to ``stderr_buffer_size`` bytes per process, or exposed on the pipeline when the
    limit is ``None``.

    :param commands: argv sequences in pipeline order
    :param stderr_buffer_size: maximum bytes to retain per process, a sequence of per
        process limits, or ``None`` to expose the corresponding stderr stream
    :param pipefail: default ``pipefail`` interpretation used by
        :meth:`ProcessPipeline.wait`
    :param grace_period: seconds between terminate and kill during shutdown
    :param cwd: If not ``None``, the working directory is changed before executing
    :param env: If not ``None``, it must be a mapping that defines the environment
        variables for the new processes
    :param startupinfo: an instance of :class:`subprocess.STARTUPINFO` passed to each
        process (Windows only)
    :param creationflags: flags passed to each process (see :class:`subprocess.Popen`)
    :param start_new_session: if ``true`` the setsid() system call will be made in
        each child process (POSIX only)
    :param pass_fds: sequence of file descriptors to keep open in each child process
        (POSIX only)
    :param user: effective user to run each process as (POSIX only)
    :param group: effective group to run each process as (POSIX only)
    :param extra_groups: supplementary groups to set in each subprocess (POSIX only)
    :param umask: if not negative, this umask is applied in each child process
        (POSIX only)
    :return: a running process pipeline
    :raises ValueError: if the arguments are invalid

    """

    if not commands:
        raise ValueError("at least one command is required")

    normalized_commands: list[tuple[StrOrBytesPath, ...]] = []
    for argv in commands:
        if isinstance(argv, (str, bytes, PathLike)) or not isinstance(argv, Sequence):
            raise ValueError("each pipeline command must be an argv sequence")

        if not argv:
            raise ValueError("each pipeline command must contain a program name")

        normalized_commands.append(tuple(argv))

    if isinstance(stderr_buffer_size, Sequence) and not isinstance(
        stderr_buffer_size, (str, bytes)
    ):
        limits = tuple(stderr_buffer_size)
        if len(limits) != len(normalized_commands):
            raise ValueError("stderr_buffer_size must have one value per process")
    else:
        limits = (cast("int | None", stderr_buffer_size),) * len(normalized_commands)

    for limit in limits:
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
        ):
            raise ValueError("stderr buffer sizes must be non-negative integers")

    if not math.isfinite(grace_period) or grace_period < 0:
        raise ValueError("grace_period must be a finite, non-negative number")

    process_count = len(normalized_commands)
    pipes = [os.pipe() for _ in range(process_count - 1)]
    for read_fd, write_fd in pipes:
        os.set_inheritable(read_fd, False)
        os.set_inheritable(write_fd, False)

    open_parent_fds = {fd for pair in pipes for fd in pair}
    processes: list[Process] = []

    def close_parent_fd(fd: int) -> None:
        if fd in open_parent_fds:
            os.close(fd)
            open_parent_fds.remove(fd)

    try:
        for index, argv in enumerate(normalized_commands):
            if index == 0:
                stdin_fd = None
                stdin = PIPE
            else:
                stdin_fd = pipes[index - 1][0]
                os.set_inheritable(stdin_fd, True)
                stdin = stdin_fd

            if index == process_count - 1:
                stdout_fd = None
                stdout = PIPE
            else:
                stdout_fd = pipes[index][1]
                os.set_inheritable(stdout_fd, True)
                stdout = stdout_fd

            process = await open_process(
                argv,
                stdin=stdin,
                stdout=stdout,
                stderr=PIPE,
                cwd=cwd,
                env=env,
                startupinfo=startupinfo,
                creationflags=creationflags,
                start_new_session=start_new_session,
                pass_fds=pass_fds,
                user=user,
                group=group,
                extra_groups=extra_groups,
                umask=umask,
            )
            if stdin_fd is not None:
                os.set_inheritable(stdin_fd, False)

            if stdout_fd is not None:
                os.set_inheritable(stdout_fd, False)

            processes.append(process)
            if index > 0:
                close_parent_fd(cast(int, stdin))
                close_parent_fd(pipes[index - 1][1])
    except BaseException:
        with CancelScope(shield=True):
            for fd in tuple(open_parent_fds):
                os.close(fd)
                open_parent_fds.remove(fd)

            for process in processes:
                _kill_process(process)
                await process.aclose()

        raise

    pipeline = ProcessPipeline(
        commands=tuple(normalized_commands),
        processes=tuple(processes),
        stderr_limits=limits,
        pipefail=pipefail,
        grace_period=grace_period,
    )
    await pipeline._start_tasks()

    return pipeline


async def open_process(
    command: StrOrBytesPath | Sequence[StrOrBytesPath],
    *,
    stdin: int | IO[Any] | None = PIPE,
    stdout: int | IO[Any] | None = PIPE,
    stderr: int | IO[Any] | None = PIPE,
    cwd: StrOrBytesPath | None = None,
    env: Mapping[str, str] | None = None,
    startupinfo: Any = None,
    creationflags: int = 0,
    start_new_session: bool = False,
    pass_fds: Sequence[int] = (),
    user: str | int | None = None,
    group: str | int | None = None,
    extra_groups: Iterable[str | int] | None = None,
    umask: int = -1,
) -> Process:
    """
    Start an external command in a subprocess.

    .. seealso:: :class:`subprocess.Popen`

    :param command: either a string to pass to the shell, or an iterable of strings
        containing the executable name or path and its arguments
    :param stdin: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`, a
        file-like object, or ``None``
    :param stdout: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
        a file-like object, or ``None``
    :param stderr: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
        :data:`subprocess.STDOUT`, a file-like object, or ``None``
    :param cwd: If not ``None``, the working directory is changed before executing
    :param env: If env is not ``None``, it must be a mapping that defines the
        environment variables for the new process
    :param creationflags: flags that can be used to control the creation of the
        subprocess (see :class:`subprocess.Popen` for the specifics)
    :param startupinfo: an instance of :class:`subprocess.STARTUPINFO` that can be used
        to specify process startup parameters (Windows only)
    :param start_new_session: if ``true`` the setsid() system call will be made in the
        child process prior to the execution of the subprocess. (POSIX only)
    :param pass_fds: sequence of file descriptors to keep open between the parent and
        child processes. (POSIX only)
    :param user: effective user to run the process as (POSIX only)
    :param group: effective group to run the process as (POSIX only)
    :param extra_groups: supplementary groups to set in the subprocess (POSIX only)
    :param umask: if not negative, this umask is applied in the child process before
        running the given command (POSIX only)
    :return: an asynchronous process object

    """
    kwargs: dict[str, Any] = {}
    if user is not None:
        kwargs["user"] = user

    if group is not None:
        kwargs["group"] = group

    if extra_groups is not None:
        kwargs["extra_groups"] = extra_groups

    if umask >= 0:
        kwargs["umask"] = umask

    return await get_async_backend().open_process(
        command,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        cwd=cwd,
        env=env,
        startupinfo=startupinfo,
        creationflags=creationflags,
        start_new_session=start_new_session,
        pass_fds=pass_fds,
        **kwargs,
    )
