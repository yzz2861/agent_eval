import os
import subprocess
from collections import deque
from typing import Any
from typing import cast
from typing import Deque
from typing import Generator
from typing import Iterable
from typing import List
from typing import NamedTuple
from typing import Set
from typing import Tuple
from typing import Union

from ..filters.allowlist import is_line_allowlisted
from ..plugins.base import MultiLinePlugin
from ..settings import get_filters
from ..settings import get_plugins
from ..settings import get_settings
from ..transformers import get_transformed_file
from ..types import NamedIO
from ..types import SelfAwareCallable
from ..util import git
from ..util.code_snippet import CodeSnippet
from ..util.code_snippet import get_code_snippet
from ..util.inject import call_function_with_arguments
from ..util.path import get_relative_path
from .log import log
from .plugins import Plugin
from .potential_secret import PotentialSecret


#: Maximum number of recent lines retained in the bounded sliding window
#: used for filter context and multi-line plugin analysis. This bounds
#: memory usage, so arbitrarily large files are never loaded in full.
SCAN_WINDOW_LINES = 100

#: Number of lines shared between consecutive multi-line analysis windows.
#: Secrets spanning up to this many lines are guaranteed to appear in full
#: within at least one window, even if they straddle a window boundary.
SCAN_WINDOW_OVERLAP = 50


class _WindowLine(NamedTuple):
    """A single line tracked by the scanning window, preserving its
    original position in the file."""
    line_number: int
    offset: int     # character offset of the line start, in the decoded stream
    text: str


def get_files_to_scan(
    *paths: str,
    should_scan_all_files: bool = False,
    root: str = '',
) -> Generator[str, None, None]:
    """
    If we specify specific files, we should be able to scan them. This abides by the
    Principle of Least Surprise -- so users don't have to do:

        $ detect-secrets scan test_data/config.env --all-files

    to scan the specific file.

        >>> list(get_files_to_scan('test_data/config.env')) == ['test_data/config.env']

    In a similar way,

        >>> list(get_files_to_scan('test_data/config.env', '.secrets.baseline')) == \
        ...     ['test_data/config.env', '.secrets.baseline']

    If we specify directories, then we should use git tracked files when possible. To
    override this behavior, we can specify `should_scan_all_files=True`, which will force
    the scan for all files.

    See test cases for more details.

    :param root: if not specified, will assume current repository as root.
    """
    if root:
        root = os.path.realpath(root)

    # First, we determine the appropriate filtering mode to be used.
    # If this is True, then it will consider everything to be valid.
    # Otherwise, it will only list the files that are valid.
    valid_paths: Union[bool, Set[str]] = True
    for path in paths:
        # Since this is not a directory, we assume that it is a file proper, and automatically
        # consider it valid.
        if not os.path.isdir(path):
            continue

        if not should_scan_all_files:
            try:
                valid_paths = git.get_tracked_files(git.get_root_directory(root))
            except subprocess.CalledProcessError:
                log.warning('Did not detect git repository. Try scanning all files instead.')
                valid_paths = False

        # Since valid_paths attempts to get *all* tracked files in the repository, we just need
        # to initialize it once.
        break

    if not valid_paths:
        yield from []
        return

    for path in paths:
        iterator = (
            cast(List[Tuple], [(root or os.getcwd(), None, [path])])
            if os.path.isfile(path)
            else os.walk(path)
        )

        for path_root, _, filenames in iterator:
            for filename in filenames:
                relative_path = get_relative_path(
                    root=root or os.getcwd(),
                    path=os.path.join(path_root, filename),
                )
                if not relative_path:
                    # e.g. symbolic links may be pointing outside the root directory
                    continue

                if (
                    valid_paths is True
                    or relative_path in valid_paths
                ):
                    yield relative_path


def scan_line(line: str) -> Generator[PotentialSecret, None, None]:
    """Used for adhoc string scanning."""
    # Disable this, since it doesn't make sense to run this for adhoc usage.
    get_settings().disable_filters(
        'detect_secrets.filters.common.is_invalid_file',
    )
    get_filters.cache_clear()
    context = get_code_snippet(lines=[line], line_number=1)

    yield from (
        secret
        for plugin in get_plugins()
        for secret in _scan_line(
            plugin=plugin,
            filename='adhoc-string-scan',
            line=line,
            line_number=0,
            enable_eager_search=True,
            context=context,
        )
        if not _is_filtered_out(
            required_filter_parameters=['context'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
            context=context,
        )
    )


def scan_file(filename: str) -> Generator[PotentialSecret, None, None]:
    try:
        if not get_plugins():   # pragma: no cover
            log.error('No plugins to scan with!')
            return
    except FileNotFoundError:
        log.error('Unable to load plugins!')
        return

    if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
        return

    try:
        has_secret = False
        for lines in _get_lines_from_file(filename):
            for secret in _process_line_based_plugins(
                lines=enumerate(lines, start=1),
                filename=filename,
            ):
                has_secret = True
                yield secret

            if has_secret:
                break
    except IOError:
        log.warning(f'Unable to open file: {filename}')
        return


def scan_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    """
    :raises: ImportError
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    for filename, lines in _get_lines_from_diff(diff):
        yield from _process_line_based_plugins(lines, filename=filename)


def scan_for_allowlisted_secrets_in_file(filename: str) -> Generator[PotentialSecret, None, None]:
    """
    Developers are able to add individual lines to the allowlist using
    `detect_secrets.filters.allowlist.is_line_allowlisted`. However, there are
    times when we want to verify that no *actual* secrets are added to the codebase
    via this feature.

    This scans specifically for these lines, and ignores everything else.
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    if _is_filtered_out(
        required_filter_parameters=['filename'],
        filename=filename,
    ):
        return

    # NOTE: Unlike `scan_file`, we don't ever have to use eager file transformers, since we already
    # know which lines we want to scan.
    try:
        for lines in _get_lines_from_file(filename):
            yield from _scan_for_allowlisted_secrets_in_lines(enumerate(lines, start=1), filename)
            break
    except IOError:
        log.warning(f'Unable to open file: {filename}')
        return


def scan_for_allowlisted_secrets_in_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    for filename, lines in _get_lines_from_diff(diff):
        yield from _scan_for_allowlisted_secrets_in_lines(lines, filename)


def _scan_for_allowlisted_secrets_in_lines(
    lines: Iterable[Tuple[int, str]],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    # We control the setting here because it makes more sense than requiring the caller
    # to set this setting before calling this function.
    get_settings().disable_filters('detect_secrets.filters.allowlist.is_line_allowlisted')
    get_filters.cache_clear()

    line_numbers, lines = zip(*lines)
    line_content = [line.rstrip() for line in lines]
    for line_number, line in zip(line_numbers, line_content):
        context = get_code_snippet(line_content, line_number)
        if not is_line_allowlisted(
            filename=filename,
            line=line,
            context=context,
        ):
            continue

        if _is_filtered_out(required_filter_parameters=['line'], filename=filename, line=line):
            continue

        for plugin in get_plugins():
            yield from _scan_line(
                plugin=plugin,
                filename=filename,
                line=line,
                line_number=line_number,
                context=context,
            )


def _get_lines_from_file(filename: str) -> Generator[Iterable[str], None, None]:
    """
    This attempts to get lines in a given file. If no more lines are needed, the caller
    is responsible for breaking out of this loop.

    :raises: IOError
    :raises: FileNotFoundError
    """
    with open(filename) as f:
        log.info(f'Checking file: {filename}')

        try:
            lines = get_transformed_file(cast(NamedIO, f))
        except UnicodeDecodeError:
            # Undecodable (e.g. binary) files must not be silently treated
            # as clean files -- surface a diagnostic instead.
            log.warning(f'Unable to decode file as text, skipping: {filename}')
            return

        if lines:
            yield lines
        else:
            # Stream the file line by line, so the scanning window stays
            # bounded regardless of file size.
            yield _read_lines_safely(cast(NamedIO, f))

        # If the above lines don't prove to be useful to the caller, try using eager transformers.
        f.seek(0)
        try:
            lines = get_transformed_file(cast(NamedIO, f), use_eager_transformers=True)
        except UnicodeDecodeError:
            log.warning(f'Unable to decode file as text, skipping: {filename}')
            return

        if not lines:
            return

        yield lines


def _read_lines_safely(file: NamedIO) -> Generator[str, None, None]:
    """Streams lines from a file object, one at a time.

    Undecodable content is reported (rather than silently treated as a
    clean file), and iteration stops at that point.
    """
    try:
        yield from file
    except UnicodeDecodeError:
        log.warning(f'Unable to decode file as text, skipping: {file.name}')


def _get_lines_from_diff(diff: str) -> Generator[Tuple[str, List[Tuple[int, str]]], None, None]:
    """
    :raises: ImportError
    """
    # Local imports, so that we don't need to require unidiff for versions of
    # detect-secrets that don't use it.
    from unidiff import PatchSet

    patch_set = PatchSet.from_string(diff)
    for patch_file in patch_set:
        filename = patch_file.path
        if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
            continue

        yield (
            filename,
            [
                (line.target_line_no, line.value)
                for chunk in patch_file
                # target_lines refers to incoming (new) changes
                for line in chunk.target_lines()
                if line.is_added
            ],
        )


def _process_line_based_plugins(
    lines: Iterable[Tuple[int, str]],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    line_plugins, multiline_plugins = _partition_plugins()

    # Bounded sliding window over the most recently seen lines. It preserves
    # the original line numbers and offsets, supplies context to filters, and
    # feeds multi-line plugins -- all without loading the whole file into memory.
    window: Deque[_WindowLine] = deque(maxlen=SCAN_WINDOW_LINES)
    lines_since_multiline_scan = 0
    seen_multiline_secrets: Set[Tuple[str, str, int]] = set()
    offset = 0

    for line_number, raw_line in lines:
        log.debug(f'Processing {filename}:{line_number}')
        line = raw_line.rstrip()
        window.append(_WindowLine(line_number=line_number, offset=offset, text=line))
        offset += len(raw_line)
        lines_since_multiline_scan += 1

        code_snippet = _get_code_snippet_from_window(window, line_number)

        # We apply line-specific filters, and see whether that allows us to quit early.
        if not _is_filtered_out(
            required_filter_parameters=['line'],
            filename=filename,
            line=line,
            context=code_snippet,
        ):
            yield from (
                secret
                for plugin in line_plugins
                for secret in _scan_line_safely(
                    plugin=plugin,
                    filename=filename,
                    line=line,
                    line_number=line_number,
                    context=code_snippet,
                )
                if not _is_filtered_out(
                    required_filter_parameters=['context'],
                    filename=secret.filename,
                    secret=secret.secret_value,
                    plugin=plugin,
                    line=line,
                    context=code_snippet,
                )
            )

        if (
            multiline_plugins
            and lines_since_multiline_scan >= SCAN_WINDOW_LINES - SCAN_WINDOW_OVERLAP
        ):
            yield from _scan_multiline_window(
                plugins=multiline_plugins,
                filename=filename,
                window=window,
                seen=seen_multiline_secrets,
                is_final=False,
            )
            lines_since_multiline_scan = 0

    # Flush the trailing window, so secrets ending at EOF are not missed.
    if multiline_plugins and lines_since_multiline_scan:
        yield from _scan_multiline_window(
            plugins=multiline_plugins,
            filename=filename,
            window=window,
            seen=seen_multiline_secrets,
            is_final=True,
        )


def _partition_plugins() -> Tuple[List[Plugin], List[Plugin]]:
    """Splits the configured plugins into single-line plugins and
    multi-line (window based) plugins."""
    line_plugins = []
    multiline_plugins = []
    for plugin in get_plugins():
        if isinstance(plugin, MultiLinePlugin):
            multiline_plugins.append(plugin)
        else:
            line_plugins.append(plugin)

    return line_plugins, multiline_plugins


def _get_code_snippet_from_window(
    window: Deque[_WindowLine],
    line_number: int,
) -> CodeSnippet:
    """Builds a CodeSnippet for the given absolute line number, from the
    lines currently held in the bounded window."""
    start_line_number = window[0].line_number
    target_index = min(max(line_number - start_line_number, 0), len(window) - 1)

    return CodeSnippet(
        snippet=[entry.text for entry in window],
        start_line=start_line_number - 1,
        target_index=target_index,
    )


def _scan_multiline_window(
    plugins: List[Plugin],
    filename: str,
    window: Deque[_WindowLine],
    seen: Set[Tuple[str, str, int]],
    is_final: bool,
) -> Generator[PotentialSecret, None, None]:
    if not window:
        return

    lines = [entry.text for entry in window]
    start_line_number = window[0].line_number
    # Incomplete detections (those without an end line) this close to the
    # trailing edge of the window may still complete in a later window, so
    # they are deferred unless this is the final window. This prevents
    # reporting both a partial match and the full multi-line secret.
    defer_after_line = window[-1].line_number - SCAN_WINDOW_OVERLAP

    for plugin in plugins:
        try:
            secrets = call_function_with_arguments(
                plugin.analyze_multiline,
                filename=filename,
                lines=lines,
                line_number=start_line_number,
                offset=window[0].offset,
            )
        except Exception as e:
            # A misbehaving plugin must not abort the scan, or mask the
            # results of other plugins.
            log.warning(
                f'Plugin {plugin.__class__.__name__} failed to scan '
                f'{filename}:{start_line_number}-{window[-1].line_number}: {e}',
            )
            continue

        for secret in secrets or []:
            if (
                not is_final
                and getattr(secret, 'end_line_number', None) is None
                and secret.line_number > defer_after_line
            ):
                continue

            # Consecutive windows overlap, so the same secret may be found
            # more than once. Only report it the first time.
            key = (secret.type, secret.secret_hash, secret.line_number)
            if key in seen:
                continue
            seen.add(key)

            code_snippet = _get_code_snippet_from_window(window, secret.line_number)
            if _is_filtered_out(
                required_filter_parameters=['secret'],
                filename=secret.filename,
                secret=secret.secret_value,
                plugin=plugin,
                line=code_snippet.target_line,
            ):
                continue

            if _is_filtered_out(
                required_filter_parameters=['context'],
                filename=secret.filename,
                secret=secret.secret_value,
                plugin=plugin,
                line=code_snippet.target_line,
                context=code_snippet,
            ):
                continue

            yield secret


def _scan_line_safely(
    plugin: Plugin,
    filename: str,
    line: str,
    line_number: int,
    context: CodeSnippet,
    **kwargs: Any,
) -> Generator[PotentialSecret, None, None]:
    try:
        yield from _scan_line(
            plugin=plugin,
            filename=filename,
            line=line,
            line_number=line_number,
            context=context,
            **kwargs,
        )
    except Exception as e:
        # A misbehaving plugin must not abort the scan, or mask the
        # results of other plugins.
        log.warning(
            f'Plugin {plugin.__class__.__name__} failed to scan '
            f'{filename}:{line_number}: {e}',
        )


def _scan_line(
    plugin: Plugin,
    filename: str,
    line: str,
    line_number: int,
    context: CodeSnippet,
    **kwargs: Any,
) -> Generator[PotentialSecret, None, None]:
    # NOTE: We don't apply filter functions here yet, because we don't have any filters
    # that operate on (filename, line, plugin) without `secret`
    secrets = call_function_with_arguments(
        plugin.analyze_line,
        filename=filename,
        line=line,
        line_number=line_number,
        context=context,
        **kwargs,
    )
    if not secrets:
        return

    yield from (
        secret
        for secret in secrets
        if not _is_filtered_out(
            required_filter_parameters=['secret'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
        )
    )


def _is_filtered_out(required_filter_parameters: Iterable[str], **kwargs: Any) -> bool:
    for filter_fn in get_filters_with_parameter(*required_filter_parameters):
        try:
            if call_function_with_arguments(filter_fn, **kwargs):
                if 'secret' in kwargs:
                    debug_msg = f'Skipping "{0}" due to `{1}`.'.format(
                        kwargs['secret'],
                        filter_fn.path,
                    )
                elif list(kwargs.keys()) == ['filename']:
                    # We want to make sure this is only run if we're skipping files (as compared
                    # to other filters that may include `filename` as a parameter).
                    debug_msg = 'Skipping "{0}" due to `{1}`'.format(
                        kwargs['filename'],
                        filter_fn.path,
                    )
                else:
                    debug_msg = 'Skipping secret due to `{0}`.'.format(filter_fn.path)

                log.info(debug_msg)
                return True
        except TypeError:
            # Skipping non-compatible filters
            pass

    return False


def get_filters_with_parameter(*parameters: str) -> List[SelfAwareCallable]:
    """
    The issue of our method of dependency injection is that functions will be called multiple
    times. For example, if we have two functions:

    >>> def foo(filename: str): ...
    >>> def bar(filename: str, secret: str): ...

    our invocation of `call_function_with_arguments(filename=filename, secret=secret)`
    will run both of these functions. While expected, this results in multiple invocations of
    the same function, which can be less than ideal (especially if we have a heavy duty filter).

    To address this, we filter our filters with this function. It will return the functions
    that accept a minimum set of parameters, to avoid duplicative work. For instance,

    >>> get_filters_with_parameter('secret')
    [bar]
    """
    minimum_parameters = set(parameters)

    return [
        filter
        for filter in get_filters()
        if minimum_parameters <= filter.injectable_variables
    ]
