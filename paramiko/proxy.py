# Copyright (C) 2012  Yipit, Inc <coders@yipit.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


import os
import shlex
import signal
from select import select
import socket
import time

# Try-and-ignore import so platforms w/o subprocess (eg Google App Engine) can
# still import paramiko.
subprocess, subprocess_import_error = None, None
try:
    import subprocess
except ImportError as e:
    subprocess_import_error = e

from paramiko.ssh_exception import (
    ProxyCommandFailure,
    ProxyCommandNotFound,
    ProxyCommandPermissionDenied,
    ProxyCommandValidationError,
)
from paramiko.util import ClosingContextManager


#: Maximum number of arguments allowed in a ProxyCommand argv.
MAX_PROXY_COMMAND_ARGS = 64

#: Maximum length, in characters, of any single ProxyCommand argument.
MAX_PROXY_COMMAND_ARG_LENGTH = 4096

#: Maximum number of characters of proxy stderr surfaced in error messages.
MAX_PROXY_STDERR_LENGTH = 512

#: Shell metacharacters (plus newlines and NUL) rejected in ProxyCommand
#: arguments unless shell mode is explicitly enabled.
_SHELL_METACHARACTERS = frozenset(";&|`$<>\n\r\x00")

#: Environment variable names forwarded to the proxy subprocess. Anything
#: else (agent sockets, cloud credentials, tokens, ...) is stripped so the
#: proxy command cannot inherit secrets from the parent process.
_SAFE_ENVIRONMENT_NAMES = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
)

#: Lowercased substrings marking stderr lines that likely carry credentials;
#: such lines are redacted from error messages.
_SECRET_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "private key",
)


def _subprocess_env():
    """
    Build a minimal environment for the proxy subprocess, forwarding only
    whitelisted variables so agent sockets and credentials never leak.
    """
    env = {}
    for name in _SAFE_ENVIRONMENT_NAMES:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    env.setdefault("PATH", os.defpath)
    return env


def _replace_tokens(argument, tokens):
    """
    Expand ``%h``/``%p``/``%r`` style tokens inside a single argv element,
    preserving that element's boundary no matter what the values contain.
    """
    for token, value in tokens.items():
        argument = argument.replace(token, value)
    return argument


def _validate_argv(argv):
    """
    Enforce argument count/length limits and reject shell metacharacters,
    newlines and NUL bytes in a ProxyCommand argv. Returns ``argv``.
    """
    if not argv:
        raise ProxyCommandValidationError("", "ProxyCommand may not be empty")
    if len(argv) > MAX_PROXY_COMMAND_ARGS:
        raise ProxyCommandValidationError(
            " ".join(argv),
            "ProxyCommand has {} arguments; the limit is {}".format(
                len(argv), MAX_PROXY_COMMAND_ARGS
            ),
        )
    for argument in argv:
        if len(argument) > MAX_PROXY_COMMAND_ARG_LENGTH:
            raise ProxyCommandValidationError(
                " ".join(argv),
                "ProxyCommand argument exceeds the {} character limit".format(
                    MAX_PROXY_COMMAND_ARG_LENGTH
                ),
            )
        bad = sorted(_SHELL_METACHARACTERS.intersection(argument))
        if bad:
            raise ProxyCommandValidationError(
                " ".join(argv),
                "ProxyCommand argument {!r} contains forbidden shell "
                "metacharacter(s): {}".format(argument, " ".join(bad)),
            )
    return argv


def _sanitize_stderr(data):
    """
    Render proxy stderr safe for inclusion in error messages: decode, drop
    lines that look like they carry secrets, strip control characters and
    truncate to a bounded length.
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    if not isinstance(data, str):
        return ""
    lines = []
    for line in data.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if any(hint in lowered for hint in _SECRET_HINTS):
            continue
        lines.append("".join(c for c in stripped if c.isprintable()))
    return "; ".join(lines)[:MAX_PROXY_STDERR_LENGTH]


class ProxyCommand(ClosingContextManager):
    """
    Wraps a subprocess running ProxyCommand-driven programs.

    This class implements a the socket-like interface needed by the
    `.Transport` and `.Packetizer` classes. Using this class instead of a
    regular socket makes it possible to talk with a Popen'd command that will
    proxy traffic between the client and a server hosted in another machine.

    Instances of this class may be used as context managers.
    """

    def __init__(self, command_line, allow_shell=False):
        """
        Create a new CommandProxy instance. The instance created by this
        class can be passed as an argument to the `.Transport` class.

        :param command_line:
            the command that should be executed and used as the proxy. May
            be a string (parsed into an argv with `shlex.split`) or a
            sequence of strings (used verbatim as the argv, preserving
            per-argument boundaries).
        :param bool allow_shell:
            when ``True``, the command is executed through the platform
            shell, matching OpenSSH's legacy ProxyCommand behavior. The
            trust boundary in that mode is: the command text itself is
            trusted shell code, so it must come from a trusted config, and
            untrusted values must only ever enter it via
            `ProxyCommand.from_config`, which shell-quotes substituted
            tokens instead of splicing raw user input into the string.
            When ``False`` (the default) no shell is involved and arguments
            containing shell metacharacters, newlines or NUL bytes are
            rejected with `.ProxyCommandValidationError`.

        .. versionchanged:: 3.5
            Added argv-sequence support, argument validation, subprocess
            environment isolation and the ``allow_shell`` switch.
        """
        if subprocess is None:
            raise subprocess_import_error
        allow_shell = bool(allow_shell)
        if isinstance(command_line, str):
            if allow_shell:
                self.cmd = [command_line]
                popen_args = command_line
            else:
                self.cmd = _validate_argv(shlex.split(command_line))
                popen_args = list(self.cmd)
        else:
            argv = [str(argument) for argument in command_line]
            if allow_shell:
                # Quote each element so substituted values cannot be
                # reinterpreted as shell syntax.
                self.cmd = argv
                popen_args = shlex.join(argv)
            else:
                self.cmd = _validate_argv(argv)
                popen_args = list(self.cmd)
        try:
            self.process = subprocess.Popen(
                popen_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                shell=allow_shell,
                env=_subprocess_env(),
            )
        except FileNotFoundError:
            raise ProxyCommandNotFound(
                " ".join(self.cmd),
                "command not found: {}".format(self.cmd[0] if self.cmd else ""),
            )
        except PermissionError:
            raise ProxyCommandPermissionDenied(
                " ".join(self.cmd),
                "permission denied: {}".format(
                    self.cmd[0] if self.cmd else ""
                ),
            )
        except OSError as e:
            raise ProxyCommandFailure(
                " ".join(self.cmd), e.strerror or str(e)
            )
        self.timeout = None

    @classmethod
    def from_config(
        cls, command, hostname=None, port=None, username=None,
        allow_shell=False,
    ):
        """
        Build a `ProxyCommand` from an ssh_config ``ProxyCommand`` value,
        expanding ``%h``/``%p``/``%r`` tokens per argument so substituted
        values (hostnames with spaces, hostile metacharacters, ...) can
        never reshape the command's argument boundaries.

        :param command: the configured command, as a string or argv sequence
        :param hostname: value substituted for ``%h``
        :param port: value substituted for ``%p``
        :param username: value substituted for ``%r``
        :param bool allow_shell: see `__init__`; substituted tokens are
            always shell-quoted in that mode, never spliced in raw.

        .. versionadded:: 3.5
        """
        tokens = {}
        if hostname is not None:
            tokens["%h"] = str(hostname)
        if port is not None:
            tokens["%p"] = str(port)
        if username is not None:
            tokens["%r"] = str(username)
        if isinstance(command, str):
            if allow_shell:
                expanded = command
                for token, value in tokens.items():
                    expanded = expanded.replace(token, shlex.quote(value))
                return cls(expanded, allow_shell=True)
            argv = shlex.split(command)
            return cls([_replace_tokens(arg, tokens) for arg in argv])
        argv = [_replace_tokens(str(arg), tokens) for arg in command]
        return cls(argv, allow_shell=allow_shell)

    def _augment_error(self, error):
        """
        Enrich an IO error message with the proxy's exit status and a
        sanitized excerpt of its stderr, when available.
        """
        try:
            returncode = self.process.poll()
        except Exception:
            return error
        if not isinstance(returncode, int) or returncode == 0:
            return error
        detail = ""
        try:
            detail = _sanitize_stderr(self.process.stderr.read())
        except Exception:
            pass
        message = "proxy command exited with status {}".format(returncode)
        if detail:
            message = "{}: {}".format(message, detail)
        return "{} ({})".format(error, message)

    def send(self, content):
        """
        Write the content received from the SSH client to the standard
        input of the forked command.

        :param str content: string to be sent to the forked command
        """
        try:
            self.process.stdin.write(content)
        except IOError as e:
            # There was a problem with the child process. It probably
            # died and we can't proceed. The best option here is to
            # raise an exception informing the user that the informed
            # ProxyCommand is not working.
            raise ProxyCommandFailure(
                " ".join(self.cmd), self._augment_error(e.strerror)
            )
        return len(content)

    def recv(self, size):
        """
        Read from the standard output of the forked program.

        :param int size: how many chars should be read

        :return: the string of bytes read, which may be shorter than requested
        """
        try:
            buffer = b""
            start = time.time()
            while len(buffer) < size:
                select_timeout = None
                if self.timeout is not None:
                    elapsed = time.time() - start
                    if elapsed >= self.timeout:
                        raise socket.timeout()
                    select_timeout = self.timeout - elapsed

                r, w, x = select([self.process.stdout], [], [], select_timeout)
                if r and r[0] == self.process.stdout:
                    buffer += os.read(
                        self.process.stdout.fileno(), size - len(buffer)
                    )
            return buffer
        except socket.timeout:
            if buffer:
                # Don't raise socket.timeout, return partial result instead
                return buffer
            raise  # socket.timeout is a subclass of IOError
        except IOError as e:
            raise ProxyCommandFailure(
                " ".join(self.cmd), self._augment_error(e.strerror)
            )

    def close(self):
        os.kill(self.process.pid, signal.SIGTERM)

    @property
    def closed(self):
        return self.process.returncode is not None

    @property
    def _closed(self):
        # Concession to Python 3 socket-like API
        return self.closed

    def settimeout(self, timeout):
        self.timeout = timeout
