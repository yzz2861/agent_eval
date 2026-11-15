import math
import re
import string
from abc import ABCMeta
from contextlib import contextmanager
from typing import Any
from typing import cast
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Set

from ..core.log import log
from ..core.potential_secret import PotentialSecret
from .base import BasePlugin
from detect_secrets.util.code_snippet import CodeSnippet


class InputBudgetExceeded(Exception):
    """Raised when a scan must abort because its configured input budget was exceeded."""

    def __init__(self, reason: str, limit: int, observed: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.limit = limit
        self.observed = observed


class HighEntropyStringsPlugin(BasePlugin, metaclass=ABCMeta):
    """Base class for string pattern matching."""

    # Input budgets. These guard against pathological inputs (e.g. a single multi-megabyte
    # base64 blob) that would otherwise pin a CPU core while the regex engine and the entropy
    # calculation churn through the data. The defaults are generous enough that realistic
    # credentials and configuration lines are never affected.
    MAX_LINE_LENGTH = 10000               # characters allowed in a single scanned line
    MIN_CANDIDATE_LENGTH = 6              # minimum candidate length worth an entropy calculation
    MAX_CANDIDATES_PER_LINE = 1000        # maximum candidates inspected on a single line
    MAX_SCANNED_BYTES = 10 * 1024 * 1024  # maximum bytes (utf-8) accounted for per line

    def __init__(self, charset: str, limit: float) -> None:
        if limit < 0 or limit > 8:
            raise ValueError(
                "The limit set for HighEntropyStrings must be between 0.0 and 8.0",
            )

        self.charset = charset
        self.entropy_limit = limit

        # We require quoted strings to reduce noise.
        # NOTE: We need this to be a capturing group, so back-reference can work.
        self.regex = re.compile(r'([\'"])([{}]+)(\1)'.format(re.escape(charset)))

        # Lookup table used by the linear-time window scanner. Membership tests against the
        # compiled regex alone would force us back into regex backtracking.
        self._charset_members = set(charset)
        self._requires_quotes = True

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        for result in self.regex.findall(string):
            if isinstance(result, tuple):
                # This occurs on the default regex, but not on the eager regex.
                result = result[1]

            # We perform the shannon entropy check in `analyze_line` instead, so that we have
            # more control over **when** we display the results of this plugin. Specifically,
            # this allows us to show the computed entropy values during adhoc string scans.
            yield result

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet = None,
        enable_eager_search: bool = False,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        budget = self._make_budget(line)

        try:
            output = self._collect_potential_secrets(
                filename=filename,
                line=line,
                line_number=line_number,
                budget=budget,
            )
        except InputBudgetExceeded as exc:
            self._log_skip(filename, line_number, exc)
            return set()

        if output or not enable_eager_search:
            # NOTE: We perform the limit filter at this layer (rather than analyze_string) so
            # that we can surface secrets that do not meet the limit criteria when
            # enable_eager_search=True.
            return {
                secret
                for secret in output
                if (
                    self.calculate_shannon_entropy(cast(str, secret.secret_value)) >
                    self.entropy_limit
                )
            }

        # This is mainly used for adhoc string scanning. As such, it is just bad UX to require
        # quotes around the expected secret. In these cases, we only try to search it without
        # requiring quotes when we cannot find any results *with* quotes.
        #
        # NOTE: Since we currently assume this is only used for adhoc string scanning, we
        # perform the limit filtering outside this function. This allows us to see *why* secrets
        # have failed to be caught with our configured limit.
        with self.non_quoted_string_regex(is_exact_match=False):
            try:
                return self._collect_potential_secrets(
                    filename=filename,
                    line=line,
                    line_number=line_number,
                    budget=budget,
                )
            except InputBudgetExceeded as exc:
                self._log_skip(filename, line_number, exc)
                return set()

    def _make_budget(self, line: str) -> Dict[str, int]:
        return {
            "line_length": len(line),
            "scanned_bytes": 0,
            "max_scanned_bytes": self.MAX_SCANNED_BYTES,
            "candidates": 0,
            "max_candidates": self.MAX_CANDIDATES_PER_LINE,
        }

    def _collect_potential_secrets(
        self,
        filename: str,
        line: str,
        line_number: int,
        budget: Dict[str, int],
    ) -> Set[PotentialSecret]:
        output: Set[PotentialSecret] = set()
        for candidate in self._iter_candidates(line, budget):
            output.add(
                PotentialSecret(
                    type=self.secret_type,
                    filename=filename,
                    secret=candidate,
                    line_number=line_number,
                ),
            )

        return output

    def _iter_candidates(
        self,
        line: str,
        budget: Dict[str, int],
    ) -> Generator[str, None, None]:
        # Streams candidates out of ``line`` in a single linear pass.
        #
        # Unlike ``re.findall`` (which materializes every match first), this walks the line with
        # bounded state and yields as it goes. Every budget check is incremental, so even extreme
        # inputs (long lines, repeated characters, many short matches) terminate promptly instead
        # of spinning inside the regex engine.
        if budget["line_length"] > self.MAX_LINE_LENGTH:
            raise InputBudgetExceeded(
                reason="line length exceeded maximum allowed line length",
                limit=self.MAX_LINE_LENGTH,
                observed=budget["line_length"],
            )

        require_quotes = self._requires_quoted_strings()
        window: List[str] = []
        quote_character: Optional[str] = None
        index = 0

        while index < len(line):
            char = line[index]
            index += 1

            budget["scanned_bytes"] += len(char.encode("utf-8"))
            if budget["scanned_bytes"] > budget["max_scanned_bytes"]:
                raise InputBudgetExceeded(
                    reason="scanned byte count exceeded maximum allowed scan size",
                    limit=budget["max_scanned_bytes"],
                    observed=budget["scanned_bytes"],
                )

            if require_quotes:
                if quote_character is None:
                    if char == chr(39) or char == chr(34):
                        quote_character = char
                    continue

                if char == quote_character:
                    candidate = "".join(window)
                    window = []
                    quote_character = None
                    if self._is_viable_candidate(candidate, budget):
                        yield candidate
                    continue

                if char in self._charset_members:
                    window.append(char)
                else:
                    # A non-charset character (including the opposite quote) inside a quoted
                    # region breaks the run: the regex would never match this region, so we
                    # reset and wait for the closing quote before starting fresh.
                    window = []
                    quote_character = None
                continue

            if char in self._charset_members:
                window.append(char)
                continue

            candidate = "".join(window)
            window = []
            if self._is_viable_candidate(candidate, budget):
                yield candidate

        if not require_quotes:
            candidate = "".join(window)
            if self._is_viable_candidate(candidate, budget):
                yield candidate
        # An unterminated quoted run cannot match the back-referenced regex, so it is ignored.

    def _is_viable_candidate(self, candidate: str, budget: Dict[str, int]) -> bool:
        if len(candidate) < self.MIN_CANDIDATE_LENGTH:
            return False

        budget["candidates"] += 1
        if budget["candidates"] > budget["max_candidates"]:
            raise InputBudgetExceeded(
                reason="candidate count exceeded maximum candidates allowed per line",
                limit=budget["max_candidates"],
                observed=budget["candidates"],
            )

        return True

    def _requires_quoted_strings(self) -> bool:
        # The default regex requires a matching pair of quotes (back-reference). The eager
        # regex installed by ``non_quoted_string_regex`` does not.
        return self._requires_quotes

    def _log_skip(
        self,
        filename: str,
        line_number: int,
        exc: InputBudgetExceeded,
    ) -> None:
        log.warning(
            f"Skipping high entropy scan on {filename}:{line_number}: {exc.reason} "
            f"(limit={exc.limit}, observed={exc.observed}).",
        )

    def calculate_shannon_entropy(self, data: str) -> float:
        """Returns the entropy of a given string.

        Borrowed from: http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html.
        """
        if not data:  # pragma: no cover
            return 0

        # Single linear pass: build the frequency table once. The previous implementation called
        # ``data.count`` for every charset character, which re-scanned the full string for each
        # symbol (quadratic work on large, repetitive inputs).
        counts: Dict[str, int] = {}
        for char in data:
            counts[char] = counts.get(char, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p_x = count / length
            entropy += -p_x * math.log(p_x, 2)

        return entropy

    def format_scan_result(self, secret: PotentialSecret) -> str:
        if not secret.secret_value:
            # This is the best we can do, since we do not have the raw value to process.
            return "True"

        entropy = round(self.calculate_shannon_entropy(secret.secret_value), 3)
        if entropy < self.entropy_limit:
            return f"False ({entropy})"

        return f"True  ({entropy})"

    def json(self) -> Dict[str, Any]:
        return {
            **super().json(),
            "limit": self.entropy_limit,
        }

    @contextmanager
    def non_quoted_string_regex(self, is_exact_match: bool = True) -> Generator[None, None, None]:
        """
        For certain file formats, strings need not necessarily follow the
        normal convention of being denoted by single or double quotes. In these
        cases, we modify the regex accordingly.

        :param is_exact_match: True if you need to scan the secret directly.
            However, if the secret is part of a line of text, and you want to find the
            secret within the line, use False.
        """
        old_regex = self.regex

        regex_alternative = r"([{}]+)".format(re.escape(self.charset))
        if is_exact_match:
            regex_alternative = r"^" + regex_alternative + r"$"

        self.regex = re.compile(regex_alternative)
        self._requires_quotes = False

        try:
            yield
        finally:
            self.regex = old_regex
            self._requires_quotes = True


class Base64HighEntropyString(HighEntropyStringsPlugin):
    """Scans for random-looking base64 encoded strings."""
    secret_type = "Base64 High Entropy String"

    def __init__(self, limit: float = 4.5) -> None:
        super().__init__(
            charset=(
                string.ascii_letters
                + string.digits
                + "+/"       # Regular base64
                + "\\-_"     # Url-safe base64
                + "="        # Padding
            ),
            limit=limit,
        )


class HexHighEntropyString(HighEntropyStringsPlugin):
    """Scans for random-looking hex encoded strings."""

    secret_type = "Hex High Entropy String"

    def __init__(self, limit: float = 3.0) -> None:
        super().__init__(
            charset=string.hexdigits,
            limit=limit,
        )

    def calculate_shannon_entropy(self, data: str) -> float:
        """
        In our investigations, we have found that when the input is all digits,
        the number of false positives we get greatly exceeds realistic true
        positive scenarios.

        Therefore, this tries to capture this heuristic mathematically.

        We do this by noting that the maximum shannon entropy for this charset
        is ~3.32 (e.g. "0123456789", with every digit different), and we want
        to lower that below the standard limit, 3. However, at the same time,
        we also want to accommodate the fact that longer strings have a higher
        chance of being a true positive, which means "01234567890123456789"
        should be closer to the maximum entropy than the shorter version.
        """
        entropy = super().calculate_shannon_entropy(data)
        if len(data) == 1:
            return entropy

        try:
            # Check if str is that of a number
            int(data)

            # This multiplier was determined through trial and error, with the intent of keeping
            # it simple, yet achieving our goals.
            entropy -= 1.2 / math.log(len(data), 2)
        except ValueError:
            pass

        return entropy
