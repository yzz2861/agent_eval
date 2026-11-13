#
# SPDX-License-Identifier: Apache-2.0
"""Structured parsing and evaluation of ``# nosec`` suppression comments.

A nosec directive is parsed into a :class:`NosecRecord` so that the rest of
the engine never has to reason about free-form comment text.  The supported
grammar is intentionally narrow:

* ``# nosec`` -- blanket suppression of every finding on the line
* ``# nosec: B602`` or ``# nosec B602`` -- suppress a single test id
* ``# nosec: B602, B607`` -- suppress several test ids / plugin names
* ``# nosec: B60*`` -- suppress every test id matching the wildcard

Colons, commas, whitespace and letter case are normalized according to the
grammar above.  Malformed directives are reported instead of being silently
treated as a blanket ``# nosec``.
"""

import fnmatch
import logging
import re

LOG = logging.getLogger(__name__)

# The directive keyword may be preceded by other comment machinery (for
# example ``# type: ... # nosec``).  Everything after the keyword has to
# follow the strict grammar, so stray text such as space separated selectors
# produces an explicit parse error instead of a silent blanket suppression.
NOSEC_DIRECTIVE = re.compile(
    r"#\s*nosec\b\s*(?::\s*)?(?P<body>[^#]*)", re.IGNORECASE
)
TEST_ID_RE = re.compile(r"^B\d{3,4}$")
PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
WILDCARD_RE = re.compile(r"^[A-Za-z0-9_*?\[\]]+$")


class NosecError(ValueError):
    """Raised when a ``# nosec`` directive does not follow the grammar."""


class NosecRecord:
    """Structured representation of a single ``# nosec`` comment.

    :param comment: original comment text, retained for auditing
    :param lineno: physical line the comment appears on
    :param selectors: normalized selectors from the comment
    :param test_ids: resolved concrete test ids
    :param blanket: true for a directive without any selector
    :param valid: false when the directive could not be parsed/resolved
    :param error: parse/validation error message, if any
    """

    def __init__(
        self,
        comment,
        lineno,
        selectors=None,
        test_ids=None,
        blanket=False,
        valid=True,
        error=None,
    ):
        self.comment = comment
        self.lineno = lineno
        self.selectors = list(selectors) if selectors else []
        self.test_ids = set(test_ids) if test_ids else set()
        self.blanket = blanket
        self.valid = valid
        self.error = error
        self.line_range = [lineno]

    @classmethod
    def blanket_nosec(cls, comment, lineno):
        return cls(comment=comment, lineno=lineno, blanket=True)

    @classmethod
    def invalid_nosec(cls, comment, lineno, error):
        LOG.warning("Invalid nosec comment on line %i: %s", lineno, error)
        return cls(
            comment=comment,
            lineno=lineno,
            valid=False,
            error=str(error),
        )

    def suppresses(self, test_id):
        """Return ``True`` when ``test_id`` is covered by this record."""
        if not self.valid:
            return False
        if self.blanket:
            return True
        if test_id in self.test_ids:
            return True
        return any(
            fnmatch.fnmatchcase(test_id, selector)
            for selector in self.selectors
            if any(char in selector for char in "*?[")
        )

    def __repr__(self):
        return (
            f"NosecRecord(lineno={self.lineno}, blanket={self.blanket}, "
            f"selectors={self.selectors!r}, valid={self.valid})"
        )


def _known_test_ids(extman):
    return set(extman.plugins_by_id) | set(extman.blacklist_by_id) | set(
        extman.builtin
    )


def _normalize_selector(raw_selector, extman):
    """Normalize one selector and resolve it to a concrete test id.

    :param raw_selector: token from the comma separated directive body
    :param extman: loaded :class:`extension_loader.Manager`
    :return: tuple of (normalized selector, resolved test id or None)
    :raises NosecError: when the selector is malformed or unknown
    """
    selector = raw_selector.strip()
    if not selector:
        raise NosecError("empty selector in nosec list")

    if any(char in selector for char in "*?["):
        if not WILDCARD_RE.match(selector):
            raise NosecError(
                f"invalid wildcard selector {selector!r} in nosec comment"
            )
        pattern = selector.upper()
        if not any(
            fnmatch.fnmatchcase(test_id, pattern)
            for test_id in _known_test_ids(extman)
        ):
            raise NosecError(
                f"wildcard selector {selector!r} does not match any test id"
            )
        return pattern, None

    if selector.upper().startswith("B") and selector[1:].isdigit():
        test_id = selector.upper()
        if not TEST_ID_RE.match(test_id):
            raise NosecError(f"invalid test id {selector!r} in nosec comment")
        if not extman.check_id(test_id):
            raise NosecError(
                f"test id {test_id} in nosec comment does not exist"
            )
        return test_id, test_id

    plugin_name = selector.lower()
    if not PLUGIN_NAME_RE.match(plugin_name):
        raise NosecError(
            f"invalid selector {selector!r} in nosec comment; expected a "
            "test id, plugin name or wildcard"
        )
    test_id = extman.get_test_id(plugin_name)
    if not test_id:
        raise NosecError(
            f"plugin {plugin_name!r} in nosec comment is not a test "
            "name or id"
        )
    return plugin_name, test_id


def parse_nosec_comment(comment, lineno, extman):
    """Parse a source comment into a :class:`NosecRecord`.

    :param comment: raw comment text including the leading ``#``
    :param lineno: physical line number of the comment
    :param extman: loaded :class:`extension_loader.Manager`
    :return: a :class:`NosecRecord` or ``None`` when not a nosec comment
    """
    match = NOSEC_DIRECTIVE.search(comment.strip())
    if not match:
        return None

    body = match.group("body").strip()
    if not body:
        return NosecRecord.blanket_nosec(comment, lineno)

    selectors = []
    test_ids = set()
    seen = set()
    try:
        for raw_selector in body.split(","):
            selector, resolved_id = _normalize_selector(raw_selector, extman)
            if selector in seen:
                raise NosecError(
                    f"duplicate selector {selector!r} in nosec comment"
                )
            seen.add(selector)
            selectors.append(selector)
            if resolved_id is not None:
                test_ids.add(resolved_id)
    except NosecError as error:
        return NosecRecord.invalid_nosec(comment, lineno, error)

    return NosecRecord(
        comment=comment,
        lineno=lineno,
        selectors=selectors,
        test_ids=test_ids,
    )
