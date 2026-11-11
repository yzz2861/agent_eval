"""Explicit, deterministic password policy checks.

This module is intentionally separate from :class:`pwdlib.PasswordHash`.  A
caller must evaluate the raw password with a :class:`PasswordPolicy` and pass
the resulting ``normalized`` value to the hasher.  ``PasswordHash.hash()`` is
unchanged, so existing accounts can continue to verify the exact password they
were originally registered with.

The policy is pure and deterministic: the entry point is metadata for audit
records only and never changes the decision.  Passwords are normalized with a
single fixed form (NFKC), which folds full-width forms and composes canonical
combining sequences while preserving meaningful multilingual text.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Literal

from .exceptions import PwdlibError

NORMALIZATION_FORM: Literal["NFKC"] = "NFKC"
"""The one Unicode normalization form used by every entry point."""

DEFAULT_MIN_VISIBLE_CHARACTERS = 8
DEFAULT_MAX_UTF8_BYTES = 128

# Stable rule identifiers.  They are safe to persist, alert on and compare in
# tests; they never contain password material.
RULE_INVALID_INPUT_TYPE = "policy.invalid_input_type"
RULE_INVALID_UTF8 = "policy.invalid_utf8"
RULE_INVALID_SURROGATE = "policy.invalid_surrogate"
RULE_CONTROL_CHARACTER = "policy.control_character"
RULE_ZERO_WIDTH_CHARACTER = "policy.zero_width_character"
RULE_BIDI_CONTROL = "policy.bidi_control"
RULE_EMPTY = "policy.empty"
RULE_TOO_SHORT = "policy.too_short"
RULE_TOO_LONG = "policy.too_long"
RULE_WEAK_PASSWORD = "policy.weak_password"
RULE_WEAK_CHECKER_ERROR = "policy.weak_checker_error"
RULE_ACCEPTED = "policy.accepted"

# A small local denylist.  It deliberately has no network or filesystem
# dependency.  Entries are compared after NFKC normalization and case folding.
DEFAULT_WEAK_PASSWORDS = frozenset(
    {
        "00000000",
        "11111111",
        "12345678",
        "123456789",
        "1234567890",
        "abc12345",
        "admin123",
        "asdfghjk",
        "baseball",
        "changeme",
        "dragon123",
        "football",
        "iloveyou",
        "letmein",
        "monkey123",
        "passw0rd",
        "password",
        "password1",
        "password12",
        "password123",
        "princess",
        "qwerty123",
        "qwertyuiop",
        "sunshine",
        "trustno1",
        "welcome1",
        "zaq12wsx",
    }
)

_BIDI_CONTROLS = frozenset(
    {
        "\u061c",  # Arabic letter mark
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
    }
)

# Zero-width combining marks that should not be silently folded away.  Variation
# selectors are not listed here: they are meaningful parts of emoji sequences
# and are ignored by the visible-character count instead.
_ZERO_WIDTH_MARKS = frozenset({"\u034f", "\u180b", "\u180c", "\u180d"})

_VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))

_LENGTH_BUCKETS = (
    (0, 0, "0"),
    (1, 7, "1-7"),
    (8, 15, "8-15"),
    (16, 31, "16-31"),
    (32, 63, "32-63"),
    (64, 127, "64-127"),
    (128, 255, "128-255"),
    (256, 511, "256-511"),
)


def _length_range(value: int | None) -> str:
    if value is None:
        return "unknown"
    for minimum, maximum, label in _LENGTH_BUCKETS:
        if minimum <= value <= maximum:
            return label
    return "512+"


def _is_variation_selector(codepoint: int) -> bool:
    return any(start <= codepoint <= end for start, end in _VARIATION_SELECTOR_RANGES)


def _is_combining_mark(character: str) -> bool:
    return unicodedata.category(character) in {"Mn", "Mc", "Me"}


def _visible_character_count(value: str) -> int:
    """Count printable grapheme bases, ignoring marks and whitespace.

    This is a dependency-free approximation of extended grapheme clusters.  A
    base character followed by combining marks counts once, zero-width formats
    and variation selectors do not count, and whitespace does not count toward
    the policy minimum.
    """
    count = 0
    for character in value:
        if _is_combining_mark(character):
            continue
        if _is_variation_selector(ord(character)):
            continue
        if character.isspace() or not character.isprintable():
            continue
        count += 1
    return count


def _first_forbidden_character(value: str) -> tuple[str, str, str] | None:
    for character in value:
        codepoint = ord(character)
        category = unicodedata.category(character)

        if category == "Cs":
            return (
                RULE_INVALID_SURROGATE,
                "The password contains an unpaired Unicode surrogate.",
                "Remove invalid surrogate code points and submit valid Unicode text.",
            )
        if character in _BIDI_CONTROLS:
            return (
                RULE_BIDI_CONTROL,
                "The password contains a bidirectional control character.",
                "Remove bidirectional control characters from the password.",
            )
        if category == "Cc" or codepoint in {0x2028, 0x2029}:
            return (
                RULE_CONTROL_CHARACTER,
                "The password contains a control or line-separator character.",
                "Remove control characters and use printable characters only.",
            )
        if category == "Cf" or character in _ZERO_WIDTH_MARKS:
            return (
                RULE_ZERO_WIDTH_CHARACTER,
                "The password contains a zero-width or invisible format character.",
                "Remove zero-width and invisible format characters.",
            )
    return None


@dataclass(frozen=True, slots=True, repr=False)
class PolicyResult:
    """The deterministic outcome of evaluating one raw password.

    ``normalized`` is present whenever the raw value could be decoded safely,
    including for most rejections.  Callers must check ``allowed`` (or use
    :meth:`PasswordPolicy.enforce`) before passing it to a hasher.  Audit
    records should be built with :meth:`audit_event`, never by dumping this
    object.
    """

    allowed: bool
    normalized: str | None
    utf8_length: int | None
    visible_length: int
    rule_id: str | None
    reason: str | None
    suggested_action: str | None
    input_length_range: str
    entrypoint: str | None = field(default=None, compare=False)

    @property
    def accepted(self) -> bool:
        return self.allowed

    @property
    def ok(self) -> bool:
        return self.allowed

    @property
    def is_valid(self) -> bool:
        return self.allowed

    @property
    def is_rejected(self) -> bool:
        return not self.allowed

    @property
    def normalized_value(self) -> str | None:
        return self.normalized

    @property
    def utf8_bytes(self) -> int | None:
        return self.utf8_length

    @property
    def utf8_byte_length(self) -> int | None:
        return self.utf8_length

    @property
    def visible_characters(self) -> int:
        return self.visible_length

    @property
    def visible_character_count(self) -> int:
        return self.visible_length

    @property
    def code(self) -> str | None:
        return self.rule_id

    @property
    def rejection_reason(self) -> str | None:
        return self.reason

    @property
    def action(self) -> str | None:
        return self.suggested_action

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        # Never render password material, even accidentally in logs/tracebacks.
        return (
            "PolicyResult("
            f"allowed={self.allowed!r}, rule_id={self.rule_id!r}, "
            f"utf8_length={self.utf8_length!r}, "
            f"visible_length={self.visible_length!r}, "
            f"input_length_range={self.input_length_range!r}, "
            f"entrypoint={self.entrypoint!r})"
        )

    def audit_event(self, entrypoint: str | None = None) -> dict[str, object]:
        """Return a password-free audit event for a rejection or acceptance."""
        resolved_entrypoint = _validate_entrypoint(entrypoint or self.entrypoint)
        return {
            "event": (
                "password_policy.accepted"
                if self.allowed
                else "password_policy.rejected"
            ),
            "rule_id": self.rule_id or RULE_ACCEPTED,
            "entrypoint": resolved_entrypoint,
            "input_length_range": self.input_length_range,
            "utf8_bytes_range": _length_range(self.utf8_length),
            "visible_length_range": _length_range(self.visible_length),
        }


class PasswordPolicyError(PwdlibError):
    """Raised by :meth:`PasswordPolicy.enforce` for a rejected password.

    The exception deliberately carries only metadata: a stable rule id, a
    length bucket and the entry point.  It never stores or formats the raw or
    normalized password.
    """

    def __init__(self, result: PolicyResult, entrypoint: str) -> None:
        self.rule_id = result.rule_id
        self.entrypoint = entrypoint
        self.input_length_range = result.input_length_range
        self.reason = result.reason
        self.suggested_action = result.suggested_action
        message = (
            f"Password rejected by policy rule {result.rule_id!r} "
            f"at entry point {entrypoint!r} "
            f"(input length range: {result.input_length_range}). "
            f"Suggested action: {result.suggested_action or 'choose another password.'}"
        )
        super().__init__(message)


def _validate_entrypoint(entrypoint: str | None) -> str:
    if not isinstance(entrypoint, str) or not entrypoint:
        raise ValueError("entrypoint must be a non-empty string")  # noqa: TRY003
    return entrypoint


class PasswordPolicy:
    """A reusable, explicit policy shared by all registration entry points.

    The same configured instance (or identically configured instances) must be
    used everywhere.  ``evaluate`` returns a :class:`PolicyResult`; callers that
    want a fail-fast API can use ``enforce``, which returns the normalized value
    or raises :class:`PasswordPolicyError`.

    Args:
        min_visible_characters: Minimum printable grapheme bases.  Defaults to 8.
        max_utf8_bytes: Maximum UTF-8 encoded bytes after normalization.  Defaults
            to 128; this prevents a few visible characters from being padded with
            thousands of bytes.
        weak_passwords: Extra weak passwords, compared after normalization and
            case folding.  They are added to the built-in local denylist.
        include_default_weak_passwords: Set to ``False`` to disable the built-in
            denylist when supplying a custom one.
        weak_password_checker: Optional local callback receiving the normalized
            password and returning ``True`` when it is weak.  No network access
            is performed by this module.  Callback exceptions fail closed.
    """

    normalization_form = NORMALIZATION_FORM

    def __init__(
        self,
        *,
        min_visible_characters: int = DEFAULT_MIN_VISIBLE_CHARACTERS,
        max_utf8_bytes: int = DEFAULT_MAX_UTF8_BYTES,
        weak_passwords: Iterable[str] | None = None,
        include_default_weak_passwords: bool = True,
        weak_password_checker: Callable[[str], bool] | None = None,
    ) -> None:
        if min_visible_characters < 1:
            raise ValueError("min_visible_characters must be positive")  # noqa: TRY003
        if max_utf8_bytes < 1:
            raise ValueError("max_utf8_bytes must be positive")  # noqa: TRY003
        if weak_password_checker is not None and not callable(weak_password_checker):
            raise TypeError("weak_password_checker must be callable")  # noqa: TRY003

        self.min_visible_characters = min_visible_characters
        self.max_utf8_bytes = max_utf8_bytes
        self._weak_password_checker = weak_password_checker

        weak_entries = (
            set(DEFAULT_WEAK_PASSWORDS) if include_default_weak_passwords else set()
        )
        if weak_passwords is not None:
            weak_entries.update(
                self._normalize_weak_entry(word) for word in weak_passwords
            )
        weak_entries.discard("")
        self._weak_passwords = frozenset(weak_entries)

    @staticmethod
    def _normalize_weak_entry(value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("weak_passwords entries must be str")  # noqa: TRY003
        return unicodedata.normalize(NORMALIZATION_FORM, value).casefold()

    def normalize(self, password: str | bytes) -> str | None:
        """Return the fixed-form normalized value, or ``None`` if undecodable.

        This helper does not make an accept/reject decision.  Use
        :meth:`evaluate` or :meth:`enforce` for the full policy.
        """
        if isinstance(password, bytes):
            try:
                password = password.decode("utf-8")
            except UnicodeDecodeError:
                return None
        if not isinstance(password, str):
            return None
        if _contains_surrogate(password):
            return None
        return unicodedata.normalize(NORMALIZATION_FORM, password)

    def evaluate(
        self,
        password: str | bytes | None,
        *,
        entrypoint: str | None = None,
    ) -> PolicyResult:
        """Evaluate a raw password without hashing it.

        ``entrypoint`` is attached as metadata only (and is excluded from result
        equality).  It never influences normalization or the decision.
        """
        if entrypoint is not None:
            entrypoint = _validate_entrypoint(entrypoint)

        if not isinstance(password, (str, bytes)):
            return self._rejected(
                RULE_INVALID_INPUT_TYPE,
                "The password must be supplied as str or bytes.",
                "Submit the password as str or UTF-8 bytes.",
                normalized=None,
                utf8_length=None,
                visible_length=0,
                input_length_range="unknown",
                entrypoint=entrypoint,
            )

        raw_length = len(password)
        if isinstance(password, bytes):
            try:
                text = password.decode("utf-8")
            except UnicodeDecodeError:
                return self._rejected(
                    RULE_INVALID_UTF8,
                    "The password bytes are not valid UTF-8.",
                    "Submit the password using valid UTF-8 encoding.",
                    normalized=None,
                    utf8_length=None,
                    visible_length=0,
                    input_length_range=_length_range(raw_length),
                    entrypoint=entrypoint,
                )
        else:
            text = password

        if _contains_surrogate(text):
            return self._rejected(
                RULE_INVALID_SURROGATE,
                "The password contains an unpaired Unicode surrogate.",
                "Remove invalid surrogate code points and submit valid Unicode text.",
                normalized=None,
                utf8_length=None,
                visible_length=0,
                input_length_range=_length_range(len(text)),
                entrypoint=entrypoint,
            )

        normalized = unicodedata.normalize(NORMALIZATION_FORM, text)
        utf8_length = len(normalized.encode("utf-8"))
        visible_length = _visible_character_count(normalized)
        input_length_range = _length_range(len(text))

        if not normalized:
            return self._rejected(
                RULE_EMPTY,
                "The password is empty.",
                f"Set a password with at least {self.min_visible_characters} visible characters.",
                normalized=normalized,
                utf8_length=utf8_length,
                visible_length=visible_length,
                input_length_range=input_length_range,
                entrypoint=entrypoint,
            )

        forbidden = _first_forbidden_character(normalized)
        if forbidden is not None:
            rule_id, reason, action = forbidden
            return self._rejected(
                rule_id,
                reason,
                action,
                normalized=normalized,
                utf8_length=utf8_length,
                visible_length=visible_length,
                input_length_range=input_length_range,
                entrypoint=entrypoint,
            )

        if visible_length < self.min_visible_characters:
            return self._rejected(
                RULE_TOO_SHORT,
                (
                    f"The password has only {visible_length} visible character(s); "
                    f"at least {self.min_visible_characters} are required."
                ),
                f"Use at least {self.min_visible_characters} visible characters.",
                normalized=normalized,
                utf8_length=utf8_length,
                visible_length=visible_length,
                input_length_range=input_length_range,
                entrypoint=entrypoint,
            )

        if utf8_length > self.max_utf8_bytes:
            return self._rejected(
                RULE_TOO_LONG,
                (
                    f"The normalized password is {utf8_length} UTF-8 bytes; "
                    f"the maximum is {self.max_utf8_bytes}."
                ),
                f"Reduce the password to at most {self.max_utf8_bytes} UTF-8 bytes.",
                normalized=normalized,
                utf8_length=utf8_length,
                visible_length=visible_length,
                input_length_range=input_length_range,
                entrypoint=entrypoint,
            )

        if normalized.casefold() in self._weak_passwords:
            return self._rejected(
                RULE_WEAK_PASSWORD,
                "The password is in the local weak-password denylist.",
                "Choose a password that is not a commonly used weak password.",
                normalized=normalized,
                utf8_length=utf8_length,
                visible_length=visible_length,
                input_length_range=input_length_range,
                entrypoint=entrypoint,
            )

        if self._weak_password_checker is not None:
            try:
                is_weak = bool(self._weak_password_checker(normalized))
            except Exception:  # noqa: BLE001 - a broken callback must fail closed.
                return self._rejected(
                    RULE_WEAK_CHECKER_ERROR,
                    "The configured weak-password callback failed.",
                    "Fix the weak-password callback before accepting passwords.",
                    normalized=normalized,
                    utf8_length=utf8_length,
                    visible_length=visible_length,
                    input_length_range=input_length_range,
                    entrypoint=entrypoint,
                )
            if is_weak:
                return self._rejected(
                    RULE_WEAK_PASSWORD,
                    "The password was rejected by the configured weak-password callback.",
                    "Choose a password that is not a commonly used weak password.",
                    normalized=normalized,
                    utf8_length=utf8_length,
                    visible_length=visible_length,
                    input_length_range=input_length_range,
                    entrypoint=entrypoint,
                )

        return PolicyResult(
            allowed=True,
            normalized=normalized,
            utf8_length=utf8_length,
            visible_length=visible_length,
            rule_id=None,
            reason=None,
            suggested_action=None,
            input_length_range=input_length_range,
            entrypoint=entrypoint,
        )

    def check(
        self,
        password: str | bytes | None,
        *,
        entrypoint: str | None = None,
    ) -> PolicyResult:
        """Alias for :meth:`evaluate`."""
        return self.evaluate(password, entrypoint=entrypoint)

    def enforce(self, password: str | bytes | None, *, entrypoint: str) -> str:
        """Return the normalized password or raise without exposing plaintext."""
        resolved_entrypoint = _validate_entrypoint(entrypoint)
        result = self.evaluate(password, entrypoint=resolved_entrypoint)
        if not result.allowed:
            raise PasswordPolicyError(result, resolved_entrypoint)
        if result.normalized is None:  # pragma: no cover - defensive invariant
            raise PasswordPolicyError(result, resolved_entrypoint)
        return result.normalized

    @staticmethod
    def _rejected(
        rule_id: str,
        reason: str,
        action: str,
        *,
        normalized: str | None,
        utf8_length: int | None,
        visible_length: int,
        input_length_range: str,
        entrypoint: str | None,
    ) -> PolicyResult:
        return PolicyResult(
            allowed=False,
            normalized=normalized,
            utf8_length=utf8_length,
            visible_length=visible_length,
            rule_id=rule_id,
            reason=reason,
            suggested_action=action,
            input_length_range=input_length_range,
            entrypoint=entrypoint,
        )


def _contains_surrogate(value: str) -> bool:
    return any(unicodedata.category(character) == "Cs" for character in value)


__all__ = [
    "DEFAULT_MAX_UTF8_BYTES",
    "DEFAULT_MIN_VISIBLE_CHARACTERS",
    "DEFAULT_WEAK_PASSWORDS",
    "NORMALIZATION_FORM",
    "RULE_ACCEPTED",
    "RULE_BIDI_CONTROL",
    "RULE_CONTROL_CHARACTER",
    "RULE_EMPTY",
    "RULE_INVALID_INPUT_TYPE",
    "RULE_INVALID_SURROGATE",
    "RULE_INVALID_UTF8",
    "RULE_TOO_LONG",
    "RULE_TOO_SHORT",
    "RULE_WEAK_CHECKER_ERROR",
    "RULE_WEAK_PASSWORD",
    "RULE_ZERO_WIDTH_CHARACTER",
    "PasswordPolicy",
    "PasswordPolicyError",
    "PolicyResult",
]
