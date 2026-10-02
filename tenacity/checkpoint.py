import dataclasses
import hashlib
import hmac
import json
import math
import time
import typing as t

from tenacity.wait import (
    JsonValue,
    deserialize_wait_strategy,
    serialize_wait_strategy,
    wait_base,
)

if t.TYPE_CHECKING:
    from tenacity import RetryCallState


CHECKPOINT_VERSION = 1
_PAYLOAD_KEYS = {
    "version",
    "attempt_number",
    "elapsed_budget",
    "saved_at",
    "next_allowed_at",
    "wait_strategy",
}


class RetryCheckpointError(ValueError):
    """Raised when a retry checkpoint cannot safely be used."""


@dataclasses.dataclass(frozen=True, slots=True)
class RetryCheckpoint:
    """Authenticated, portable state saved between two retry attempts."""

    attempt_number: int
    elapsed_budget: float
    saved_at: float
    next_allowed_at: float
    wait_strategy: wait_base

    @classmethod
    def from_retry_state(
        cls,
        retry_state: "RetryCallState",
        *,
        current_time: float | None = None,
    ) -> "RetryCheckpoint":
        """Create a checkpoint only during the safe before-sleep phase."""
        if retry_state.retry_object is None:
            raise RetryCheckpointError("checkpoint requires a retry controller")
        if retry_state.outcome is None:
            raise RetryCheckpointError(
                "checkpoints can only be saved between retry attempts"
            )
        if retry_state.next_action is None:
            raise RetryCheckpointError("checkpoint saved in an unsafe retry phase")

        sleep_for = float(retry_state.next_action.sleep)
        wait_strategy = retry_state.retry_object.wait
        if not isinstance(wait_strategy, wait_base):
            raise RetryCheckpointError("wait strategy is unsupported")
        attempt_number = retry_state.attempt_number + 1
        monotonic_saved_at = time.monotonic()
        elapsed_budget = monotonic_saved_at - retry_state.start_time
        saved_at = time.time() if current_time is None else current_time

        checkpoint = cls(
            attempt_number=attempt_number,
            elapsed_budget=float(elapsed_budget),
            saved_at=float(saved_at),
            next_allowed_at=float(saved_at + sleep_for),
            wait_strategy=wait_strategy,
        )
        checkpoint._validate()
        serialize_wait_strategy(checkpoint.wait_strategy)
        return checkpoint

    def to_bytes(self, secret: str | bytes) -> bytes:
        """Serialize the checkpoint as authenticated JSON."""
        key = _secret_bytes(secret)
        self._validate()
        payload: dict[str, JsonValue] = {
            "version": CHECKPOINT_VERSION,
            "attempt_number": self.attempt_number,
            "elapsed_budget": self.elapsed_budget,
            "saved_at": self.saved_at,
            "next_allowed_at": self.next_allowed_at,
            "wait_strategy": serialize_wait_strategy(self.wait_strategy),
        }
        payload_bytes = _canonical_json(payload)
        signature = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
        envelope = {
            "version": CHECKPOINT_VERSION,
            "payload": json.loads(payload_bytes.decode("utf-8")),
            "signature": signature,
        }
        return _canonical_json(envelope)

    @classmethod
    def from_bytes(cls, data: bytes | str, secret: str | bytes) -> "RetryCheckpoint":
        """Verify and deserialize an authenticated JSON checkpoint."""
        key = _secret_bytes(secret)
        try:
            raw = data.decode("utf-8") if isinstance(data, bytes) else data
            envelope = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RetryCheckpointError) as exc:
            raise RetryCheckpointError("invalid retry checkpoint") from exc

        if not isinstance(envelope, dict) or set(envelope) != {
            "version",
            "payload",
            "signature",
        }:
            raise RetryCheckpointError("invalid retry checkpoint")
        if envelope["version"] != CHECKPOINT_VERSION:
            raise RetryCheckpointError("unsupported checkpoint version")
        signature = envelope["signature"]
        if not isinstance(signature, str):
            raise RetryCheckpointError("invalid retry checkpoint")

        payload = envelope["payload"]
        if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
            raise RetryCheckpointError("invalid retry checkpoint")
        payload_bytes = _canonical_json(payload)
        expected = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise RetryCheckpointError("retry checkpoint signature is invalid")
        if payload["version"] != CHECKPOINT_VERSION:
            raise RetryCheckpointError("unsupported checkpoint version")

        attempt_number = payload["attempt_number"]
        if isinstance(attempt_number, bool) or not isinstance(attempt_number, int):
            raise RetryCheckpointError("attempt_number must be an integer")

        try:
            wait_strategy = deserialize_wait_strategy(
                _json_object(payload["wait_strategy"])
            )
        except (TypeError, ValueError) as exc:
            raise RetryCheckpointError(str(exc)) from exc

        checkpoint = cls(
            attempt_number=attempt_number,
            elapsed_budget=_payload_number(payload, "elapsed_budget"),
            saved_at=_payload_number(payload, "saved_at"),
            next_allowed_at=_payload_number(payload, "next_allowed_at"),
            wait_strategy=wait_strategy,
        )
        checkpoint._validate()
        return checkpoint

    def _validate(self) -> None:
        if isinstance(self.attempt_number, bool) or not isinstance(
            self.attempt_number, int
        ):
            raise RetryCheckpointError("attempt_number must be an integer")
        if self.attempt_number < 2:
            raise RetryCheckpointError("attempt_number must identify a later attempt")
        for value in (
            self.elapsed_budget,
            self.saved_at,
            self.next_allowed_at,
        ):
            if not math.isfinite(value):
                raise RetryCheckpointError("checkpoint timestamps must be finite")
        if self.elapsed_budget < 0:
            raise RetryCheckpointError("elapsed_budget cannot be negative")
        if self.next_allowed_at < self.saved_at:
            raise RetryCheckpointError("next allowed time precedes checkpoint time")
        if not isinstance(self.wait_strategy, wait_base):
            raise RetryCheckpointError("wait strategy is unsupported")


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        key = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        key = secret
    else:
        raise TypeError("checkpoint secret must be str or bytes")
    if not key:
        raise ValueError("checkpoint secret must not be empty")
    return key


def _canonical_json(value: t.Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=False,
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, t.Any]]) -> dict[str, t.Any]:
    result: dict[str, t.Any] = {}
    for key, value in pairs:
        if key in result:
            raise RetryCheckpointError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> t.NoReturn:
    raise RetryCheckpointError("invalid JSON constant: " + value)


def _json_object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise RetryCheckpointError("invalid retry checkpoint")
    return value


def _payload_number(payload: dict[str, JsonValue], name: str) -> float:
    value = payload[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RetryCheckpointError(name + " must be a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise RetryCheckpointError(name + " is too large") from exc
    if not math.isfinite(number):
        raise RetryCheckpointError(name + " must be finite")
    return number


__all__ = [
    "CHECKPOINT_VERSION",
    "RetryCheckpoint",
    "RetryCheckpointError",
]
