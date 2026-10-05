import asyncio
import hashlib
import hmac
from datetime import datetime
from datetime import timezone

import pytest
from freezegun import freeze_time

from itsdangerous.asynchronous import AsyncSerializer
from itsdangerous.asynchronous import AsyncTimedSerializer
from itsdangerous.asynchronous import AsyncURLSafeSerializer
from itsdangerous.asynchronous import AsyncURLSafeTimedSerializer
from itsdangerous.exc import BadData
from itsdangerous.exc import BadSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.exc import SignerUnavailable
from itsdangerous.serializer import Serializer
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer


def run(coro):
    return asyncio.run(coro)


class RecordingAsyncSigner:
    """Async signer test double that emulates a remote HMAC service.

    Uses the same key derivation and algorithm as the sync
    :class:`Signer` so that wire-format compatibility can be tested.
    Records every call as ``(method, value, salt)``.
    """

    def __init__(self, secret_key=b"secret_key"):
        self.secret_key = secret_key
        self.calls = []

    def _sign(self, value, salt):
        key = hashlib.sha1(salt + b"signer" + self.secret_key).digest()
        return hmac.new(key, msg=value, digestmod=hashlib.sha1).digest()

    async def get_signature(self, value, *, salt):
        self.calls.append(("get_signature", value, salt))
        return self._sign(value, salt)

    async def verify_signature(self, value, sig, *, salt):
        self.calls.append(("verify_signature", value, salt))
        return hmac.compare_digest(sig, self._sign(value, salt))


class TrackedAwaitable:
    """Awaitable wrapper that records whether it was awaited. If the
    serializer forgets an ``await``, the flag stays ``False`` and the
    wrapped value is never unwrapped.
    """

    def __init__(self, coro):
        self.coro = coro
        self.awaited = False

    def __await__(self):
        self.awaited = True
        return (yield from self.coro.__await__())


class TrackedSigner:
    """Returns :class:`TrackedAwaitable` results from plain methods
    to detect a missing ``await`` in the serializer.
    """

    def __init__(self):
        self.inner = RecordingAsyncSigner()
        self.awaitables = []

    def get_signature(self, value, *, salt):
        tracked = TrackedAwaitable(self.inner.get_signature(value, salt=salt))
        self.awaitables.append(tracked)
        return tracked

    def verify_signature(self, value, sig, *, salt):
        tracked = TrackedAwaitable(self.inner.verify_signature(value, sig, salt=salt))
        self.awaitables.append(tracked)
        return tracked


class HangingSigner:
    """Test double that hangs forever unless cancelled."""

    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = False

    async def _hang(self):
        self.started.set()

        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled = True
            raise

    async def get_signature(self, value, *, salt):
        await self._hang()

    async def verify_signature(self, value, sig, *, salt):
        await self._hang()


class UnavailableSigner:
    """Test double whose service is always unavailable."""

    def __init__(self):
        self.calls = 0

    async def get_signature(self, value, *, salt):
        self.calls += 1
        raise SignerUnavailable("service unreachable")

    async def verify_signature(self, value, sig, *, salt):
        self.calls += 1
        raise SignerUnavailable("service unreachable")


class SyncOnlySigner:
    """A signer without async methods must not be accepted."""

    def get_signature(self, value, *, salt):
        return b"sig"

    def verify_signature(self, value, sig, *, salt):
        return True


class BadReturnSigner:
    """Async methods that return the wrong types."""

    async def get_signature(self, value, *, salt):
        return "not-bytes"

    async def verify_signature(self, value, sig, *, salt):
        return "yes"


class ClockAsyncTimedSerializer(AsyncTimedSerializer):
    """Timed serializer with a controllable, countable clock."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.now = 1_700_000_000
        self.timestamp_calls = 0

    def get_timestamp(self):
        self.timestamp_calls += 1
        return self.now


class TestAsyncSerializer:
    @pytest.mark.parametrize(
        "value", (None, True, "str", "text", [1, 2, 3], {"id": 42})
    )
    def test_round_trip(self, value):
        s = AsyncSerializer(RecordingAsyncSigner())
        assert run(s.loads(run(s.dumps(value)))) == value

    def test_matches_sync_wire_format(self):
        async_s = AsyncSerializer(RecordingAsyncSigner())
        sync_s = Serializer("secret_key")
        value = {"id": 42}
        assert run(async_s.dumps(value)) == sync_s.dumps(value)
        assert run(async_s.loads(sync_s.dumps(value))) == value
        assert sync_s.loads(run(async_s.dumps(value))) == value

    def test_exactly_one_signer_call_per_operation(self):
        signer = RecordingAsyncSigner()
        s = AsyncSerializer(signer)
        signed = run(s.dumps({"id": 42}))
        assert [call[0] for call in signer.calls] == ["get_signature"]
        assert run(s.loads(signed)) == {"id": 42}
        assert [call[0] for call in signer.calls] == [
            "get_signature",
            "verify_signature",
        ]

    def test_salt_passed_as_purpose(self):
        signer = RecordingAsyncSigner()
        s = AsyncSerializer(signer, salt="purpose-a")
        signed = run(s.dumps({"id": 42}))
        assert signer.calls[0][2] == b"purpose-a"
        assert run(s.loads(signed)) == {"id": 42}
        assert signer.calls[1][2] == b"purpose-a"

        with pytest.raises(BadSignature):
            run(s.loads(signed, salt="purpose-b"))

    def test_sep_validation(self):
        with pytest.raises(ValueError):
            AsyncSerializer(RecordingAsyncSigner(), sep="-")

    def test_no_missing_await(self):
        signer = TrackedSigner()
        s = AsyncSerializer(signer)
        signed = run(s.dumps({"id": 42}))
        assert run(s.loads(signed)) == {"id": 42}
        assert len(signer.awaitables) == 2
        assert all(tracked.awaited for tracked in signer.awaitables)

    def test_non_async_signer_rejected(self):
        s = AsyncSerializer(SyncOnlySigner())

        with pytest.raises(TypeError):
            run(s.dumps({"id": 42}))

        good = AsyncSerializer(RecordingAsyncSigner())
        signed = run(good.dumps({"id": 42}))

        with pytest.raises(TypeError):
            run(s.loads(signed))

    def test_bad_return_type_rejected(self):
        s = AsyncSerializer(BadReturnSigner())

        with pytest.raises(TypeError):
            run(s.dumps({"id": 42}))

        good = AsyncSerializer(RecordingAsyncSigner())
        signed = run(good.dumps({"id": 42}))

        with pytest.raises(TypeError):
            run(s.loads(signed))

    def test_tampered_payload_rejected(self):
        s = AsyncSerializer(RecordingAsyncSigner())
        signed = run(s.dumps({"id": 42}))
        tampered = signed.replace("42", "43")

        with pytest.raises(BadSignature):
            run(s.loads(tampered))

        assert run(s.validate(tampered)) is False
        ok, payload = run(s.loads_unsafe(tampered))
        assert ok is False
        assert payload == {"id": 43}

    def test_malformed_signature_not_sent_to_service(self):
        signer = RecordingAsyncSigner()
        s = AsyncSerializer(signer)

        with pytest.raises(BadSignature):
            run(s.loads("no-separator"))

        # Invalid base64 padding is rejected locally, without
        # calling the signing service.
        with pytest.raises(BadSignature):
            run(s.loads('{"id": 42}.A'))

        assert signer.calls == []

    def test_garbage_signature_rejected(self):
        # Non-alphabet characters are discarded by the base64
        # decoder, leaving an empty signature that does not match,
        # consistent with the sync signer.
        s = AsyncSerializer(RecordingAsyncSigner())

        with pytest.raises(BadSignature):
            run(s.loads('{"id": 42}.!!!'))

    def test_unavailable_propagates(self):
        good = AsyncSerializer(RecordingAsyncSigner())
        signed = run(good.dumps({"id": 42}))
        s = AsyncSerializer(UnavailableSigner())

        with pytest.raises(SignerUnavailable):
            run(s.dumps({"id": 42}))

        with pytest.raises(SignerUnavailable):
            run(s.loads(signed))

        with pytest.raises(SignerUnavailable):
            run(s.validate(signed))

        with pytest.raises(SignerUnavailable):
            run(s.loads_unsafe(signed))

    def test_unavailable_is_not_bad_data(self):
        assert not issubclass(SignerUnavailable, BadData)
        assert not issubclass(SignerUnavailable, BadSignature)

    def test_cancellation_propagates(self):
        signer = HangingSigner()
        s = AsyncSerializer(signer)

        async def main():
            task = asyncio.create_task(s.dumps({"id": 42}))
            await signer.started.wait()
            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

        run(main())
        assert signer.cancelled

    def test_cancellation_during_loads(self):
        good = AsyncSerializer(RecordingAsyncSigner())
        signed = run(good.dumps({"id": 42}))
        signer = HangingSigner()
        s = AsyncSerializer(signer)

        async def main():
            task = asyncio.create_task(s.loads(signed))
            await signer.started.wait()
            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

        run(main())
        assert signer.cancelled

    def test_hanging_does_not_silently_succeed(self):
        signer = HangingSigner()
        s = AsyncSerializer(signer)

        async def main():
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(s.dumps({"id": 42}), timeout=0.05)

        run(main())
        assert signer.cancelled


class TestAsyncTimedSerializer:
    def test_timestamp_determined_once(self):
        s = ClockAsyncTimedSerializer(RecordingAsyncSigner())
        run(s.dumps({"id": 42}))
        assert s.timestamp_calls == 1

    @freeze_time("2024-06-01 12:00:00")
    def test_matches_sync_wire_format(self):
        async_s = AsyncTimedSerializer(RecordingAsyncSigner())
        sync_s = TimedSerializer("secret_key")
        value = {"id": 42}
        assert run(async_s.dumps(value)) == sync_s.dumps(value)
        assert run(async_s.loads(sync_s.dumps(value), max_age=60)) == value
        assert sync_s.loads(run(async_s.dumps(value)), max_age=60) == value

    def test_max_age(self):
        s = ClockAsyncTimedSerializer(RecordingAsyncSigner())
        signed = run(s.dumps({"id": 42}))
        s.now += 100

        with pytest.raises(SignatureExpired):
            run(s.loads(signed, max_age=10))

        assert run(s.loads(signed, max_age=200)) == {"id": 42}

    def test_max_age_checked_after_verification(self):
        good = ClockAsyncTimedSerializer(RecordingAsyncSigner())
        signed = run(good.dumps({"id": 42}))
        s = ClockAsyncTimedSerializer(UnavailableSigner())
        s.now = good.now + 1000

        with pytest.raises(SignerUnavailable):
            run(s.loads(signed, max_age=10))

    def test_return_timestamp(self):
        s = ClockAsyncTimedSerializer(RecordingAsyncSigner())
        signed = run(s.dumps({"id": 42}))
        payload, dt = run(s.loads(signed, return_timestamp=True))
        assert payload == {"id": 42}
        assert dt == datetime.fromtimestamp(s.now, tz=timezone.utc)

    def test_negative_age(self):
        s = ClockAsyncTimedSerializer(RecordingAsyncSigner())
        signed = run(s.dumps({"id": 42}))
        s.now -= 100

        with pytest.raises(SignatureExpired):
            run(s.loads(signed, max_age=10))

    def test_validate(self):
        s = ClockAsyncTimedSerializer(RecordingAsyncSigner())
        signed = run(s.dumps({"id": 42}))
        assert run(s.validate(signed, max_age=10)) is True
        s.now += 100
        assert run(s.validate(signed, max_age=10)) is False

    def test_unavailable_propagates(self):
        s = ClockAsyncTimedSerializer(UnavailableSigner())

        with pytest.raises(SignerUnavailable):
            run(s.dumps({"id": 42}))


class TestAsyncURLSafeSerializer:
    def test_matches_sync_wire_format(self):
        async_s = AsyncURLSafeSerializer(RecordingAsyncSigner())
        sync_s = URLSafeSerializer("secret_key")
        value = {"id": 42, "name": "itsdangerous"}
        assert run(async_s.dumps(value)) == sync_s.dumps(value)
        assert run(async_s.loads(sync_s.dumps(value))) == value
        assert sync_s.loads(run(async_s.dumps(value))) == value

    def test_compressed_matches_sync(self):
        async_s = AsyncURLSafeSerializer(RecordingAsyncSigner())
        sync_s = URLSafeSerializer("secret_key")
        value = {"data": "a" * 500}
        signed = run(async_s.dumps(value))
        assert signed == sync_s.dumps(value)
        assert signed.startswith(".")
        assert run(async_s.loads(signed)) == value

    def test_timed_cross_compatible(self):
        async_s = AsyncURLSafeTimedSerializer(RecordingAsyncSigner())
        sync_s = URLSafeTimedSerializer("secret_key")
        value = {"id": 42}
        assert run(async_s.loads(sync_s.dumps(value), max_age=3600)) == value
        assert sync_s.loads(run(async_s.dumps(value)), max_age=3600) == value


class TestSyncAPI:
    def test_does_not_start_event_loop(self, monkeypatch):
        def forbidden(*args, **kwargs):
            raise AssertionError("sync API started an event loop")

        monkeypatch.setattr(asyncio, "run", forbidden)
        monkeypatch.setattr(asyncio, "new_event_loop", forbidden)
        monkeypatch.setattr(asyncio, "get_event_loop", forbidden)

        signer = Signer("secret_key")
        assert signer.unsign(signer.sign(b"value")) == b"value"

        s = Serializer("secret_key")
        assert s.loads(s.dumps({"id": 42})) == {"id": 42}

        timed = TimedSerializer("secret_key")
        assert timed.loads(timed.dumps({"id": 42}), max_age=60) == {"id": 42}

        url_safe = URLSafeSerializer("secret_key")
        assert url_safe.loads(url_safe.dumps({"id": 42})) == {"id": 42}
