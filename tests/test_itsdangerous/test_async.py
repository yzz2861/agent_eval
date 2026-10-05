import asyncio
import hashlib
import hmac
import pickle

import pytest
from freezegun import freeze_time

from itsdangerous.encoding import base64_decode
from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadSignature
from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.exc import SignerUnavailable
from itsdangerous.serializer import AsyncSerializer
from itsdangerous.serializer import Serializer
from itsdangerous.signer import AsyncSigner
from itsdangerous.signer import Signer
from itsdangerous.timed import AsyncTimedSerializer
from itsdangerous.timed import AsyncTimestampSigner
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from itsdangerous.url_safe import AsyncURLSafeSerializer
from itsdangerous.url_safe import AsyncURLSafeTimedSerializer
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer


class HMACBackend:
    """Simulates a remote signing service. Records every call so
    tests can check for missing, duplicate, or misdirected calls.
    """

    def __init__(self, key=b"secret-key"):
        self.key = key
        self.sign_calls = []
        self.verify_calls = []

    def _signature(self, value, purpose):
        mac = hmac.new(self.key, msg=purpose + value, digestmod=hashlib.sha256)
        return mac.digest()

    async def sign(self, value, *, purpose):
        self.sign_calls.append((value, purpose))
        return self._signature(value, purpose)

    async def verify(self, value, signature, *, purpose):
        self.verify_calls.append((value, signature, purpose))
        return hmac.compare_digest(signature, self._signature(value, purpose))


class SyncBridgeBackend:
    """Computes signatures exactly like the sync Signer, to show
    that async and sync signed values are interchangeable.
    """

    def __init__(self, secret_key="secret-key"):
        self.secret_key = secret_key

    def _signer(self, purpose):
        return Signer(self.secret_key, salt=purpose)

    async def sign(self, value, *, purpose):
        return base64_decode(self._signer(purpose).get_signature(value))

    async def verify(self, value, signature, *, purpose):
        return self._signer(purpose).verify_signature(value, base64_encode(signature))


class HangingBackend:
    """Never produces a result, to test cancellation and timeouts."""

    def __init__(self):
        self.entered = asyncio.Event()
        self.cancelled = False

    async def _hang(self):
        self.entered.set()

        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise

    async def sign(self, value, *, purpose):
        await self._hang()

    async def verify(self, value, signature, *, purpose):
        await self._hang()


class FailingBackend:
    """Always raises, simulating an unavailable signing service."""

    def __init__(self, exc=None):
        self.exc = exc if exc is not None else ConnectionError("service unavailable")
        self.calls = 0

    async def sign(self, value, *, purpose):
        self.calls += 1
        raise self.exc

    async def verify(self, value, signature, *, purpose):
        self.calls += 1
        raise self.exc


class TestAsyncSigner:
    def test_round_trip(self):
        backend = HMACBackend()
        signer = AsyncSigner(backend, salt="purpose")

        async def main():
            signed = await signer.sign(b"my string")
            assert await signer.unsign(signed) == b"my string"
            assert await signer.validate(signed)
            return signed

        signed = asyncio.run(main())
        # same encoding convention as Signer: value.sep.base64(sig)
        value, sig = signed.rsplit(b".", 1)
        assert value == b"my string"
        assert base64_decode(sig) == backend._signature(b"my string", b"purpose")

    def test_backend_receives_exact_bytes_and_purpose_once(self):
        backend = HMACBackend()
        signer = AsyncSigner(backend, salt="purpose")

        async def main():
            signed = await signer.sign(b"my string")
            await signer.unsign(signed)

        asyncio.run(main())
        assert backend.sign_calls == [(b"my string", b"purpose")]
        assert len(backend.verify_calls) == 1
        value, sig, purpose = backend.verify_calls[0]
        assert value == b"my string"
        assert purpose == b"purpose"
        assert sig == backend._signature(b"my string", b"purpose")

    def test_default_purpose(self):
        backend = HMACBackend()
        signer = AsyncSigner(backend)
        asyncio.run(signer.sign(b"x"))
        assert backend.sign_calls == [(b"x", b"itsdangerous.Signer")]

    def test_tampered_value(self):
        async def main():
            signer = AsyncSigner(HMACBackend())
            signed = await signer.sign(b"my string")
            tampered = b"different" + signed[len(b"my string"):]

            with pytest.raises(BadSignature) as exc_info:
                await signer.unsign(tampered)

            assert exc_info.value.payload == b"different"
            assert not await signer.validate(tampered)

        asyncio.run(main())

    def test_interoperable_with_sync_signer(self):
        async def main():
            backend = SyncBridgeBackend()
            async_signer = AsyncSigner(backend, salt="itsdangerous")
            sync_signer = Signer("secret-key", salt="itsdangerous")
            assert await async_signer.unsign(sync_signer.sign(b"data")) == b"data"
            assert sync_signer.unsign(await async_signer.sign(b"data")) == b"data"

        asyncio.run(main())


class TestAsyncSignerFailure:
    def test_unavailable_is_not_bad_signature(self):
        assert not issubclass(SignerUnavailable, BadSignature)

    def test_sign_unavailable(self):
        backend = FailingBackend()
        signer = AsyncSigner(backend)

        async def main():
            with pytest.raises(SignerUnavailable) as exc_info:
                await signer.sign(b"value")

            assert isinstance(exc_info.value.original_error, ConnectionError)

        asyncio.run(main())
        assert backend.calls == 1

    def test_verify_unavailable_does_not_fall_back(self):
        backend = FailingBackend()
        signer = AsyncSigner(backend)
        signed = asyncio.run(AsyncSigner(HMACBackend()).sign(b"value"))

        async def main():
            with pytest.raises(SignerUnavailable):
                await signer.unsign(signed)

            # validate must not treat an unavailable service as an
            # invalid signature, and must not succeed either.
            with pytest.raises(SignerUnavailable):
                await signer.validate(signed)

        asyncio.run(main())

    def test_backend_may_raise_unavailable_directly(self):
        backend = FailingBackend(SignerUnavailable("down"))
        signer = AsyncSigner(backend)

        async def main():
            with pytest.raises(SignerUnavailable):
                await signer.sign(b"value")

        asyncio.run(main())


class TestAsyncSignerCancellation:
    def test_cancel_sign(self):
        backend = HangingBackend()
        signer = AsyncSigner(backend)

        async def main():
            task = asyncio.create_task(signer.sign(b"value"))
            await backend.entered.wait()
            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        assert backend.cancelled

    def test_cancel_verify(self):
        signed = asyncio.run(AsyncSigner(HMACBackend()).sign(b"value"))
        backend = HangingBackend()
        signer = AsyncSigner(backend)

        async def main():
            task = asyncio.create_task(signer.unsign(signed))
            await backend.entered.wait()
            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        assert backend.cancelled

    def test_timeout_is_not_bad_signature(self):
        backend = HangingBackend()
        signer = AsyncSigner(backend)

        async def main():
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(signer.sign(b"value"), timeout=0.01)

        asyncio.run(main())


class TestAsyncSerializer:
    def test_round_trip(self):
        async def main():
            s = AsyncSerializer(HMACBackend())
            signed = await s.dumps({"id": 42})
            assert isinstance(signed, str)
            assert not asyncio.iscoroutine(signed)
            assert await s.loads(signed) == {"id": 42}

        asyncio.run(main())

    def test_bytes_serializer(self):
        async def main():
            s = AsyncSerializer(HMACBackend(), serializer=pickle)
            signed = await s.dumps({"id": 42})
            assert isinstance(signed, bytes)
            assert await s.loads(signed) == {"id": 42}

        asyncio.run(main())

    def test_salt_is_passed_as_purpose(self):
        backend = HMACBackend()
        s = AsyncSerializer(backend, salt="my-purpose")

        async def main():
            signed = await s.dumps([1, 2])
            assert await s.loads(signed) == [1, 2]

        asyncio.run(main())
        assert backend.sign_calls[0][1] == b"my-purpose"
        assert len(backend.sign_calls) == 1
        assert len(backend.verify_calls) == 1

    def test_interoperable_with_sync_serializer(self):
        async def main():
            sync = Serializer("secret-key")
            async_ = AsyncSerializer(SyncBridgeBackend())
            assert await async_.loads(sync.dumps({"id": 42})) == {"id": 42}
            assert sync.loads(await async_.dumps({"id": 42})) == {"id": 42}

        asyncio.run(main())

    def test_fallback_signers(self):
        async def main():
            backend = HMACBackend()
            old = AsyncSerializer(backend, signer_kwargs={"sep": b"|"})
            token = await old.dumps({"id": 1})
            s = AsyncSerializer(backend, fallback_signers=[{"sep": b"|"}])
            assert await s.loads(token) == {"id": 1}

        asyncio.run(main())

    def test_tampered(self):
        async def main():
            s = AsyncSerializer(HMACBackend())
            signed = await s.dumps({"id": 42})
            tampered = "X" + signed[1:]

            with pytest.raises(BadSignature):
                await s.loads(tampered)

        asyncio.run(main())

    def test_loads_unsafe_bad_signature(self):
        async def main():
            s = AsyncSerializer(HMACBackend())
            signed = await s.dumps({"id": 42})
            value, sig = signed.rsplit(".", 1)
            tampered = value + "." + base64_encode(b"forged").decode()
            ok, payload = await s.loads_unsafe(tampered)
            assert not ok
            assert payload == {"id": 42}

        asyncio.run(main())

    def test_unavailable_is_not_silently_downgraded(self):
        backend = FailingBackend()
        s = AsyncSerializer(backend)
        signed = asyncio.run(AsyncSerializer(HMACBackend()).dumps({"id": 42}))

        async def main():
            with pytest.raises(SignerUnavailable):
                await s.loads(signed)

            # loads_unsafe must not return the unverified payload
            # when the signing service is unavailable.
            with pytest.raises(SignerUnavailable):
                await s.loads_unsafe(signed)

        asyncio.run(main())


class TestAsyncTimedSerializer:
    def test_round_trip(self):
        async def main():
            s = AsyncTimedSerializer(HMACBackend())

            with freeze_time("2024-01-01"):
                signed = await s.dumps({"id": 42})

            with freeze_time("2024-01-01 00:00:30"):
                assert await s.loads(signed, max_age=60) == {"id": 42}
                payload, dt = await s.loads(signed, max_age=60, return_timestamp=True)
                assert payload == {"id": 42}
                assert dt.year == 2024

        asyncio.run(main())

    def test_expired(self):
        async def main():
            s = AsyncTimedSerializer(HMACBackend())

            with freeze_time("2024-01-01"):
                signed = await s.dumps({"id": 42})

            with freeze_time("2024-01-02"):
                with pytest.raises(SignatureExpired):
                    await s.loads(signed, max_age=60)

        asyncio.run(main())

    def test_max_age_checked_after_verification(self):
        async def main():
            s = AsyncTimedSerializer(HMACBackend())

            with freeze_time("2024-01-01"):
                signed = await s.dumps({"id": 42})

            value, sig = signed.rsplit(".", 1)
            tampered = value + "." + base64_encode(b"forged").decode()

            with freeze_time("2024-01-02"):
                # An invalid signature must be reported as such, not
                # as expired, even if the timestamp is too old.
                with pytest.raises(BadTimeSignature) as exc_info:
                    await s.loads(tampered, max_age=60)

                assert not isinstance(exc_info.value, SignatureExpired)

        asyncio.run(main())

    def test_timestamp_determined_once_per_sign(self):
        class CountingSigner(AsyncTimestampSigner):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.timestamp_calls = 0

            def get_timestamp(self):
                self.timestamp_calls += 1
                return super().get_timestamp()

        async def main():
            signer = CountingSigner(HMACBackend())

            with freeze_time("2024-01-01"):
                signed = await signer.sign(b"value")

            assert signer.timestamp_calls == 1
            value, ts = await signer.unsign(signed, return_timestamp=True)
            assert value == b"value"
            assert signer.timestamp_calls == 1

        asyncio.run(main())

    def test_signed_structure(self):
        async def main():
            signer = AsyncTimestampSigner(HMACBackend())

            with freeze_time("2024-01-01"):
                signed = await signer.sign(b"value")

            value, ts, sig = signed.rsplit(b".", 2)
            assert value == b"value"
            assert base64_decode(ts)
            assert base64_decode(sig)

        asyncio.run(main())


class TestAsyncURLSafe:
    @pytest.mark.parametrize(
        "cls", [AsyncURLSafeSerializer, AsyncURLSafeTimedSerializer]
    )
    def test_round_trip(self, cls):
        async def main():
            s = cls(HMACBackend())
            signed = await s.dumps([1, 2, 3, 4])
            assert isinstance(signed, str)
            assert await s.loads(signed) == [1, 2, 3, 4]

        asyncio.run(main())

    def test_interoperable_with_sync(self):
        async def main():
            sync = URLSafeSerializer("secret-key")
            async_ = AsyncURLSafeSerializer(SyncBridgeBackend())
            assert await async_.loads(sync.dumps([1, 2, 3])) == [1, 2, 3]
            assert sync.loads(await async_.dumps([1, 2, 3])) == [1, 2, 3]

        asyncio.run(main())

    def test_timed_interoperable_with_sync(self):
        async def main():
            sync = URLSafeTimedSerializer("secret-key")
            async_ = AsyncURLSafeTimedSerializer(SyncBridgeBackend())

            with freeze_time("2024-01-01"):
                token = await async_.dumps([1, 2, 3])
                assert sync.loads(token, max_age=3600) == [1, 2, 3]
                token = sync.dumps([1, 2, 3])
                assert await async_.loads(token, max_age=3600) == [1, 2, 3]

        asyncio.run(main())


def test_sync_api_does_not_start_event_loop(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("sync API must not start an event loop")

    monkeypatch.setattr(asyncio, "run", fail)
    monkeypatch.setattr(asyncio, "new_event_loop", fail)
    monkeypatch.setattr(asyncio, "get_event_loop", fail)

    signer = Signer("secret-key")
    assert signer.unsign(signer.sign(b"value")) == b"value"

    ts_signer = TimestampSigner("secret-key")
    assert ts_signer.unsign(ts_signer.sign(b"value"), max_age=10) == b"value"

    s = Serializer("secret-key")
    assert s.loads(s.dumps({"id": 1})) == {"id": 1}

    timed = TimedSerializer("secret-key")
    assert timed.loads(timed.dumps({"id": 1}), max_age=10) == {"id": 1}

    url = URLSafeSerializer("secret-key")
    assert url.loads(url.dumps([1, 2])) == [1, 2]

    url_timed = URLSafeTimedSerializer("secret-key")
    assert url_timed.loads(url_timed.dumps([1, 2]), max_age=10) == [1, 2]
