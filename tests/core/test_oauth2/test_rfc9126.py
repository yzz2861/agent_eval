import threading

import pytest

from authlib.oauth2.rfc9126 import InMemoryPushedAuthorizationRequestStorage
from authlib.oauth2.rfc9126 import PushedAuthorizationRequestNotFoundError


def test_in_memory_storage_consumes_once():
    storage = InMemoryPushedAuthorizationRequestStorage()
    storage.save("urn:request", "client-id", {"response_type": "code"}, 2**31)

    request = storage.consume("urn:request")
    assert request.get_client_id() == "client-id"

    with pytest.raises(PushedAuthorizationRequestNotFoundError):
        storage.consume("urn:request")


def test_in_memory_storage_rejects_expired_and_bound_request():
    storage = InMemoryPushedAuthorizationRequestStorage()
    storage.save("urn:expired", "client-id", {}, 0)
    storage.save("urn:bound", "client-id", {}, 2**31)

    with pytest.raises(PushedAuthorizationRequestNotFoundError):
        storage.consume("urn:expired")
    with pytest.raises(PushedAuthorizationRequestNotFoundError):
        storage.consume("urn:bound", "other-client")


def test_in_memory_storage_consumption_is_atomic():
    storage = InMemoryPushedAuthorizationRequestStorage()
    storage.save("urn:request", "client-id", {}, 2**31)
    winners = []
    barrier = threading.Barrier(8)

    def consume():
        barrier.wait()
        try:
            storage.consume("urn:request")
        except PushedAuthorizationRequestNotFoundError:
            return
        winners.append(threading.get_ident())

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(winners) == 1
