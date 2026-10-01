from __future__ import annotations

import logging

import pytest

import dramatiq
from dramatiq import Message
from dramatiq.brokers.stub import StubBroker


def test_actors_with_same_name_but_different_versions_can_be_registered(stub_broker):
    # Given two actors that share a name but declare different versions
    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        pass

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2():
        pass

    # Then both versions should be registered on the broker
    assert stub_broker.actor_versions["add"] == {"v1": add_v1, "v2": add_v2}
    # And the first declared version should be the default
    assert stub_broker.get_actor("add") is add_v1
    assert stub_broker.get_actor("add", "v2") is add_v2


def test_registering_the_same_name_and_version_twice_raises(stub_broker):
    # Given an actor with an explicit version
    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        pass

    # When I try to declare another actor with the same name and version
    # Then a ValueError should be raised
    with pytest.raises(ValueError) as exc_info:

        @dramatiq.actor(actor_name="add", actor_version="v1")
        def add_v1_again():
            pass

    assert str(exc_info.value) == "An actor named 'add' with version 'v1' is already registered."


def test_messages_carry_the_version_of_the_actor_that_sent_them(stub_broker):
    # Given two versions of an actor
    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        pass

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2():
        pass

    # When I build messages through each actor
    message_v1 = add_v1.message()
    message_v2 = add_v2.message()

    # Then each message should record the version of its actor
    assert message_v1.actor_version == "v1"
    assert message_v2.actor_version == "v2"

    # And the version should survive an encode/decode roundtrip
    assert Message.decode(message_v1.encode()).actor_version == "v1"
    assert Message.decode(message_v2.encode()).actor_version == "v2"


def test_messages_without_a_version_decode_as_unversioned(stub_broker):
    # Given a message encoded by an older version of dramatiq (no actor_version field)
    message = Message(queue_name="default", actor_name="add", args=(), kwargs={}, options={})
    encoded = message.encode()
    assert b"actor_version" not in encoded or message.actor_version is None

    # When I decode a payload that lacks the actor_version key
    import json

    payload = json.dumps(
        {
            "queue_name": "default",
            "actor_name": "add",
            "args": [],
            "kwargs": {},
            "options": {},
            "message_id": "id-1",
            "message_timestamp": 0,
        }
    ).encode()
    decoded = Message.decode(payload)

    # Then the message should decode as unversioned
    assert decoded.actor_version is None


def test_worker_dispatches_messages_to_their_declared_version(stub_broker, stub_worker):
    # Given two versions of an actor that record their calls
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1(x):
        calls.append("v1")

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2(x):
        calls.append("v2")

    # When I send a message through the v1 actor
    add_v1.send(1)
    stub_broker.join(add_v1.queue_name)
    stub_worker.join()

    # Then the v1 implementation should have run
    assert calls == ["v1"]


def test_switching_the_default_version_does_not_affect_queued_messages(stub_broker, stub_worker):
    # Given two versions of an actor that record their calls
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        calls.append("v1")

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2():
        calls.append("v2")

    # When I enqueue a message through v1 and then switch the default version
    add_v1.send()
    stub_broker.set_default_actor("add", "v2")

    # Then the queued message should still run the v1 implementation
    stub_broker.join(add_v1.queue_name)
    stub_worker.join()
    assert calls == ["v1"]

    # And new messages sent through the default actor should run v2
    stub_broker.get_actor("add").send()
    stub_broker.join(add_v1.queue_name)
    stub_worker.join()
    assert calls == ["v1", "v2"]


def test_retries_keep_the_version_of_the_original_message(stub_broker, stub_worker):
    # Given two versions of an actor where v1 fails on its first run
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1", max_retries=2)
    def add_v1():
        calls.append("v1")
        if calls.count("v1") == 1:
            raise dramatiq.Retry(delay=50)

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2():
        calls.append("v2")

    # When I send a message through v1 and switch the default version before it is retried
    add_v1.send()
    stub_broker.set_default_actor("add", "v2")
    stub_broker.join(add_v1.queue_name)
    stub_worker.join()

    # Then the retry should have run the v1 implementation again
    assert calls == ["v1", "v1"]


def test_pipeline_successors_keep_their_declared_versions(stub_broker, stub_worker):
    # Given two versions of an actor that record their calls
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1(x):
        calls.append("v1")
        return x + 1

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2(x):
        calls.append("v2")
        return x + 1

    # When I run a pipeline whose successor was built from the v2 actor
    pipe = dramatiq.pipeline([add_v1.message(1), add_v2.message()])

    # Then the pipe target should record the successor's version
    assert pipe.messages[0].options["pipe_target"]["actor_version"] == "v2"

    # And when the pipeline runs
    pipe.run()
    stub_broker.join(add_v1.queue_name)
    stub_worker.join()

    # Then each step should have been dispatched to its declared version
    assert calls == ["v1", "v2"]


def test_unversioned_messages_fall_back_to_the_default_version_with_a_warning(stub_broker, stub_worker, caplog):
    # Given two versions of an actor that record their calls
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        calls.append("v1")

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2():
        calls.append("v2")

    # When I enqueue a message that doesn't declare a version
    message = Message(queue_name="default", actor_name="add", args=(), kwargs={}, options={})
    with caplog.at_level(logging.WARNING):
        stub_broker.enqueue(message)
    stub_broker.join("default")
    stub_worker.join()

    # Then the default version should have run
    assert calls == ["v1"]

    # And the fallback should have been logged
    assert any("doesn't declare an actor version" in record.message for record in caplog.records)


def test_unversioned_messages_are_rejected_when_the_policy_is_error(stub_broker, stub_worker):
    # Given a broker that rejects unversioned messages
    stub_broker.unversioned_message_policy = "error"
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        calls.append("v1")

    # When I enqueue a message that doesn't declare a version
    message = Message(queue_name="default", actor_name="add", args=(), kwargs={}, options={})
    stub_broker.enqueue(message)
    stub_broker.join("default", fail_fast=False)
    stub_worker.join()

    # Then the message should not have run and should have been dead-lettered
    assert calls == []
    assert [m.message_id for m in stub_broker.dead_letters] == [message.message_id]


def test_messages_with_unknown_versions_are_rejected_by_default(stub_broker, stub_worker):
    # Given an actor with a single registered version
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        calls.append("v1")

    # When I enqueue a message that declares an unregistered version
    message = Message(queue_name="default", actor_name="add", args=(), kwargs={}, options={}, actor_version="v9")
    stub_broker.enqueue(message)
    stub_broker.join("default", fail_fast=False)
    stub_worker.join()

    # Then the message should not have run and should have been dead-lettered
    assert calls == []
    assert [m.message_id for m in stub_broker.dead_letters] == [message.message_id]


def test_messages_with_unknown_versions_fall_back_to_the_default_version_when_configured(stub_broker, stub_worker, caplog):
    # Given a broker that falls back to the default version for unknown versions
    stub_broker.unknown_version_policy = "default"
    calls = []

    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        calls.append("v1")

    # When I enqueue a message that declares an unregistered version
    message = Message(queue_name="default", actor_name="add", args=(), kwargs={}, options={}, actor_version="v9")
    with caplog.at_level(logging.WARNING):
        stub_broker.enqueue(message)
    stub_broker.join("default")
    stub_worker.join()

    # Then the default version should have run
    assert calls == ["v1"]

    # And the fallback should have been logged
    assert any("unknown version" in record.message for record in caplog.records)


def test_set_default_actor_changes_the_default_version(stub_broker):
    # Given two versions of an actor
    @dramatiq.actor(actor_name="add", actor_version="v1")
    def add_v1():
        pass

    @dramatiq.actor(actor_name="add", actor_version="v2")
    def add_v2():
        pass

    # When I change the default version
    stub_broker.set_default_actor("add", "v2")

    # Then name-based lookups should return the new default
    assert stub_broker.get_actor("add") is add_v2

    # And setting an unknown default should raise ActorNotFound
    with pytest.raises(dramatiq.ActorNotFound):
        stub_broker.set_default_actor("add", "v9")

    with pytest.raises(dramatiq.ActorNotFound):
        stub_broker.set_default_actor("missing", "v1")


def test_invalid_message_version_policies_are_rejected(stub_broker):
    # Given a broker
    # When I try to set an invalid policy
    # Then a ValueError should be raised
    with pytest.raises(ValueError):
        stub_broker.unversioned_message_policy = "bogus"

    with pytest.raises(ValueError):
        stub_broker.unknown_version_policy = "bogus"

    with pytest.raises(ValueError):
        StubBroker(unversioned_message_policy="bogus")

    with pytest.raises(ValueError):
        StubBroker(unknown_version_policy="bogus")
