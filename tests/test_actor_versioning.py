from __future__ import annotations

import logging

import pytest

import dramatiq
from dramatiq import Message, Worker
from dramatiq.brokers.stub import StubBroker
from dramatiq.errors import ActorNotFound


def test_message_stamps_actor_version(stub_broker):
    # Given an actor with an explicit version
    @dramatiq.actor(version="v1")
    def work():
        pass

    # When I build and send a message
    message = work.message()
    sent = work.send()

    # Then both messages carry the actor's version
    assert message.actor_version == "v1"
    assert sent.actor_version == "v1"

    # And the version survives an encode/decode roundtrip
    assert Message.decode(sent.encode()).actor_version == "v1"


def test_unversioned_actor_sends_unversioned_messages(stub_broker):
    # Given an actor without a version
    @dramatiq.actor
    def work():
        pass

    # When I build a message
    message = work.message()

    # Then it carries no version
    assert message.actor_version is None


def test_decode_old_message_without_version_field(stub_broker):
    # Given a message encoded by an older version of Dramatiq that
    # doesn't know about actor versions
    message = Message(queue_name="default", actor_name="work", args=(), kwargs={}, options={})
    data = message.asdict()
    del data["actor_version"]

    # When I decode it
    decoded = Message.decode(dramatiq.get_encoder().encode(data))

    # Then it decodes cleanly with no version
    assert decoded.actor_version is None


def test_duplicate_version_registration_raises(stub_broker):
    # Given an actor registered with a specific version
    @dramatiq.actor(actor_name="work", version="v1")
    def work_v1():
        pass

    # When I try to register another actor with the same name and version
    with pytest.raises(ValueError) as exc_info:

        @dramatiq.actor(actor_name="work", version="v1")
        def work_v1_again():
            pass

    # Then a ValueError is raised at declaration time
    assert str(exc_info.value) == "An actor named 'work' with version 'v1' is already registered."


def test_same_name_different_versions_allowed(stub_broker):
    # Given two actors with the same name but different versions
    @dramatiq.actor(actor_name="work", version="v1")
    def work_v1():
        pass

    @dramatiq.actor(actor_name="work", version="v2")
    def work_v2():
        pass

    # Then both are registered and individually addressable
    assert stub_broker.get_actor("work", version="v1") is work_v1
    assert stub_broker.get_actor("work", version="v2") is work_v2

    # And the most recently declared version is the default
    assert stub_broker.get_actor("work") is work_v2


def test_worker_dispatches_to_message_version(stub_broker, stub_worker):
    # Given two versions of the same actor that record their calls
    calls = []

    @dramatiq.actor(actor_name="work", version="v1")
    def work_v1():
        calls.append("v1")

    @dramatiq.actor(actor_name="work", version="v2")
    def work_v2():
        calls.append("v2")

    # When I send a message through each version
    work_v1.send()
    work_v2.send()
    stub_broker.join("default")
    stub_worker.join()

    # Then each message is dispatched to the version it was sent with
    assert calls == ["v1", "v2"]


def test_default_version_only_affects_new_messages(stub_broker):
    # Given a v1 actor and a message that has already been enqueued
    calls = []

    @dramatiq.actor(actor_name="work", version="v1")
    def work_v1():
        calls.append("v1")

    work_v1.send()

    # When a new default version is declared after the message was sent
    @dramatiq.actor(actor_name="work", version="v2")
    def work_v2():
        calls.append("v2")

    # Then the queued message still runs the original version
    worker = Worker(stub_broker, worker_timeout=100)
    worker.start()
    try:
        stub_broker.join("default")
        worker.join()
    finally:
        worker.stop()
    assert calls == ["v1"]

    # And new messages sent by name use the new default version
    stub_broker.get_actor("work").send()
    worker = Worker(stub_broker, worker_timeout=100)
    worker.start()
    try:
        stub_broker.join("default")
        worker.join()
    finally:
        worker.stop()
    assert calls == ["v1", "v2"]


def test_retries_keep_original_version(stub_broker, stub_worker):
    # Given a v1 actor that fails on its first attempt
    calls = []

    @dramatiq.actor(actor_name="work", version="v1", max_retries=3, min_backoff=10, max_backoff=100)
    def work_v1():
        calls.append("v1")
        if calls.count("v1") < 2:
            raise RuntimeError("boom")

    work_v1.send()

    # And a newer default version declared before the message is processed
    @dramatiq.actor(actor_name="work", version="v2")
    def work_v2():
        calls.append("v2")

    # When the message is processed and retried
    stub_broker.join("default")
    stub_worker.join()

    # Then both attempts run the original version
    assert calls == ["v1", "v1"]


def test_pipeline_successors_keep_their_versions(stub_broker, stub_worker):
    # Given two versions of the same actor chained into a pipeline
    calls = []

    @dramatiq.actor(actor_name="step", version="v1")
    def step_v1(x):
        calls.append(("v1", (x,)))
        return x + 1

    @dramatiq.actor(actor_name="step", version="v2")
    def step_v2(*args):
        calls.append(("v2", args))

    # When the pipeline runs
    dramatiq.pipeline([step_v1.message(1), step_v2.message(2)]).run()
    stub_broker.join("default")
    stub_worker.join()

    # Then each step runs the version it was composed with
    assert calls == [("v1", (1,)), ("v2", (2, 2))]


def test_unknown_version_error_policy_dead_letters_message(stub_broker, stub_worker):
    # Given an actor whose registered version is v1
    calls = []

    @dramatiq.actor(actor_name="work", version="v1")
    def work():
        calls.append("v1")

    # When a message for an unregistered version is enqueued
    message = Message(queue_name="default", actor_name="work", actor_version="v9", args=(), kwargs={}, options={})
    stub_broker.enqueue(message)
    stub_broker.join("default", fail_fast=False)
    stub_worker.join()

    # Then the actor doesn't run and the message is dead-lettered
    assert calls == []
    assert [m.message_id for m in stub_broker.dead_letters] == [message.message_id]


def test_unknown_version_default_policy_falls_back_with_warning(stub_broker, stub_worker, caplog):
    # Given a broker that falls back to the default version
    stub_broker.unknown_version_policy = "default"
    calls = []

    @dramatiq.actor(actor_name="work", version="v1")
    def work():
        calls.append("v1")

    # When a message for an unregistered version is enqueued
    message = Message(queue_name="default", actor_name="work", actor_version="v9", args=(), kwargs={}, options={})
    stub_broker.enqueue(message)
    with caplog.at_level(logging.WARNING):
        stub_broker.join("default")
        stub_worker.join()

    # Then the default version runs and the fallback is logged
    assert calls == ["v1"]
    assert not stub_broker.dead_letters
    assert any("unregistered version" in record.message for record in caplog.records)


def test_unversioned_message_error_policy_dead_letters_message(stub_broker, stub_worker):
    # Given a broker that rejects messages without a version
    stub_broker.unversioned_message_policy = "error"
    calls = []

    @dramatiq.actor(actor_name="work", version="v1")
    def work():
        calls.append("v1")

    # When an old message without a version is enqueued
    message = Message(queue_name="default", actor_name="work", args=(), kwargs={}, options={})
    stub_broker.enqueue(message)
    stub_broker.join("default", fail_fast=False)
    stub_worker.join()

    # Then the actor doesn't run and the message is dead-lettered
    assert calls == []
    assert [m.message_id for m in stub_broker.dead_letters] == [message.message_id]


def test_unversioned_message_default_policy_uses_default_version_with_warning(stub_broker, stub_worker, caplog):
    # Given an actor that only exists as version v1
    calls = []

    @dramatiq.actor(actor_name="work", version="v1")
    def work():
        calls.append("v1")

    # When an old message without a version is enqueued
    message = Message(queue_name="default", actor_name="work", args=(), kwargs={}, options={})
    stub_broker.enqueue(message)
    with caplog.at_level(logging.WARNING):
        stub_broker.join("default")
        stub_worker.join()

    # Then the default version runs and the fallback is logged
    assert calls == ["v1"]
    assert any("without a version" in record.message for record in caplog.records)


def test_unversioned_actor_handles_unversioned_messages_silently(stub_broker, stub_worker, caplog):
    # Given a plain unversioned actor
    calls = []

    @dramatiq.actor
    def work():
        calls.append("ran")

    # When a message without a version is processed
    work.send()
    with caplog.at_level(logging.WARNING):
        stub_broker.join("default")
        stub_worker.join()

    # Then it runs without any version-related warnings
    assert calls == ["ran"]
    assert not [record for record in caplog.records if "version" in record.message]


def test_set_default_actor_version(stub_broker):
    # Given two versions of the same actor
    @dramatiq.actor(actor_name="work", version="v1")
    def work_v1():
        pass

    @dramatiq.actor(actor_name="work", version="v2")
    def work_v2():
        pass

    # The most recently declared version is the default
    assert stub_broker.get_actor("work") is work_v2

    # When I switch the default version back to v1
    stub_broker.set_default_actor_version("work", "v1")

    # Then new lookups by name resolve to v1
    assert stub_broker.get_actor("work") is work_v1

    # And setting an unregistered version raises ActorNotFound
    with pytest.raises(ActorNotFound):
        stub_broker.set_default_actor_version("work", "v9")


def test_invalid_version_policy_raises():
    # Given an invalid version policy
    # Then broker construction fails fast
    with pytest.raises(ValueError):
        StubBroker(unversioned_message_policy="bogus")

    with pytest.raises(ValueError):
        StubBroker(unknown_version_policy="bogus")


def test_delayed_message_keeps_version_across_default_switch(stub_broker):
    # Given a v1 actor and a delayed message
    calls = []

    @dramatiq.actor(actor_name="work", version="v1")
    def work_v1():
        calls.append("v1")

    work_v1.send_with_options(delay=50)

    # And a newer default version declared before the delay expires
    @dramatiq.actor(actor_name="work", version="v2")
    def work_v2():
        calls.append("v2")

    # When the delayed message is delivered
    worker = Worker(stub_broker, worker_timeout=100)
    worker.start()
    try:
        stub_broker.join("default")
        worker.join()
    finally:
        worker.stop()

    # Then it still runs the version it was sent with
    assert calls == ["v1"]
