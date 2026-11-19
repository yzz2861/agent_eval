##############################################################################
#
# Copyright (c) 2026 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""Tests for the revocable capability integration layer.

The scheduling is fully deterministic: no threads, no time based logic and
no external services.  A harmless integer counter is the host capability,
and ``CapabilityDomain.before_revoke`` is used as the explicit revocation
linearization point.
"""

import pytest

from RestrictedPython import CapabilityDomain
from RestrictedPython import CapabilityRevokedError
from RestrictedPython import RevocableDict
from RestrictedPython import RevocableList
from RestrictedPython import compile_restricted_exec
from RestrictedPython import guarded_getitem
from RestrictedPython import revocable_generator
from RestrictedPython.Guards import safe_builtins


class HostCounter:
    """The harmless host capability used by every test."""

    def __init__(self):
        self.value = 0

    def increment(self, amount=1):
        self.value += amount
        return self.value


@pytest.fixture
def domain():
    return CapabilityDomain("test-domain")


@pytest.fixture
def counter():
    return HostCounter()


def _grant(domain, counter, name="increment"):
    return domain.grant(counter.increment, name)


def _exec_restricted(source, domain, capability, counter):
    """Run *source* with the default compile API and guarded globals."""
    result = compile_restricted_exec(source)
    assert result.errors == ()
    glb = {
        "__builtins__": safe_builtins,
        "_write_": lambda value: value,
        "_getattr_": getattr,
        "_getiter_": iter,
        "_getitem_": lambda ob, key: guarded_getitem(domain, ob, key),
        "increment": capability,
        "store": RevocableDict(domain),
        "bucket": RevocableList(domain),
        "counter": counter,
    }
    exec(result.code, glb)
    return glb



def test_call_then_revoke_blocks_the_next_call(domain, counter):
    """Call before revoke works; every call after it is refused."""
    capability = _grant(domain, counter)

    assert capability() == 1
    assert counter.value == 1

    domain.revoke()

    with pytest.raises(CapabilityRevokedError):
        capability()
    assert counter.value == 1


def test_revoke_then_call_blocks_immediately(domain, counter):
    """A capability revoked before its first use never runs."""
    capability = _grant(domain, counter)
    domain.revoke()

    with pytest.raises(CapabilityRevokedError):
        capability(5)
    assert counter.value == 0


def test_saved_alias_cannot_be_revived(domain, counter):
    """A plain name alias is just another reference to the wrapper."""
    capability = _grant(domain, counter)
    alias = capability

    domain.revoke()
    with pytest.raises(CapabilityRevokedError):
        alias()

    fresh = _grant(domain, counter)
    assert fresh() == 1
    with pytest.raises(CapabilityRevokedError):
        alias()
    with pytest.raises(CapabilityRevokedError):
        capability()


def test_closure_cell_is_checked_at_call_time(domain, counter):
    """The capability captured by a closure stays revocable."""
    capability = _grant(domain, counter)

    source = (
        "def make_caller(fn):\n"
        "    def caller():\n"
        "        return fn()\n"
        "    return caller\n"
        "caller = make_caller(increment)\n"
        "before = caller()\n"
    )
    glb = _exec_restricted(source, domain, capability, counter)
    assert glb["before"] == 1

    domain.revoke()
    with pytest.raises(CapabilityRevokedError):
        glb["caller"]()
    assert counter.value == 1


def test_container_entries_keep_the_grant_generation(domain, counter):
    """Capabilities stored in guarded containers die with the domain."""
    capability = _grant(domain, counter)
    store = RevocableDict(domain, {"fn": capability})
    bucket = RevocableList(domain, [capability])

    assert store["fn"]() == 1
    assert bucket[0]() == 2

    domain.revoke()
    with pytest.raises(CapabilityRevokedError):
        store["fn"]
    with pytest.raises(CapabilityRevokedError):
        bucket[0]
    with pytest.raises(CapabilityRevokedError):
        len(store)
    with pytest.raises(CapabilityRevokedError):
        list(bucket)


def test_old_containers_stay_dead_after_re_grant(domain, counter):
    """Re-granting at a new generation must not resurrect old containers."""
    old_store = RevocableDict(domain, {"value": 1})
    domain.revoke()
    domain.grant(counter.increment)

    with pytest.raises(CapabilityRevokedError):
        old_store["value"]

    new_store = RevocableDict(domain, {"value": 2})
    assert new_store["value"] == 2



def test_generator_resume_checks_every_step(domain, counter):
    """A generator saved by restricted code is gated on every resume."""
    capability = _grant(domain, counter)
    guarded = revocable_generator(
        domain, (capability() for _ in range(4)))

    assert next(guarded) == 1
    assert next(guarded) == 2

    domain.revoke()
    with pytest.raises(CapabilityRevokedError):
        next(guarded)
    assert counter.value == 2


def test_generator_revoked_before_first_step_never_runs(domain, counter):
    """Revocation before the first ``next()`` stops iteration entirely."""
    capability = _grant(domain, counter)
    guarded = revocable_generator(
        domain, (capability() for _ in range(3)))
    domain.revoke()

    with pytest.raises(CapabilityRevokedError):
        next(guarded)
    assert counter.value == 0


def test_revocation_is_linearized_through_before_revoke(domain, counter):
    """The hook defines one explicit, deterministic revocation point."""
    log = []
    capability = _grant(domain, counter)

    def hook(active_domain):
        assert active_domain is domain
        # The generation only changes after the hook returns: an operation
        # scheduled here is strictly before the revocation point.
        log.append(("hook", domain.generation))
        assert capability() == 1

    domain.before_revoke = hook
    domain.revoke()

    assert log == [("hook", 0)]
    assert domain.generation == 1
    with pytest.raises(CapabilityRevokedError):
        capability()
    assert counter.value == 1


def test_in_flight_call_commits_its_side_effect(domain, counter):
    """A call that passed the check completes; nothing is rolled back."""

    def revoking_operation():
        domain.revoke()
        counter.increment()
        return "committed"

    capability = domain.grant(revoking_operation, "revoking_operation")
    assert capability() == "committed"
    assert counter.value == 1

    with pytest.raises(CapabilityRevokedError):
        capability()
    assert counter.value == 1


def test_revocation_does_not_touch_other_domains(counter):
    """Each domain owns an independent generation counter."""
    first = CapabilityDomain("first")
    second = CapabilityDomain("second")
    first_cap = first.grant(counter.increment, "first")
    second_cap = second.grant(counter.increment, "second")

    first.revoke()

    with pytest.raises(CapabilityRevokedError):
        first_cap()
    assert second_cap() == 1
    assert first.generation == 1
    assert second.generation == 0

    second.revoke()
    with pytest.raises(CapabilityRevokedError):
        second_cap()


def test_domain_rejects_foreign_and_non_capabilities(domain, counter):
    """The explicit domain check rejects wrong types and other domains."""
    other = CapabilityDomain("other")
    foreign = other.grant(counter.increment)

    with pytest.raises(TypeError):
        domain.check(counter.increment)
    with pytest.raises(ValueError):
        domain.check(foreign)

    local = _grant(domain, counter)
    domain.check(local)
    domain.revoke()
    with pytest.raises(CapabilityRevokedError):
        domain.check(local)



def test_guarded_getitem_supports_generation_snapshots(domain):
    """A bound generation stays stale after revocation and re-grant."""
    container = {"key": "value"}
    granted_generation = domain.generation

    assert guarded_getitem(domain, container, "key") == "value"
    assert guarded_getitem(
        domain, container, "key", granted_generation) == "value"

    domain.revoke()
    with pytest.raises(CapabilityRevokedError):
        guarded_getitem(domain, container, "key", granted_generation)

    domain.grant(lambda: None)
    with pytest.raises(CapabilityRevokedError):
        guarded_getitem(domain, container, "key", granted_generation)
    assert guarded_getitem(domain, container, "key") == "value"



def test_restricted_code_using_all_aliasing_forms(domain, counter):
    """End-to-end check through the unchanged compile API."""
    capability = _grant(domain, counter)
    source = (
        "alias = increment\n"
        "store[\"fn\"] = increment\n"
        "bucket.append(increment)\n"
        "def closed():\n"
        "    return increment()\n"
        "gen = revocable_generator(domain_obj, "
        "(increment() for _ in range(2)))\n"
        "first = alias()\n"
        "second = store[\"fn\"]()\n"
        "third = bucket[0]()\n"
        "fourth = closed()\n"
        "fifth = next(gen)\n"
    )
    result = compile_restricted_exec(source)
    assert result.errors == ()
    glb = {
        "__builtins__": safe_builtins,
        "_write_": lambda value: value,
        "_getattr_": getattr,
        "_getiter_": iter,
        "_getitem_": lambda ob, key: guarded_getitem(domain, ob, key),
        "increment": capability,
        "store": RevocableDict(domain),
        "bucket": RevocableList(domain),
        "domain_obj": domain,
        "revocable_generator": revocable_generator,
        "next": next,
    }
    exec(result.code, glb)
    assert (glb["first"], glb["second"], glb["third"],
            glb["fourth"], glb["fifth"]) == (1, 2, 3, 4, 5)

    domain.revoke()
    with pytest.raises(CapabilityRevokedError):
        glb["alias"]()
    with pytest.raises(CapabilityRevokedError):
        glb["closed"]()
    with pytest.raises(CapabilityRevokedError):
        next(glb["gen"])
    with pytest.raises(CapabilityRevokedError):
        glb["store"]["fn"]
    with pytest.raises(CapabilityRevokedError):
        glb["bucket"][0]
    assert counter.value == 5


def test_wrapper_metadata_is_preserved(domain, counter):
    """The wrapper keeps the wrapped callable metadata."""
    capability = _grant(domain, counter)
    assert capability.__name__ == "increment"
    assert capability.__wrapped__ == counter.increment
    assert repr(capability).startswith("<RevocableCapability")
    assert capability.revoked is False

    domain.revoke()
    assert capability.revoked is True



def test_revocable_generator_accepts_plain_iterators(domain, counter):
    """Any iterator can be guarded, not only generator objects."""
    guarded = revocable_generator(domain, iter([1, 2, 3]))
    assert list(guarded) == [1, 2, 3]

    with pytest.raises(TypeError):
        revocable_generator(domain, 42)


def test_container_mixin_methods_are_gated(domain):
    """Methods inherited from the container ABCs share the generation gate."""
    store = RevocableDict(domain, {"a": 1})
    bucket = RevocableList(domain, [1, 2])
    domain.revoke()

    with pytest.raises(CapabilityRevokedError):
        store.get("a")
    with pytest.raises(CapabilityRevokedError):
        "a" in store
    with pytest.raises(CapabilityRevokedError):
        list(store.keys())
    with pytest.raises(CapabilityRevokedError):
        1 in bucket
    with pytest.raises(CapabilityRevokedError):
        list(bucket)

