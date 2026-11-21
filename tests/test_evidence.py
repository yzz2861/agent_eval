from __future__ import annotations

import threading
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from io import BytesIO

import pytest

from cbor2 import (
    CBORDecodeError,
    Evidence,
    EvidenceView,
    SharedReferenceError,
    dumps,
    load_evidence,
    loads_evidence,
)


def make_sealed_log() -> bytes:
    """A synthetic sealed log where both entries reference the same actor object."""
    actor = {"name": "root", "uid": 0}
    log = {
        "seal": {"alg": "sha256", "sig": "deadbeef"},
        "entries": [
            {"actor": actor, "action": "login"},
            {"actor": actor, "action": "logout"},
        ],
    }
    return dumps(log, value_sharing=True)


class TestEvidence:
    def test_shared_values_stay_aliased_in_evidence_root(self) -> None:
        evidence = loads_evidence(make_sealed_log())
        first = evidence.root["entries"][0]["actor"]
        second = evidence.root["entries"][1]["actor"]
        assert first is second
        assert ("entries", 1, "actor") in evidence.shared_paths

    def test_evidence_root_is_immutable(self) -> None:
        evidence = loads_evidence(make_sealed_log())
        assert isinstance(evidence.root, Mapping)
        assert not isinstance(evidence.root, dict)
        assert isinstance(evidence.root["entries"], tuple)
        with pytest.raises(TypeError):
            evidence.root["entries"] = ()

    def test_evidence_identity(self) -> None:
        data = make_sealed_log()
        evidence = loads_evidence(data)
        assert isinstance(evidence, Evidence)
        assert evidence.data == data
        assert evidence.digest == sha256(data).hexdigest()
        other = loads_evidence(dumps({"seal": {}, "entries": []}))
        assert other.digest != evidence.digest

    def test_load_evidence_from_file(self) -> None:
        data = make_sealed_log()
        evidence = load_evidence(BytesIO(data))
        assert evidence.data == data
        assert evidence.digest == sha256(data).hexdigest()

    def test_immutable_option_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="immutable"):
            loads_evidence(make_sealed_log(), immutable=False)

    def test_decoder_kwargs_are_forwarded(self) -> None:
        with pytest.raises(CBORDecodeError, match="exceeded"):
            loads_evidence(make_sealed_log(), max_depth=2)

    def test_shared_immutable_scalars_are_ignored(self) -> None:
        evidence = loads_evidence(dumps(["hello", "hello"], value_sharing=True))
        assert evidence.shared_paths == ()

    def test_empty_containers_are_not_false_positives(self) -> None:
        evidence = loads_evidence(dumps([[], [], {}]))
        assert evidence.shared_paths == ()


class TestEvidenceViewIsolation:
    def test_concurrent_component_annotations_do_not_leak(self) -> None:
        """Two review components query the same sealed log simultaneously; the
        annotations one leaves on its own view must not change the other's
        readings or the original evidence."""
        evidence = loads_evidence(make_sealed_log())
        barrier = threading.Barrier(2)

        def query_log(annotate: bool) -> EvidenceView:
            view = evidence.view()
            barrier.wait(timeout=10)
            if annotate:
                actor = view.data["entries"][0]["actor"]
                actor["annotation"] = "suspicious"
                view.data["annotations"] = ["reviewed by component A"]
            return view

        with ThreadPoolExecutor(max_workers=2) as pool:
            view_a = pool.submit(query_log, True)
            view_b = pool.submit(query_log, False)
            view_a, view_b = view_a.result(), view_b.result()

        # Component A sees its annotation through both aliases of the shared actor
        assert view_a.data["entries"][0]["actor"]["annotation"] == "suspicious"
        assert view_a.data["entries"][1]["actor"]["annotation"] == "suspicious"
        assert view_a.data["annotations"] == ["reviewed by component A"]

        # Component B's readings are unaffected
        assert "annotation" not in view_b.data["entries"][0]["actor"]
        assert "annotation" not in view_b.data["entries"][1]["actor"]
        assert "annotations" not in view_b.data
        assert view_b.data["entries"][0]["actor"] == {"name": "root", "uid": 0}

        # The original evidence is pristine
        assert "annotation" not in evidence.root["entries"][0]["actor"]
        assert "annotations" not in evidence.root

        # Both views refer to the same original evidence identity
        assert view_a.evidence is view_b.evidence is evidence
        assert view_a.evidence.digest == view_b.evidence.digest

    def test_view_preserves_aliasing_within_but_not_across_views(self) -> None:
        evidence = loads_evidence(make_sealed_log())
        first_view, second_view = evidence.view(), evidence.view()
        first_actor = first_view.data["entries"][0]["actor"]
        assert first_actor is first_view.data["entries"][1]["actor"]
        assert first_actor is not second_view.data["entries"][0]["actor"]
        assert isinstance(first_actor, dict)
        assert isinstance(first_view.data["entries"], list)

    def test_mutating_view_containers_does_not_touch_evidence(self) -> None:
        evidence = loads_evidence(make_sealed_log())
        view = evidence.view()
        view.data["entries"].append({"action": "escalate"})
        view.data["seal"]["sig"] = "forged"
        assert len(evidence.root["entries"]) == 2
        assert evidence.root["seal"]["sig"] == "deadbeef"


class TestSharedReferenceDiagnostics:
    def test_protected_field_with_shared_value(self) -> None:
        seal = {"alg": "sha256", "sig": "deadbeef"}
        data = dumps({"seal": seal, "backup_seal": seal}, value_sharing=True)
        with pytest.raises(SharedReferenceError, match=r"critical field \$\.seal"):
            loads_evidence(data, protected_paths=[("seal",)])
        # Without the declaration the same log decodes fine
        assert loads_evidence(data).shared_paths == (("backup_seal",),)

    def test_protected_field_below_shared_ancestor(self) -> None:
        data = make_sealed_log()
        with pytest.raises(SharedReferenceError, match=r"critical field \$\.entries"):
            loads_evidence(data, protected_paths=[("entries",)])

    def test_protected_field_above_shared_value(self) -> None:
        data = make_sealed_log()
        with pytest.raises(SharedReferenceError, match=r"\$\.entries\[0\]"):
            loads_evidence(data, protected_paths=[("entries", 0)])

    def test_diagnostic_lists_shared_locations(self) -> None:
        seal = {"alg": "sha256"}
        data = dumps({"seal": seal, "backup_seal": seal}, value_sharing=True)
        with pytest.raises(SharedReferenceError, match=r"\$\.backup_seal") as excinfo:
            loads_evidence(data, protected_paths=[("seal",)])
        assert isinstance(excinfo.value, CBORDecodeError)

    def test_unrelated_shared_values_do_not_trigger_protection(self) -> None:
        evidence = loads_evidence(make_sealed_log(), protected_paths=[("seal",)])
        assert evidence.root["seal"]["sig"] == "deadbeef"

    def test_forbid_shared_keys(self) -> None:
        key = ("a", "b")
        data = dumps({key: 1, "alias": key}, value_sharing=True)
        with pytest.raises(SharedReferenceError, match="map key"):
            loads_evidence(data, forbid_shared_keys=True)
        # Allowed by default
        assert loads_evidence(data).shared_paths
