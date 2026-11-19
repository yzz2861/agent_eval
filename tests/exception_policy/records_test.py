import datetime as dt
import json
from datetime import timezone

import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.exception_policy import (
    DecisionState,
    ExceptionRecord,
    RuleVersion,
    Scope,
    SecretIdentity,
    build_record,
    evidence_fingerprint,
)

UTC = timezone.utc


def _identity():
    return SecretIdentity.from_hashed_secret(
        "AWS", PotentialSecret.hash_secret("top-secret"),
    )


def _record(**overrides):
    now = dt.datetime(2026, 1, 1, tzinfo=UTC)
    params = dict(
        secret_identity=_identity(),
        scope=Scope.from_string("acme", "config"),
        rule=RuleVersion.parse("AWS", "1.0.0"),
        decided_by="alice",
        rationale="false positive per SEC-1",
        created_at=now,
        expires_at=now + dt.timedelta(days=10),
        evidence_references=("SEC-1",),
        decision_id="d1",
    )
    params.update(overrides)
    return build_record(**params)


def test_evidence_is_fingerprinted_not_plaintext():
    record = _record()
    assert record.evidence_fingerprints
    assert all(fp.startswith("sha256:") for fp in record.evidence_fingerprints)
    serialized = json.dumps(record.to_dict())
    assert "top-secret" not in serialized
    # approval evidence references are stored only as fingerprints
    assert record.evidence_fingerprints[0] not in ("SEC-1",)


def test_evidence_fingerprint_is_stable():
    assert evidence_fingerprint("SEC-1") == evidence_fingerprint("SEC-1")
    assert evidence_fingerprint("SEC-1") != evidence_fingerprint("SEC-2")


def test_record_is_immutable():
    record = _record()
    with pytest.raises(Exception):
        record.rationale = "changed"  # type: ignore[misc]


def test_serialization_round_trip_preserves_fields():
    record = _record()
    restored = ExceptionRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    assert restored == record


def test_requires_rationale_and_actor():
    with pytest.raises(ValueError):
        _record(rationale="")
    with pytest.raises(ValueError):
        _record(decided_by="")


def test_rejects_naive_datetimes():
    naive = dt.datetime(2026, 1, 1)
    with pytest.raises(ValueError):
        _record(created_at=naive)


def test_effective_window_is_half_open(now=None):
    now = dt.datetime(2026, 1, 1, tzinfo=UTC)
    expiry = now + dt.timedelta(days=1)
    record = _record(created_at=now, expires_at=expiry)
    assert record.is_active_at(now)
    assert record.is_active_at(expiry - dt.timedelta(seconds=1))
    assert not record.is_active_at(expiry)


def test_rejects_effective_after_expiry():
    now = dt.datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError):
        _record(
            created_at=now,
            effective_at=now + dt.timedelta(days=5),
            expires_at=now + dt.timedelta(days=1),
        )


def test_revocation_record_state():
    record = _record(state=DecisionState.REVOKED)
    assert not record.is_approved
