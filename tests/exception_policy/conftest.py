import datetime as dt
from datetime import timezone

import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.exception_policy import (
    ExceptionStore,
    Finding,
    RuleVersion,
    Scope,
    SecretIdentity,
    build_record,
    finding_from_potential_secret,
)

UTC = timezone.utc
PROJECT = "acme"
RULE_NAME = "AWSKeyDetector"
RULE_VERSION = "1.4.0"
SECRET_VALUE = "super-secret-value"


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def expiry(now: dt.datetime) -> dt.datetime:
    return now + dt.timedelta(days=30)


@pytest.fixture
def identity() -> SecretIdentity:
    return SecretIdentity.from_hashed_secret(
        RULE_NAME,
        PotentialSecret.hash_secret(SECRET_VALUE),
    )


@pytest.fixture
def rule() -> RuleVersion:
    return RuleVersion.parse(RULE_NAME, RULE_VERSION)


@pytest.fixture
def approved_scope() -> Scope:
    return Scope.from_string(PROJECT, "config")


def make_finding(
    secret_value: str = SECRET_VALUE,
    path: str = "config/app.yaml",
    project: str = PROJECT,
    rule_version: str = RULE_VERSION,
    secret_type: str = RULE_NAME,
) -> Finding:
    secret = PotentialSecret(
        type=secret_type,
        filename=path,
        secret=secret_value,
        line_number=7,
    )
    return finding_from_potential_secret(secret, project, rule_version)


def make_approved_record(
    identity: SecretIdentity,
    scope: Scope,
    rule: RuleVersion,
    now: dt.datetime,
    expiry: dt.datetime,
    **kwargs: object,
):
    kwargs.setdefault("decided_by", "alice")
    kwargs.setdefault("rationale", "documented false positive in SEC-9")
    kwargs.setdefault("evidence_references", ("https://tickets/SEC-9",))
    kwargs.setdefault("decision_id", "decision-1")
    return build_record(
        secret_identity=identity,
        scope=scope,
        rule=rule,
        created_at=now,
        expires_at=expiry,
        **kwargs,
    )


@pytest.fixture
def approved_record(identity, approved_scope, rule, now, expiry):
    return make_approved_record(identity, approved_scope, rule, now, expiry)


@pytest.fixture
def store(approved_record) -> ExceptionStore:
    return ExceptionStore([approved_record])
