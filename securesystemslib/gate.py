"""Policy-based release gate built on DSSE envelope verification.

The release gate takes a batch of DSSE envelopes (see
:mod:`securesystemslib.dsse`) and a versionable :class:`ReleasePolicy`, and
decides whether an artifact may be released.  Cryptographic verification uses
the same PAE and :meth:`securesystemslib.signer.Key.verify_signature` primitives
as :meth:`securesystemslib.dsse.Envelope.verify`; the raw payload is never
re-serialized or mutated before verification.

The gate evaluates a fixed, ordered pipeline so that a failed release always
points at the specific check that blocked it:

1. ``envelope`` -- every item must deserialize as a DSSE envelope.
2. ``signature`` -- every envelope must carry a signature that verifies under
   a key registered in the policy keyring.
3. ``payload_type`` -- the envelope's ``payloadType`` must be one the policy
   expects.
4. ``subject`` -- an in-toto style statement must name the expected artifact.
5. ``role`` -- the verified signer must be allowed to issue the predicate and
   the configured thresholds and separation-of-duties rules must be met.

Evidence selection is content based: the order of the input envelopes does not
matter, duplicate reports and repeated envelopes are deduplicated, multiple
keys registered to one principal collapse into that principal, and attestations
that are cryptographically valid but not applicable to the release are reported
as findings instead of silently counting as evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from securesystemslib import exceptions
from securesystemslib.dsse import Envelope
from securesystemslib.gate_exceptions import GateInputError, PolicyError
from securesystemslib.signer import Key

logger = logging.getLogger(__name__)

#: Policy schema version understood by this module.
GATE_POLICY_SCHEMA_VERSION = 1

#: DSSE payload type of in-toto style attestations.
IN_TOTO_PAYLOAD_TYPE = "https://in-toto.io/Statement/v1"

#: The ordered gate identifiers, evaluated in this order.
GATE_ORDER = ("envelope", "signature", "payload_type", "subject", "role")


class GateStatus(str, Enum):  # noqa: UP042
    """Outcome of a single gate evaluation."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    WARN = "warn"


@dataclass
class GateFinding:
    """A single diagnostic item emitted by a gate.

    Attributes:
        gate: Name of the gate that produced the finding.
        status: Finding severity; only ``fail`` blocks the release.
        message: Human readable explanation.
        envelope_index: Index of the offending input envelope, or ``None`` for
            policy-level findings.
        keyid: Key id the finding relates to, if applicable.
        role: Predicate/role name the finding relates to, if applicable.
    """

    gate: str
    status: GateStatus
    message: str
    envelope_index: int | None = None
    keyid: str | None = None
    role: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Returns the JSON-serializable representation of the finding."""

        return {
            "gate": self.gate,
            "status": self.status.value,
            "message": self.message,
            "envelope_index": self.envelope_index,
            "keyid": self.keyid,
            "role": self.role,
        }


@dataclass(frozen=True)
class RoleRule:
    """Policy requirements for one predicate type.

    Attributes:
        predicate_type: in-toto ``predicateType`` this rule applies to.
        allowed_keyids: Key ids permitted to sign this predicate.
        threshold: Number of distinct principals that must attest.
        separation_from: Predicate types that must be attested by different
            principals (approval independence).
    """

    predicate_type: str
    allowed_keyids: frozenset[str]
    threshold: int
    separation_from: frozenset[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RoleRule:
        """Creates a role rule from its JSON/dict representation."""

        predicate_type = data["predicate_type"]
        allowed_keyids = frozenset(data["allowed_keyids"])
        threshold = data["threshold"]
        separation_from = frozenset(data.get("separation_from", ()))

        if not predicate_type or not isinstance(predicate_type, str):
            raise PolicyError(f"Invalid predicate_type in rule: {data!r}")
        if not allowed_keyids:
            raise PolicyError(
                f"Rule for {predicate_type!r} must allow at least one key"
            )
        if not isinstance(threshold, int) or threshold < 1:
            raise PolicyError(
                f"Rule for {predicate_type!r} has invalid threshold {threshold!r}"
            )
        if threshold > len(allowed_keyids):
            raise PolicyError(
                f"Threshold {threshold} for {predicate_type!r} exceeds the"
                f" {len(allowed_keyids)} allowed keys"
            )

        return cls(predicate_type, allowed_keyids, threshold, separation_from)


@dataclass
class ReleasePolicy:
    """Versionable policy consumed by :class:`ReleaseGate`.

    Attributes:
        schema_version: Policy schema version; must match
            :data:`GATE_POLICY_SCHEMA_VERSION`.
        policy_id: Stable identifier of the policy.
        policy_version: Free-form, monotonically trackable version string.
        expected_payload_types: DSSE ``payloadType`` values the gate accepts.
        expected_subjects: Subject name/digest pairs the artifact must match.
        keyring: Public keys trusted for verification, keyed by keyid.
        role_rules: Predicate rules keyed by predicate type.
        principals: Principal id mapped to the set of registered keyids.
        subject_match: ``"exact"`` requires the full subject set to match;
            ``"contains"`` only requires every expected subject to be present.
    """

    schema_version: int
    policy_id: str
    policy_version: str
    expected_payload_types: frozenset[str]
    expected_subjects: tuple[dict[str, str], ...]
    keyring: dict[str, Key]
    role_rules: dict[str, RoleRule]
    principals: dict[str, frozenset[str]]
    subject_match: str = "exact"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReleasePolicy:  # noqa: PLR0912
        """Creates a policy from its JSON/dict representation.

        Raises:
            PolicyError: If the policy is malformed or uses an unsupported
                schema version.
        """

        schema_version = data.get("schema_version")
        if schema_version != GATE_POLICY_SCHEMA_VERSION:
            raise PolicyError(
                f"Unsupported policy schema_version {schema_version!r},"
                f" expected {GATE_POLICY_SCHEMA_VERSION}"
            )

        policy_id = data.get("policy_id")
        policy_version = data.get("policy_version")
        if not isinstance(policy_id, str) or not policy_id:
            raise PolicyError("Policy requires a non-empty 'policy_id'")
        if not isinstance(policy_version, str) or not policy_version:
            raise PolicyError("Policy requires a non-empty 'policy_version'")

        payload_types = data.get("expected_payload_types")
        if not isinstance(payload_types, list) or not payload_types:
            raise PolicyError("'expected_payload_types' must be a non-empty list")
        expected_payload_types = frozenset(payload_types)

        subjects = data.get("expected_subjects")
        if not isinstance(subjects, list) or not subjects:
            raise PolicyError("'expected_subjects' must be a non-empty list")
        expected_subjects = tuple(_validate_subject(entry) for entry in subjects)

        keyring_data = data.get("keyring", {})
        if not isinstance(keyring_data, dict) or not keyring_data:
            raise PolicyError("'keyring' must be a non-empty object of key dicts")
        try:
            keyring = {
                keyid: Key.from_dict(keyid, key_dict)
                for keyid, key_dict in keyring_data.items()
            }
        except (KeyError, TypeError, ValueError) as error:
            raise PolicyError(f"Invalid key in keyring: {error}") from error

        rules_data = data.get("roles", [])
        if not isinstance(rules_data, list) or not rules_data:
            raise PolicyError("'roles' must be a non-empty list of role rules")
        role_rules: dict[str, RoleRule] = {}
        for rule_data in rules_data:
            rule = RoleRule.from_dict(rule_data)
            if rule.predicate_type in role_rules:
                raise PolicyError(f"Duplicate role rule for {rule.predicate_type!r}")
            unknown = rule.allowed_keyids - keyring.keys()
            if unknown:
                raise PolicyError(
                    f"Role {rule.predicate_type!r} allows keys absent from the"
                    f" keyring: {sorted(unknown)}"
                )
            role_rules[rule.predicate_type] = rule

        principals = _load_principals(data.get("principals", {}), keyring)

        subject_match = data.get("subject_match", "exact")
        if subject_match not in ("exact", "contains"):
            raise PolicyError(
                f"Invalid subject_match {subject_match!r},"
                " expected 'exact' or 'contains'"
            )

        # Cross-validate separation-of-duties references.
        for rule in role_rules.values():
            unknown_roles = rule.separation_from - role_rules.keys()
            if unknown_roles:
                raise PolicyError(
                    f"Role {rule.predicate_type!r} declares separation from"
                    f" unknown roles: {sorted(unknown_roles)}"
                )

        return cls(
            schema_version,
            policy_id,
            policy_version,
            expected_payload_types,
            expected_subjects,
            keyring,
            role_rules,
            principals,
            subject_match,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> ReleasePolicy:
        """Loads a policy from a JSON file."""

        try:
            with open(path, "rb") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            raise PolicyError(f"Cannot load policy from {path}: {error}") from error
        return cls.from_dict(data)

    def principal_of(self, keyid: str) -> str:
        """Returns the principal that registered ``keyid``.

        Keys without an explicit principal mapping are treated as principals of
        their own, identified by keyid.
        """

        for principal, keyids in self.principals.items():
            if keyid in keyids:
                return principal
        return keyid

    def to_dict(self) -> dict[str, Any]:
        """Returns the JSON-serializable representation of the policy."""

        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "expected_payload_types": sorted(self.expected_payload_types),
            "expected_subjects": list(self.expected_subjects),
            "keyring": {keyid: key.to_dict() for keyid, key in self.keyring.items()},
            "roles": [
                {
                    "predicate_type": rule.predicate_type,
                    "allowed_keyids": sorted(rule.allowed_keyids),
                    "threshold": rule.threshold,
                    "separation_from": sorted(rule.separation_from),
                }
                for rule in self.role_rules.values()
            ],
            "principals": {
                principal: sorted(keyids)
                for principal, keyids in self.principals.items()
            },
            "subject_match": self.subject_match,
        }


def _validate_subject(entry: Any) -> dict[str, str]:
    if not isinstance(entry, dict) or "name" not in entry:
        raise PolicyError(f"Invalid subject entry: {entry!r}")
    name = entry["name"]
    digest = entry.get("digest", {})
    if not isinstance(name, str) or not name:
        raise PolicyError(f"Subject requires a non-empty name: {entry!r}")
    if not isinstance(digest, dict) or not all(
        isinstance(algorithm, str) and isinstance(value, str)
        for algorithm, value in digest.items()
    ):
        raise PolicyError(f"Subject digest must map strings to strings: {entry!r}")
    return {"name": name, "digest": dict(digest)}


def _load_principals(data: Any, keyring: dict[str, Key]) -> dict[str, frozenset[str]]:
    if not isinstance(data, dict):
        raise PolicyError("'principals' must be an object")

    seen: dict[str, str] = {}
    principals: dict[str, frozenset[str]] = {}
    for principal, keyids in data.items():
        if not isinstance(principal, str) or not principal:
            raise PolicyError(f"Invalid principal id: {principal!r}")
        if not isinstance(keyids, list) or not keyids:
            raise PolicyError(
                f"Principal {principal!r} must register a non-empty key list"
            )
        keyid_set = frozenset(keyids)
        for keyid in keyid_set:
            if keyid not in keyring:
                raise PolicyError(
                    f"Principal {principal!r} registers unknown key {keyid!r}"
                )
            if keyid in seen:
                raise PolicyError(
                    f"Key {keyid!r} registered to multiple principals:"
                    f" {seen[keyid]!r} and {principal!r}"
                )
            seen[keyid] = principal
        principals[principal] = keyid_set
    return principals


@dataclass(frozen=True)
class Evidence:
    """One applicable, verified attestation selected by the gate.

    Evidence is keyed by the envelope payload and the verifying key id, so that
    repeated or reordered input items never count more than once.
    """

    envelope_index: int
    keyid: str
    principal: str
    predicate_type: str
    subject: dict[str, Any]
    payload_digest: str


@dataclass(frozen=True)
class GateResult:
    """Outcome of a release gate evaluation.

    Attributes:
        allowed: ``True`` exactly when no gate produced a failure finding.
        blocking_gates: Ordered, de-duplicated names of gates that blocked.
        findings: Every finding emitted during the run, in emission order.
        evidence: Applicable attestations selected as evidence.
        policy_id: Id of the policy that produced the decision.
        policy_version: Version of the policy that produced the decision.
    """

    allowed: bool
    blocking_gates: tuple[str, ...]
    findings: tuple[GateFinding, ...]
    evidence: tuple[Evidence, ...]
    policy_id: str
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        """Returns the JSON-serializable representation of the result."""

        return {
            "allowed": self.allowed,
            "blocking_gates": list(self.blocking_gates),
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": [
                {
                    "envelope_index": item.envelope_index,
                    "keyid": item.keyid,
                    "principal": item.principal,
                    "predicate_type": item.predicate_type,
                    "subject": item.subject,
                    "payload_digest": item.payload_digest,
                }
                for item in self.evidence
            ],
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
        }


class ReleaseGate:
    """Evaluates a batch of DSSE envelopes against a release policy."""

    def __init__(self, policy: ReleasePolicy) -> None:
        self.policy = policy
        self.findings: list[GateFinding] = []
        self.evidence: list[Evidence] = []
        self._seen_evidence: set[tuple[str, str, str]] = set()

    # gate pipeline ---------------------------------------------------------

    @classmethod
    def from_policy_file(cls, path: str | Path) -> ReleaseGate:
        """Creates a gate from a versionable policy file on disk."""

        policy = ReleasePolicy.from_file(path)
        return cls(policy)

    def evaluate(self, envelopes: list[dict[str, Any] | Envelope]) -> GateResult:
        """Runs all gates in order and returns the release decision.

        Arguments:
            envelopes: DSSE envelopes in dict or :class:`Envelope` form.
                Order is irrelevant; the gate selects evidence by content.

        Returns:
            A :class:`GateResult` with the final decision and a finding per
            blocking gate (plus warnings for valid but inapplicable input).
        """

        self.findings = []
        self.evidence = []
        self._seen_evidence = set()

        parsed = self._gate_envelope(envelopes)
        verified = self._gate_signature(parsed)
        typed = self._gate_payload_type(verified)
        scoped = self._gate_subject(typed)
        self._gate_role(scoped)

        for gate_name in GATE_ORDER:
            if not any(finding.gate == gate_name for finding in self.findings):
                self.findings.append(
                    GateFinding(gate_name, GateStatus.PASS, f"{gate_name} gate passed")
                )

        blocking = [
            finding for finding in self.findings if finding.status == GateStatus.FAIL
        ]
        return GateResult(
            allowed=not blocking,
            blocking_gates=tuple(dict.fromkeys(finding.gate for finding in blocking)),
            findings=tuple(self.findings),
            evidence=tuple(self.evidence),
            policy_id=self.policy.policy_id,
            policy_version=self.policy.policy_version,
        )

    def _gate_envelope(
        self, envelopes: list[dict[str, Any] | Envelope]
    ) -> list[tuple[int, Envelope]]:
        """Gate 1: every input item must parse as a DSSE envelope."""

        if not envelopes:
            raise GateInputError("Release gate requires at least one envelope")

        parsed: list[tuple[int, Envelope]] = []
        for index, item in enumerate(envelopes):
            if isinstance(item, Envelope):
                parsed.append((index, item))
                continue
            try:
                # Envelope.from_dict mutates its argument; copy so callers
                # can evaluate the same input batch more than once.
                envelope = Envelope.from_dict(copy.deepcopy(item))
            except (KeyError, TypeError, ValueError) as error:
                self.findings.append(
                    GateFinding(
                        "envelope",
                        GateStatus.FAIL,
                        f"Malformed DSSE envelope: {error}",
                        envelope_index=index,
                    )
                )
                continue
            parsed.append((index, envelope))
        return parsed

    def _gate_signature(
        self, parsed: list[tuple[int, Envelope]]
    ) -> list[tuple[int, Envelope, frozenset[str]]]:
        """Gate 2: at least one signature verifies under a registered key."""

        verified: list[tuple[int, Envelope, frozenset[str]]] = []
        for index, envelope in parsed:
            accepted = self._verify_envelope(index, envelope)
            if accepted:
                verified.append((index, envelope, accepted))
            else:
                self.findings.append(
                    GateFinding(
                        "signature",
                        GateStatus.FAIL,
                        "No signature verifies under a key registered in the"
                        " policy keyring",
                        envelope_index=index,
                    )
                )
        return verified

    def _verify_envelope(self, index: int, envelope: Envelope) -> frozenset[str]:
        """Verifies each signature against the keyring, mirroring
        ``Envelope.verify`` but recording every unknown/invalid signature."""

        accepted: set[str] = set()
        pae = envelope.pae()
        for signature in envelope.signatures.values():
            key = self.policy.keyring.get(signature.keyid)
            if key is None:
                self.findings.append(
                    GateFinding(
                        "signature",
                        GateStatus.WARN,
                        f"Signature keyid {signature.keyid!r} is not registered"
                        " in the policy keyring",
                        envelope_index=index,
                        keyid=signature.keyid,
                    )
                )
                continue
            try:
                key.verify_signature(signature, pae)
            except exceptions.UnverifiedSignatureError as error:
                self.findings.append(
                    GateFinding(
                        "signature",
                        GateStatus.FAIL,
                        f"Signature from {signature.keyid!r} does not verify: {error}",
                        envelope_index=index,
                        keyid=signature.keyid,
                    )
                )
                continue
            accepted.add(signature.keyid)
        return frozenset(accepted)

    def _gate_payload_type(
        self,
        checked: list[tuple[int, Envelope, frozenset[str]]],
    ) -> list[tuple[int, Envelope, frozenset[str]]]:
        """Gate 3: payloadType must be one the policy expects.

        A valid envelope with an unexpected type is inapplicable evidence: it
        is reported as a warning and excluded, not counted as an attestation.
        """

        typed: list[tuple[int, Envelope, frozenset[str]]] = []
        for index, envelope, verified in checked:
            if envelope.payload_type not in self.policy.expected_payload_types:
                self.findings.append(
                    GateFinding(
                        "payload_type",
                        GateStatus.WARN,
                        f"Unexpected payloadType {envelope.payload_type!r};"
                        " attestation is not applicable to this release",
                        envelope_index=index,
                    )
                )
                continue
            typed.append((index, envelope, verified))
        return typed

    def _gate_subject(
        self,
        typed: list[tuple[int, Envelope, frozenset[str]]],
    ) -> list[tuple[int, Envelope, frozenset[str], str]]:
        """Gate 4: the statement subject must name the expected artifact."""

        scoped: list[tuple[int, Envelope, frozenset[str], str]] = []
        for index, envelope, verified in typed:
            try:
                statement = json.loads(envelope.payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                self.findings.append(
                    GateFinding(
                        "subject",
                        GateStatus.FAIL,
                        f"Payload is not a UTF-8 JSON statement: {error}",
                        envelope_index=index,
                    )
                )
                continue

            if not isinstance(statement, dict):
                self.findings.append(
                    GateFinding(
                        "subject",
                        GateStatus.FAIL,
                        "Statement payload must be a JSON object",
                        envelope_index=index,
                    )
                )
                continue

            subjects = statement.get("subject")
            if not isinstance(subjects, list) or not subjects:
                self.findings.append(
                    GateFinding(
                        "subject",
                        GateStatus.FAIL,
                        "Statement does not name any subject",
                        envelope_index=index,
                    )
                )
                continue

            parsed_subjects: list[dict[str, Any]] = []
            subject_error = False
            for entry in subjects:
                try:
                    parsed_subjects.append(_validate_subject(entry))
                except PolicyError as error:
                    self.findings.append(
                        GateFinding(
                            "subject",
                            GateStatus.FAIL,
                            str(error),
                            envelope_index=index,
                        )
                    )
                    subject_error = True
            if subject_error:
                continue

            actual = tuple(parsed_subjects)
            matched = self._matches_expected_subject(actual)
            if not matched:
                self.findings.append(
                    GateFinding(
                        "subject",
                        GateStatus.WARN,
                        "Valid attestation does not apply to the expected"
                        " release artifact; it cannot be selected as evidence",
                        envelope_index=index,
                    )
                )
                continue

            predicate_type = statement.get("predicateType")
            if not isinstance(predicate_type, str) or not predicate_type:
                self.findings.append(
                    GateFinding(
                        "subject",
                        GateStatus.FAIL,
                        "Statement is missing a string 'predicateType'",
                        envelope_index=index,
                    )
                )
                continue
            scoped.append((index, envelope, verified, predicate_type))
        return scoped

    def _matches_expected_subject(self, actual: tuple[dict[str, Any], ...]) -> bool:
        expected = self.policy.expected_subjects
        if self.policy.subject_match == "exact":
            return len(actual) == len(expected) and all(
                item in actual for item in expected
            )
        return all(item in actual for item in expected)

    def _gate_role(
        self,
        scoped: list[tuple[int, Envelope, frozenset[str], str]],
    ) -> None:
        """Gate 5: signer role rules, thresholds and approval independence."""

        for index, envelope, verified_keyids, predicate_type in scoped:
            statement = json.loads(envelope.payload.decode("utf-8"))
            rule = self.policy.role_rules.get(predicate_type)
            if rule is None:
                self.findings.append(
                    GateFinding(
                        "role",
                        GateStatus.WARN,
                        f"Predicate {predicate_type!r} is not governed by the"
                        " policy; attestation is valid but not applicable",
                        envelope_index=index,
                        role=predicate_type,
                    )
                )
                continue

            payload_digest = hashlib.sha256(envelope.payload).hexdigest()
            allowed_verifiers = verified_keyids & rule.allowed_keyids
            for keyid in sorted(verified_keyids - rule.allowed_keyids):
                self.findings.append(
                    GateFinding(
                        "role",
                        GateStatus.FAIL,
                        f"Signer key {keyid!r} is not allowed to issue"
                        f" {predicate_type!r}",
                        envelope_index=index,
                        keyid=keyid,
                        role=predicate_type,
                    )
                )

            for keyid in sorted(allowed_verifiers):
                identity = (payload_digest, envelope.payload_type, keyid)
                if identity in self._seen_evidence:
                    self.findings.append(
                        GateFinding(
                            "role",
                            GateStatus.WARN,
                            "Duplicate report ignored: same payload and key"
                            f" {keyid!r} already selected as evidence",
                            envelope_index=index,
                            keyid=keyid,
                            role=predicate_type,
                        )
                    )
                    continue
                self._seen_evidence.add(identity)
                self.evidence.append(
                    Evidence(
                        envelope_index=index,
                        keyid=keyid,
                        principal=self.policy.principal_of(keyid),
                        predicate_type=predicate_type,
                        subject=statement.get("subject", []),
                        payload_digest=payload_digest,
                    )
                )

        self._evaluate_role_rules()

    def _evaluate_role_rules(self) -> None:
        """Applies thresholds and separation-of-duties to selected evidence."""

        principals_by_role: dict[str, set[str]] = {}
        for evidence in self.evidence:
            principals_by_role.setdefault(evidence.predicate_type, set()).add(
                evidence.principal
            )

        for predicate_type, rule in self.policy.role_rules.items():
            principals = principals_by_role.get(predicate_type, set())
            if len(principals) < rule.threshold:
                self.findings.append(
                    GateFinding(
                        "role",
                        GateStatus.FAIL,
                        f"Role {predicate_type!r} requires"
                        f" {rule.threshold} distinct principal(s), found"
                        f" {len(principals)}: {sorted(principals)}",
                        role=predicate_type,
                    )
                )
                continue
            self.findings.append(
                GateFinding(
                    "role",
                    GateStatus.PASS,
                    f"Role {predicate_type!r} threshold met by {sorted(principals)}",
                    role=predicate_type,
                )
            )
            for other in rule.separation_from:
                overlap = principals & principals_by_role.get(other, set())
                if overlap:
                    self.findings.append(
                        GateFinding(
                            "role",
                            GateStatus.FAIL,
                            f"Approval independence violated between"
                            f" {predicate_type!r} and {other!r}: shared"
                            f" principal(s) {sorted(overlap)}",
                            role=predicate_type,
                        )
                    )
