"""
Derivation certificates for plugin executions.

A certificate records the registry evidence a plugin actually read, the rule
version that turned that evidence into a conclusion, and the key decisions in
between. It deliberately contains identities and digests instead of raw hive
contents, so it can be shared without handing over the whole hive.

The verifier re-reads every recorded evidence item from a hive, checks the rule
identity, then replays the plugin with an audit observer that rejects reads the
certificate does not cover. A run that needs new evidence, sees different
bytes, or uses a different rule cannot be reported as verified.
"""

import hashlib
import importlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Union

from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException
from regipy.utils import normalize_registry_path

CERTIFICATE_SCHEMA = "regipy-derivation-certificate/v1"

STATUS_VERIFIED = "verified"
STATUS_RULE_CHANGED = "rule_changed"
STATUS_INPUT_SUBSTITUTED = "input_substituted"
STATUS_UNRECORDED_READ = "unrecorded_read"
STATUS_CONCLUSION_MISMATCH = "conclusion_mismatch"
STATUS_INVALID_CERTIFICATE = "invalid_certificate"
STATUS_UNSUPPORTED_BACKEND = "unsupported_backend"


class CertificateError(Exception):
    """Raised when a certificate cannot be generated or is structurally invalid."""


@dataclass
class Evidence:
    """A single key or value identity read while deriving a conclusion."""

    id: str
    kind: str
    path: str
    exists: bool
    name: Optional[str] = None
    value_type: Optional[str] = None
    size: Optional[int] = None
    digest: Optional[str] = None
    digest_scope: Optional[str] = None
    last_modified: Optional[int] = None
    subkey_count: Optional[int] = None
    values_count: Optional[int] = None
    is_corrupted: bool = False


@dataclass
class VerificationIssue:
    """One reason a certificate did not verify."""

    category: str
    code: str
    message: str
    evidence_id: Optional[str] = None


@dataclass
class VerificationResult:
    """Outcome of independently verifying a certificate against a hive."""

    verified: bool
    status: str
    issues: list[dict[str, Any]] = field(default_factory=list)
    evidence_checked: int = 0
    unrecorded_reads: list[dict[str, Any]] = field(default_factory=list)
    conclusion_sha256: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def key_evidence_id(path: str) -> str:
    """Stable identity for a key read (registry paths are case-insensitive)."""
    return "key:" + normalize_registry_path(path).casefold()


def value_evidence_id(path: str, name: str) -> str:
    """Stable identity for a value read (value names are case-insensitive)."""
    return key_evidence_id(path).replace("key:", "value:", 1) + "::" + str(name).casefold()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _digest_bytes(value: Union[bytes, bytearray, None]) -> str:
    return hashlib.sha256(bytes(value or b"")).hexdigest()


def _entries_count(entries: Any) -> int:
    if isinstance(entries, dict):
        return len(entries)
    if isinstance(entries, list):
        return len(entries)
    return 0


class CertificateRecorder:
    """
    Read observer used while generating or replaying a plugin execution.

    In ``record`` mode it collects evidence. In ``verify`` mode it additionally
    flags every key/value read that is not in the certificate's evidence set.
    """

    def __init__(
        self,
        mode: str = "record",
        allowed_evidence: Optional[set[str]] = None,
    ) -> None:
        self.mode = mode
        self.allowed_evidence = allowed_evidence or set()
        self.evidence: dict[str, Evidence] = {}
        self.decisions: list[dict[str, Any]] = []
        self.unrecorded_reads: list[dict[str, Any]] = []

    def _check_allowed(self, kind: str, evidence_id: str) -> None:
        if self.mode == "verify" and evidence_id not in self.allowed_evidence:
            self.unrecorded_reads.append({"kind": kind, "evidence_id": evidence_id})

    def on_key_read(self, path, exists, key=None) -> None:
        normalized_path = normalize_registry_path(path)
        evidence_id = key_evidence_id(normalized_path)
        self._check_allowed("key", evidence_id)
        if evidence_id in self.evidence:
            return

        evidence = Evidence(
            id=evidence_id,
            kind="key",
            path=normalized_path,
            exists=bool(exists),
        )
        if key is not None:
            evidence.last_modified = int(key.header.last_modified)
            evidence.subkey_count = int(key.subkey_count)
            evidence.values_count = int(key.values_count)
            evidence.digest_scope = "key_metadata"
            evidence.digest = _digest(
                {
                    "path": normalized_path.casefold(),
                    "last_modified": evidence.last_modified,
                    "subkey_count": evidence.subkey_count,
                    "values_count": evidence.values_count,
                }
            )
        self.evidence[evidence_id] = evidence

    def on_value_read(self, path, name, value_type, raw_value, size=None, is_corrupted=False) -> None:
        normalized_path = normalize_registry_path(path)
        evidence_id = value_evidence_id(normalized_path, name)
        self._check_allowed("value", evidence_id)
        if evidence_id in self.evidence:
            return

        self.evidence[evidence_id] = Evidence(
            id=evidence_id,
            kind="value",
            path=normalized_path,
            exists=True,
            name=str(name),
            value_type=str(value_type),
            size=size,
            digest=_digest_bytes(raw_value),
            digest_scope="value_data",
            is_corrupted=bool(is_corrupted),
        )

    def record_decision(
        self,
        step: str,
        outcome: Any,
        evidence_ids: Optional[list[str]] = None,
    ) -> None:
        """Record a key judgement step and the evidence it depends on."""
        evidence_ids = list(evidence_ids or [])
        for evidence_id in evidence_ids:
            self._check_allowed("decision", evidence_id)
        self.decisions.append(
            {
                "step": step,
                "outcome": outcome,
                "evidence": evidence_ids,
            }
        )

    def build_certificate(self, plugin) -> dict[str, Any]:
        rule = _current_rule(plugin)
        evidence = [asdict(item) for item in sorted(self.evidence.values(), key=lambda item: item.id)]
        evidence_ids = {item["id"] for item in evidence}

        for decision in self.decisions:
            missing = [evidence_id for evidence_id in decision["evidence"] if evidence_id not in evidence_ids]
            if missing:
                raise CertificateError(
                    f"Decision {decision['step']!r} depends on evidence that was not recorded: {sorted(missing)}"
                )

        return {
            "schema": CERTIFICATE_SCHEMA,
            "plugin": {
                "name": plugin.NAME,
                "class_name": type(plugin).__name__,
                "module": type(plugin).__module__,
                **rule,
            },
            "execution": {
                "as_json": bool(plugin.as_json),
                "trim_values": bool(plugin.trim_values),
            },
            "hive": {
                "hive_type": plugin.registry_hive.hive_type,
                "partial_hive_path": plugin.registry_hive.partial_hive_path,
            },
            "evidence": evidence,
            "decisions": self.decisions,
            "decisions_sha256": _digest(self.decisions),
            "conclusion": {
                "entries_count": _entries_count(plugin.entries),
                "sha256": _digest(plugin.entries),
            },
            "summary": {
                "keys": sum(1 for item in evidence if item["kind"] == "key"),
                "values": sum(1 for item in evidence if item["kind"] == "value"),
                "decisions": len(self.decisions),
            },
        }


def _current_rule(plugin) -> dict[str, Any]:
    version = getattr(plugin, "CERTIFICATE_RULE_VERSION", None) or "0"
    rule_method = getattr(plugin, "certificate_rule", None)
    rule = rule_method() if callable(rule_method) else None
    if rule is None:
        rule = {"kind": "unversioned_plugin", "name": plugin.NAME}
    return {
        "rule_version": str(version),
        "rule": rule,
        "rule_sha256": _digest(rule),
    }


def _install_observer(hive, observer):
    setter = getattr(hive, "set_read_observer", None)
    if setter is None:
        raise CertificateError(
            "This registry backend does not support derivation certificates. "
            "Use the default Python backend (regipy.registry.RegistryHive)."
        )
    previous = getattr(hive, "_read_observer", None)
    setter(observer)
    return previous


def _restore_observer(hive, previous) -> None:
    setter = getattr(hive, "set_read_observer", None)
    if setter is not None:
        setter(previous)


def run_plugin_with_certificate(plugin) -> dict[str, Any]:
    """
    Run an already-instantiated plugin and return a derivation certificate.

    The plugin's default interface is unchanged: this only installs an observer
    on the hive for the duration of ``plugin.run()``.
    """
    recorder = CertificateRecorder(mode="record")
    previous_observer = _install_observer(plugin.registry_hive, recorder)
    previous_recorder = getattr(plugin, "certificate_recorder", None)
    plugin.certificate_recorder = recorder
    try:
        plugin.run()
    finally:
        plugin.certificate_recorder = previous_recorder
        _restore_observer(plugin.registry_hive, previous_observer)
    return recorder.build_certificate(plugin)


def _resolve_plugin_class(certificate: dict[str, Any]):
    plugin_meta = certificate.get("plugin") or {}
    module_name = plugin_meta.get("module")
    class_name = plugin_meta.get("class_name")
    if not module_name or not class_name:
        raise CertificateError("Certificate is missing plugin module/class metadata")
    module = importlib.import_module(module_name)
    return getattr(module, class_name)


def _read_evidence(hive, evidence_items: list[dict[str, Any]]) -> dict[str, Evidence]:
    """
    Re-read certificate evidence through the same observer used for recording.

    This keeps the digest definition identical on both sides and avoids a
    verifier-only decoding path.
    """
    recorder = CertificateRecorder(mode="record")
    previous_observer = _install_observer(hive, recorder)
    paths_with_values = {item.get("path") for item in evidence_items if item.get("kind") == "value" and item.get("path")}
    paths = sorted({item["path"] for item in evidence_items if item.get("path")})
    try:
        for path in paths:
            try:
                key = hive.get_key(path)
            except RegistryKeyNotFoundException:
                continue
            if path in paths_with_values:
                try:
                    list(key.iter_values(as_json=True, trim_values=False))
                except RegistryParsingException:
                    continue
    finally:
        _restore_observer(hive, previous_observer)
    return recorder.evidence


def _issue(category: str, code: str, message: str, evidence_id: Optional[str] = None) -> VerificationIssue:
    return VerificationIssue(category=category, code=code, message=message, evidence_id=evidence_id)


def _compare_evidence(
    recorded: list[dict[str, Any]],
    observed: dict[str, Evidence],
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []
    in_certificate = {item["id"] for item in recorded}

    for item in recorded:
        evidence_id = item["id"]
        current = observed.get(evidence_id)
        if current is None:
            issues.append(
                _issue(
                    STATUS_INPUT_SUBSTITUTED,
                    "evidence_missing",
                    f"Recorded evidence {evidence_id!r} is no longer present in the hive",
                    evidence_id,
                )
            )
            continue

        if item.get("exists", True) != current.exists:
            code = "evidence_missing" if item.get("exists", True) else "evidence_added"
            issues.append(
                _issue(
                    STATUS_INPUT_SUBSTITUTED,
                    code,
                    f"Evidence {evidence_id!r} changed existence (certificate={item.get('exists')}, now={current.exists})",
                    evidence_id,
                )
            )
            continue

        if item.get("exists", True) and item.get("digest") != current.digest:
            issues.append(
                _issue(
                    STATUS_INPUT_SUBSTITUTED,
                    "evidence_modified",
                    f"Evidence {evidence_id!r} has different bytes than the certificate recorded",
                    evidence_id,
                )
            )

    for evidence_id, current in observed.items():
        if evidence_id not in in_certificate and current.exists:
            issues.append(
                _issue(
                    STATUS_INPUT_SUBSTITUTED,
                    "evidence_added",
                    f"Evidence {evidence_id!r} exists now but was not present in the certificate",
                    evidence_id,
                )
            )

    return issues


def _status_for(issues: list[VerificationIssue]) -> str:
    categories = {issue.category for issue in issues}
    if STATUS_RULE_CHANGED in categories:
        return STATUS_RULE_CHANGED
    if STATUS_INPUT_SUBSTITUTED in categories:
        return STATUS_INPUT_SUBSTITUTED
    if STATUS_UNRECORDED_READ in categories:
        return STATUS_UNRECORDED_READ
    if STATUS_CONCLUSION_MISMATCH in categories:
        return STATUS_CONCLUSION_MISMATCH
    return STATUS_VERIFIED


def verify_certificate(
    certificate: dict[str, Any],
    registry_hive,
    plugin_class=None,
) -> VerificationResult:
    """
    Verify a derivation certificate against a hive.

    Steps are deliberately separate so callers can tell a rule change from an
    input substitution:

    1. validate the certificate and its rule identity;
    2. re-read every recorded key/value and compare original-byte digests;
    3. replay the plugin under an audit observer; any unrecorded read fails;
    4. compare the rebuilt conclusion and decision trace.
    """
    issues: list[VerificationIssue] = []

    if not isinstance(certificate, dict) or certificate.get("schema") != CERTIFICATE_SCHEMA:
        return VerificationResult(
            verified=False,
            status=STATUS_INVALID_CERTIFICATE,
            issues=[
                _issue(
                    STATUS_INVALID_CERTIFICATE,
                    "bad_schema",
                    f"Expected certificate schema {CERTIFICATE_SCHEMA!r}",
                ).__dict__
            ],
        )

    try:
        resolved_plugin_class = plugin_class or _resolve_plugin_class(certificate)
    except (CertificateError, ImportError, AttributeError) as ex:
        return VerificationResult(
            verified=False,
            status=STATUS_INVALID_CERTIFICATE,
            issues=[
                _issue(
                    STATUS_INVALID_CERTIFICATE,
                    "plugin_unavailable",
                    f"Could not resolve the plugin that produced the certificate: {ex}",
                ).__dict__
            ],
        )

    try:
        _install_observer(registry_hive, None)
    except CertificateError as ex:
        return VerificationResult(
            verified=False,
            status=STATUS_UNSUPPORTED_BACKEND,
            issues=[
                _issue(
                    STATUS_UNSUPPORTED_BACKEND,
                    "observer_unsupported",
                    str(ex),
                ).__dict__
            ],
        )

    execution = certificate.get("execution") or {}
    plugin = resolved_plugin_class(
        registry_hive,
        as_json=execution.get("as_json", True),
        trim_values=execution.get("trim_values", False),
    )

    current_rule = _current_rule(plugin)
    recorded_plugin = certificate.get("plugin") or {}
    if recorded_plugin.get("rule_version") != current_rule["rule_version"]:
        issues.append(
            _issue(
                STATUS_RULE_CHANGED,
                "rule_version_changed",
                "Plugin rule version changed since the certificate was issued "
                f"({recorded_plugin.get('rule_version')!r} -> {current_rule['rule_version']!r})",
            )
        )
    if recorded_plugin.get("rule_sha256") != current_rule["rule_sha256"]:
        issues.append(
            _issue(
                STATUS_RULE_CHANGED,
                "rule_content_changed",
                "Plugin rule content changed since the certificate was issued",
            )
        )

    recorded_evidence = certificate.get("evidence") or []
    observed_evidence = _read_evidence(registry_hive, recorded_evidence)
    issues.extend(_compare_evidence(recorded_evidence, observed_evidence))

    conclusion_sha256: Optional[str] = None
    unrecorded_reads: list[dict[str, Any]] = []
    rule_changed = any(issue.category == STATUS_RULE_CHANGED for issue in issues)

    if not rule_changed:
        allowed_evidence = {item["id"] for item in recorded_evidence}
        audit = CertificateRecorder(mode="verify", allowed_evidence=allowed_evidence)
        previous_observer = _install_observer(registry_hive, audit)
        previous_recorder = getattr(plugin, "certificate_recorder", None)
        plugin.certificate_recorder = audit
        replay_failed = None
        try:
            plugin.run()
        except Exception as ex:
            # A changed input can make the plugin itself fail. That is still a
            # verification failure, not a verifier crash.
            replay_failed = ex
        finally:
            plugin.certificate_recorder = previous_recorder
            _restore_observer(registry_hive, previous_observer)

        if replay_failed is not None:
            issues.append(
                _issue(
                    STATUS_CONCLUSION_MISMATCH,
                    "replay_failed",
                    f"Plugin replay failed against the current evidence: {replay_failed}",
                )
            )
        else:
            conclusion_sha256 = _digest(plugin.entries)
            recorded_conclusion = certificate.get("conclusion") or {}
            if conclusion_sha256 != recorded_conclusion.get("sha256"):
                issues.append(
                    _issue(
                        STATUS_CONCLUSION_MISMATCH,
                        "conclusion_changed",
                        "Rebuilt plugin conclusion does not match the certificate",
                    )
                )

            if _digest(audit.decisions) != certificate.get("decisions_sha256"):
                issues.append(
                    _issue(
                        STATUS_CONCLUSION_MISMATCH,
                        "decision_trace_changed",
                        "Rebuilt decision trace does not match the certificate",
                    )
                )

        unrecorded_reads = audit.unrecorded_reads
        for read in unrecorded_reads:
            issues.append(
                _issue(
                    STATUS_UNRECORDED_READ,
                    "read_not_in_certificate",
                    f"Plugin replayed a read that is not covered by the certificate: {read['evidence_id']}",
                    read["evidence_id"],
                )
            )

    status = _status_for(issues)
    return VerificationResult(
        verified=status == STATUS_VERIFIED,
        status=status,
        issues=[issue.__dict__ for issue in issues],
        evidence_checked=len(recorded_evidence),
        unrecorded_reads=unrecorded_reads,
        conclusion_sha256=conclusion_sha256,
    )
