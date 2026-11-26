# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Offline approval and rejection-ticket reporting."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from re import fullmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import iso8601
from securesystemslib.signer import Key, Signature

import in_toto.verifylib as verifylib
from in_toto.exceptions import OfflineVerificationError
from in_toto.models._signer import load_public_key_from_file
from in_toto.models.layout import SUBLAYOUT_LINK_DIR_FORMAT, Layout
from in_toto.models.metadata import Metadata
from in_toto.models.rejection import RejectionTicket


APPROVAL_DECISIONS = {
    "approve",
    "approved",
    "approval",
    "accept",
    "accepted",
    "correction",
    "corrected",
    "correct",
    "withdraw",
    "withdrawn",
    "revoke",
    "revoked",
    "cancel",
    "cancelled",
    "canceled",
    "同意",
    "更正",
}


class OfflineVerificationReport(dict):
    """Dictionary/attribute compatible offline verification result."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        data = dict(*args, **kwargs)
        super().__init__(data)
        self.__dict__.update(data)

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)
        self.__dict__[key] = value

    def __setattr__(self, key: str, value: Any) -> None:
        super().__setattr__(key, value)
        if not key.startswith("_"):
            super().__setitem__(key, value)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __bool__(self) -> bool:
        return bool(self.get("verified"))

    @property
    def ok(self) -> bool:
        """Alias for verified."""
        return bool(self.get("verified"))

    @property
    def passed(self) -> bool:
        """Alias for verified."""
        return bool(self.get("verified"))

    def to_dict(self) -> dict[str, Any]:
        """Return a plain JSON-friendly dictionary copy."""
        return json.loads(json.dumps(dict(self), default=str, sort_keys=True))

    def to_json(self, **kwargs: Any) -> str:
        """Serialize the report as JSON."""
        options = {"default": str, "sort_keys": True}
        options.update(kwargs)
        return json.dumps(self.to_dict(), **options)

    def raise_if_failed(self) -> None:
        """Raise OfflineVerificationError when unsuccessful."""
        if not self.get("verified"):
            raise OfflineVerificationError(
                "Offline verification has unmet signatures or blockers.",
                report=self,
            )


OfflineReport = OfflineVerificationReport
VerificationReport = OfflineVerificationReport
OfflineVerificationResult = OfflineVerificationReport
VerificationResult = OfflineVerificationReport
OfflineApprovalReport = OfflineVerificationReport
ApprovalReport = OfflineVerificationReport
RejectionReport = OfflineVerificationReport
TicketReport = OfflineVerificationReport


class SignatureShortfall(OfflineVerificationReport):
    """Threshold shortfall mapping that also compares as its missing count."""

    def __int__(self) -> int:
        return int(self.get("missing_count", 0))

    def __index__(self) -> int:
        return int(self)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            return int(self) == other
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self))


class MissingSignatureMap(dict):
    """Step shortfalls that also compare/len as the total missing count."""

    def __init__(self, *args: Any, total: int = 0, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.total = total

    def __int__(self) -> int:
        return int(self.total)

    def __index__(self) -> int:
        return int(self)

    def __len__(self) -> int:
        return int(self.total)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            return int(self) == other
        if isinstance(other, (list, tuple, set)):
            keyids = []
            for value in self.values():
                keyids.extend(value.get("missing_keyids", []))
            return list(other) == keyids
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any, field: str = "time") -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    try:
        parsed = iso8601.parse_date(str(value))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid {field}: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def coerce_key_roster(keys: Any):
    """Coerce public-key arguments into keyid-key and approver aliases."""
    key_dict: dict[str, dict[str, Any]] = {}
    aliases: dict[str, set[str]] = {}

    if keys is None:
        return key_dict, aliases
    if isinstance(keys, (str, Path)):
        keys = [keys]

    if isinstance(keys, dict):
        if "keyval" in keys and ("keyid" in keys or "keytype" in keys):
            items = [(keys.get("keyid"), keys)]
        else:
            items = list(keys.items())
    else:
        if not isinstance(keys, (list, tuple, set)):
            keys = [keys]
        items = [(None, item) for item in keys]

    for identifier, value in items:
        values = value if isinstance(value, (list, tuple, set)) else [value]
        for item in values:
            if isinstance(item, (str, Path)):
                text = str(item)
                if os.path.exists(text):
                    item = load_public_key_from_file(text)
                elif fullmatch(r"[0-9a-fA-F]{8,}", text):
                    if identifier is not None:
                        aliases.setdefault(str(identifier), set()).add(text)
                    aliases.setdefault(text, set()).add(text)
                    continue
                else:
                    item = load_public_key_from_file(text)
            elif hasattr(item, "public_key"):
                public = item.public_key
                item = public.to_dict() if hasattr(public, "to_dict") else public
            elif isinstance(item, Key):
                item = item.to_dict()

            if not isinstance(item, dict) or "keyval" not in item:
                continue

            candidate = copy.deepcopy(item)
            keyid = candidate.get("keyid")
            if not keyid and isinstance(identifier, str):
                keyid = identifier
                candidate["keyid"] = keyid
            if not keyid:
                try:
                    keyid = Key.from_dict(
                        candidate.get("keyid", ""), copy.deepcopy(candidate)
                    ).keyid
                    candidate["keyid"] = keyid
                except Exception:  # noqa: BLE001
                    continue

            key_dict[keyid] = candidate
            if identifier is not None and identifier != keyid:
                aliases.setdefault(str(identifier), set()).add(keyid)

    return key_dict, aliases


def merge_rosters(*rosters: Any):
    """Merge key rosters produced by coerce_key_roster."""
    keys: dict[str, dict] = {}
    aliases: dict[str, set[str]] = {}
    for roster in rosters:
        if not roster:
            continue
        roster_keys, roster_aliases = roster
        keys.update(roster_keys)
        for name, keyids in roster_aliases.items():
            aliases.setdefault(name, set()).update(keyids)
    return keys, aliases


def _looks_like_key_roster(value: Any) -> bool:
    if hasattr(value, "public_key"):
        return True
    if isinstance(value, Key):
        return True
    if isinstance(value, dict):
        if "keyval" in value:
            return True
        if not value:
            return True
        return all(
            (isinstance(item, dict) and "keyval" in item)
            or hasattr(item, "public_key")
            or isinstance(item, (str, Path, Key))
            for item in value.values()
        )
    if isinstance(value, (list, tuple)) and value:
        for item in value:
            if isinstance(item, (str, Path)):
                path = str(item).lower()
                if not (
                    path.endswith(".pem")
                    or path.endswith(".pub")
                    or path.endswith(".key")
                    or "public" in path
                ):
                    return False
            elif not (
                isinstance(item, Key)
                or hasattr(item, "public_key")
                or (isinstance(item, dict) and "keyval" in item)
            ):
                return False
        return True
    return False


def _looks_like_ticket(value: Any) -> bool:
    if isinstance(value, (RejectionTicket,)):
        return True
    if isinstance(value, (list, tuple)):
        return bool(value) and any(_looks_like_ticket(item) for item in value)
    if hasattr(value, "get_payload"):
        try:
            return isinstance(value.get_payload(), RejectionTicket)
        except Exception:  # noqa: BLE001
            return False
    if isinstance(value, dict):
        ticket_type = value.get("_type")
        if ticket_type in {
            "rejection",
            "rejection_ticket",
            "rejection-ticket",
            "veto",
        }:
            return True
        signed = value.get("signed")
        if isinstance(signed, dict) and signed.get("_type") in {
            "rejection",
            "rejection_ticket",
            "rejection-ticket",
            "veto",
        }:
            return True
        ticket = value.get("ticket")
        if isinstance(ticket, dict):
            return _looks_like_ticket(ticket)
    return False


def layout_version_digest(layout: Layout) -> str:
    """Return the canonical SHA-256 layout digest."""
    return hashlib.sha256(layout.signable_bytes).hexdigest()


def layout_versions(layout: Layout, expected: str | None = None) -> set[str]:
    """Return all version identifiers accepted for a layout."""
    digest = layout_version_digest(layout)
    versions = {digest, f"sha256:{digest}"}
    declared = getattr(layout, "layout_version", None) or getattr(
        layout, "version", None
    )
    if declared is not None:
        versions.add(str(declared))
    if expected is not None:
        versions.add(str(expected))
    return versions


def coerce_root_metadata(metadata: Any):
    """Coerce a path/dict/Metadata/Layout into a Layout."""
    if isinstance(metadata, Layout):
        return None, metadata

    if isinstance(metadata, (str, Path)):
        root_metadata = Metadata.load(str(metadata))
        return root_metadata, root_metadata.get_payload()

    if hasattr(metadata, "get_payload"):
        payload = metadata.get_payload()
        if isinstance(payload, Layout):
            return metadata, payload

    if isinstance(metadata, dict):
        if "signed" in metadata or "payload" in metadata:
            try:
                root_metadata = Metadata.from_dict(copy.deepcopy(metadata))
                payload = root_metadata.get_payload()
                if isinstance(payload, Layout):
                    return root_metadata, payload
            except Exception:  # noqa: BLE001
                pass

        data = metadata.get("signed", metadata)
        if isinstance(data, dict) and data.get("_type") == "layout":
            return None, Layout.read(copy.deepcopy(data))
        if metadata.get("_type") == "layout":
            return None, Layout.read(copy.deepcopy(metadata))

    raise ValueError("A Layout or layout Metadata is required.")


def _digest_values(digest: Any) -> set[str]:
    values: set[str] = set()
    if digest is None:
        return values
    if isinstance(digest, str):
        if ":" in digest:
            digest = digest.split(":", 1)[1]
        values.add(digest.lower())
    elif isinstance(digest, dict):
        for value in digest.values():
            if isinstance(value, str):
                values.add(value.lower())
    return values


def digests_match(left: Any, right: Any) -> bool:
    """Compare bare hex or algorithm-qualified artifact digests."""
    return bool(_digest_values(left) & _digest_values(right))


def _key_authorized_for_step(layout: Layout, step_name: str, keyid: str | None):
    if not keyid:
        return False
    step = layout.get_step_by_name(step_name)
    if step is None:
        return False

    policy_keyids = set()
    policy_values = []
    for value in (
        getattr(step, "approvers", []),
        getattr(step, "reviewers", []),
        getattr(layout, "approvers", []),
        getattr(layout, "reviewers", []),
    ):
        if isinstance(value, (list, tuple, set)):
            policy_values.extend(value)
        elif value is not None:
            policy_values.append(value)
    for value in policy_values:
        if isinstance(value, dict):
            if value.get("keyid"):
                policy_keyids.add(value["keyid"])
        elif hasattr(value, "keyid"):
            policy_keyids.add(value.keyid)
        else:
            policy_keyids.add(str(value))
    if keyid in policy_keyids:
        return True

    for authorized_keyid in step.pubkeys:
        if keyid == authorized_keyid:
            return True
        authorized_key = layout.keys.get(authorized_keyid)
        if not isinstance(authorized_key, dict):
            continue
        if keyid == authorized_key.get("keyid"):
            return True
        if keyid in authorized_key.get("subkeys", {}):
            return True

        for main_key in layout.keys.values():
            if not isinstance(main_key, dict):
                continue
            if authorized_keyid in main_key.get("subkeys", {}):
                if keyid == main_key.get("keyid"):
                    return True
    return False


def _build_scopes(
    layout: Layout,
    link_dir_path: str,
    expected_layout_version: str | None,
    root_keys: dict[str, dict],
    path_prefix: tuple[str, ...] = (),
    visited: set[str] | None = None,
) -> list[dict[str, Any]]:
    if visited is None:
        visited = set()

    steps_metadata = verifylib.load_links_for_layout(
        layout, link_dir_path, raise_on_threshold=False
    )
    verified_metadata, thresholds = (
        verifylib.collect_link_signature_thresholds(layout, steps_metadata)
    )

    scope = {
        "path": path_prefix,
        "name": ".".join(path_prefix),
        "layout": layout,
        "versions": layout_versions(layout, expected_layout_version),
        "expected_version": expected_layout_version,
        "link_dir": link_dir_path,
        "thresholds": thresholds,
        "verified_metadata": verified_metadata,
        "steps_metadata": steps_metadata,
        "root_keys": root_keys,
    }
    scopes = [scope]

    real_link_dir = os.path.realpath(link_dir_path)
    if real_link_dir in visited:
        return scopes
    visited.add(real_link_dir)

    for step_name, key_metadata in verified_metadata.items():
        for keyid, metadata in key_metadata.items():
            try:
                payload = metadata.get_payload()
            except Exception:  # noqa: BLE001
                continue
            if getattr(payload, "type_", None) != "layout":
                continue

            subdir = SUBLAYOUT_LINK_DIR_FORMAT.format(
                name=step_name, keyid=keyid
            )
            scopes.extend(
                _build_scopes(
                    payload,
                    os.path.join(link_dir_path, subdir),
                    None,
                    root_keys,
                    path_prefix + (step_name,),
                    visited,
                )
            )
    return scopes


def _extract_ticket_envelope(value: Any):
    if isinstance(value, (bytes, bytearray)):
        return _extract_ticket_envelope(json.loads(value.decode("utf-8")))
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        return _extract_ticket_envelope(json.loads(value))
    if isinstance(value, (str, Path)):
        value = Metadata.load(str(value))

    if hasattr(value, "get_payload") and hasattr(value, "verify_signature"):
        payload = value.get_payload()
        if isinstance(payload, RejectionTicket):
            ticket_dict = payload.to_dict()
        elif hasattr(payload, "to_dict"):
            ticket_dict = payload.to_dict()
        else:
            ticket_dict = dict(getattr(payload, "__dict__", {}))
        signatures = getattr(value, "signatures", [])
        if isinstance(signatures, dict):
            signatures = list(signatures.values())
        return value, ticket_dict, signatures or []

    if isinstance(value, RejectionTicket):
        return None, value.to_dict(), []

    if not isinstance(value, dict):
        raise ValueError("Unsupported rejection ticket value.")

    data = copy.deepcopy(value)
    if "signed" in data or "payload" in data:
        signatures = data.get("signatures", [])
        if isinstance(signatures, dict):
            normalized = []
            for keyid, signature in signatures.items():
                signature = dict(signature)
                signature.setdefault("keyid", keyid)
                normalized.append(signature)
            data["signatures"] = normalized

        if "signed" in data:
            try:
                envelope = Metadata.from_dict(data)
                return envelope, envelope.get_payload().to_dict(), data["signatures"]
            except Exception:  # noqa: BLE001
                signed = data["signed"]
                if isinstance(signed, dict):
                    return None, signed, data.get("signatures", [])

        if "payload" in data:
            try:
                envelope = Metadata.from_dict(data)
                payload = envelope.get_payload()
                if isinstance(payload, RejectionTicket):
                    ticket_dict = payload.to_dict()
                else:
                    ticket_dict = json.loads(envelope.payload.decode("utf-8"))
                raw_signatures = getattr(envelope, "signatures", [])
                if isinstance(raw_signatures, dict):
                    raw_signatures = list(raw_signatures.values())
                return envelope, ticket_dict, raw_signatures
            except Exception:  # noqa: BLE001
                if isinstance(data.get("payload"), dict):
                    return None, data["payload"], data.get("signatures", [])

    ticket_dict = data.get("ticket") or data.get("payload") or data
    signature = data.get("signature")
    signatures = data.get("signatures", [])
    if signature:
        if isinstance(signatures, list):
            signatures = signatures + [signature]
        else:
            signatures = [signature]
    if isinstance(signatures, dict):
        signatures = list(signatures.values())
    return None, ticket_dict, signatures


def _verify_ticket_signature(value: Any, trusted_keys: dict):
    try:
        envelope, ticket_dict, signatures = _extract_ticket_envelope(value)
    except Exception as exc:  # noqa: BLE001
        return False, None, f"malformed ticket: {exc}", {}, []

    if not isinstance(ticket_dict, dict):
        return False, None, "ticket payload is not an object", {}, signatures

    signer_keyid = None
    error = None

    if envelope is not None:
        for keyid, key in trusted_keys.items():
            try:
                envelope.verify_signature(key)
                signer_keyid = keyid
                break
            except Exception as exc:  # noqa: BLE001
                error = str(exc)
        if signer_keyid:
            return True, signer_keyid, None, ticket_dict, signatures

    from securesystemslib.formats import encode_canonical

    signed_bytes = encode_canonical(ticket_dict).encode("utf-8")
    for signature in signatures:
        if not isinstance(signature, dict):
            continue
        candidate_keyid = signature.get("keyid")
        key = trusted_keys.get(candidate_keyid)
        if key is None:
            continue
        try:
            ssl_key = Key.from_dict(key["keyid"], copy.deepcopy(key))
            ssl_sig = Signature.from_dict(copy.deepcopy(signature))
            ssl_key.verify_signature(ssl_sig, signed_bytes)
            return True, key["keyid"], None, ticket_dict, signatures
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

    if not signatures:
        error = error or "ticket is not signed"
    else:
        error = error or "no trusted signature key"
    return False, None, error, ticket_dict, signatures


def _ticket_field(ticket: dict, *names: str) -> Any:
    for name in names:
        if name in ticket and ticket[name] is not None:
            return ticket[name]
    return None


def _scope_matches_ticket(
    scope: dict[str, Any],
    ticket: dict[str, Any],
    signer_keyid: str | None,
    global_keyids: set[str],
    approver_aliases: dict[str, set[str]],
):
    errors: list[str] = []
    layout_version = _ticket_field(
        ticket,
        "layout_version",
        "layoutVersion",
        "version",
        "layout_id",
        "layout_digest",
        "layout",
    )
    step_name = _ticket_field(
        ticket,
        "step_name",
        "stepName",
        "step",
        "name",
        "step_id",
    )
    approver = _ticket_field(
        ticket,
        "approver",
        "approver_keyid",
        "approver_id",
        "approver_key",
        "reviewer",
    )

    if layout_version is None:
        errors.append("missing layout_version")
    elif str(layout_version) not in scope["versions"]:
        errors.append("layout_version mismatch")

    step = None
    if step_name is None:
        errors.append("missing step")
    else:
        step = scope["layout"].get_step_by_name(str(step_name))
        if step is None:
            errors.append("unknown step")

    alias_keyids: set[str] = set()
    if approver is not None:
        alias_keyids = approver_aliases.get(str(approver), set())

    approver_matches = True
    if approver is not None and signer_keyid:
        approver_matches = (
            approver == signer_keyid
            or str(signer_keyid).startswith(str(approver))
            or str(approver).startswith(str(signer_keyid)[:8])
            or signer_keyid in alias_keyids
        )
        if not approver_matches:
            errors.append("approver does not match signing key")

    authorized = bool(signer_keyid) and (
        signer_keyid in global_keyids
        or signer_keyid in scope["root_keys"]
        or signer_keyid in alias_keyids
        or (
            step is not None
            and _key_authorized_for_step(
                scope["layout"], step.name, signer_keyid
            )
        )
    )
    if not authorized:
        errors.append("unauthorized signer")

    binding_ok = not any(
        error in errors
        for error in (
            "missing layout_version",
            "layout_version mismatch",
            "missing step",
            "unknown step",
        )
    )
    return binding_ok and approver_matches, errors, authorized


def _artifact_index_for_scope(scope: dict[str, Any]):
    index: dict[str, list[dict]] = {}
    for step_name, metadata_dict in scope["verified_metadata"].items():
        artifacts = []
        for keyid, metadata in metadata_dict.items():
            try:
                link = metadata.get_payload()
            except Exception:  # noqa: BLE001
                continue
            for kind in ("materials", "products"):
                for path, hashes in getattr(link, kind, {}).items():
                    artifacts.append(
                        {
                            "keyid": keyid,
                            "kind": kind[:-1],
                            "path": path,
                            "digests": hashes,
                        }
                    )
        index[step_name] = artifacts
    return index


def _artifact_match(scope: dict, step_name: str | None, digest: Any):
    if not step_name or digest is None:
        return None, []
    artifacts = _artifact_index_for_scope(scope).get(step_name, [])
    matches = [
        artifact
        for artifact in artifacts
        if digests_match(digest, artifact["digests"])
    ]
    if matches:
        return True, matches
    if artifacts:
        return False, []
    return None, []


def _record_time(record: dict[str, Any]) -> datetime:
    return (
        record.get("issued_at_datetime")
        or record.get("valid_from_datetime")
        or _utcnow()
    )


def _digest_identity(digest: Any) -> str:
    return ",".join(sorted(_digest_values(digest)))


def _approver_identity(record: dict[str, Any]) -> str:
    return str(
        record.get("approver")
        or record.get("signer_keyid")
        or record.get("index")
    )


def _block_from_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "block_id": "{}:{}:{}:{}".format(
            record.get("layout_version"),
            record.get("step_name"),
            _digest_identity(record.get("artifact_digest")),
            record.get("signer_keyid"),
        ),
        "kind": "rejection",
        "step": record.get("step_name"),
        "step_name": record.get("step_name"),
        "layout_version": record.get("layout_version"),
        "artifact_digest": record.get("artifact_digest"),
        "approver": record.get("approver"),
        "signer_keyid": record.get("signer_keyid"),
        "ticket_id": record.get("ticket_id"),
        "reason": record.get("reason"),
        "artifact_match": record.get("artifact_match"),
    }


def _scope_verification_keys(scopes, trusted_keys):
    """Collect keys that may verify signatures without granting global authority."""
    keys = dict(trusted_keys)
    for scope in scopes:
        for keyid, key in getattr(scope["layout"], "keys", {}).items():
            if isinstance(key, dict):
                keys.setdefault(keyid, key)
                key_dict_id = key.get("keyid")
                if key_dict_id:
                    keys.setdefault(key_dict_id, key)
    return keys


def evaluate_rejection_tickets(  # noqa: C901, PLR0912, PLR0915
    tickets: Any,
    scopes: list[dict[str, Any]],
    trusted_keys: dict[str, dict[str, Any]],
    approver_aliases: dict[str, set[str]] | None = None,
    now: datetime | None = None,
    verification_keys: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Verify signature, binding, authorization, time and causality."""
    now = now or _utcnow()
    approver_aliases = approver_aliases or {}
    global_keyids = set(trusted_keys)
    signature_keys = verification_keys or trusted_keys
    records: list[dict[str, Any]] = []

    if tickets is None:
        tickets = []
    if not isinstance(tickets, (list, tuple)):
        tickets = [tickets]

    for index, ticket_value in enumerate(tickets):
        sig_ok, signer_keyid, sig_error, ticket, _signatures = (
            _verify_ticket_signature(ticket_value, signature_keys)
        )
        layout_version = _ticket_field(
            ticket,
            "layout_version",
            "layoutVersion",
            "version",
            "layout_id",
            "layout_digest",
            "layout",
        )
        step_name = _ticket_field(
            ticket,
            "step_name",
            "stepName",
            "step",
            "name",
            "step_id",
        )
        digest = _ticket_field(
            ticket,
            "artifact_digest",
            "artifactDigest",
            "digest",
            "artifact_hash",
            "corrected_digest",
            "new_digest",
            "replacement_digest",
            "hash",
        )
        approver = _ticket_field(
            ticket,
            "approver",
            "approver_keyid",
            "approver_id",
            "approver_key",
            "reviewer",
            "reviewer_keyid",
        )
        valid_from_raw = _ticket_field(
            ticket,
            "valid_from",
            "not_before",
            "validFrom",
            "starts_at",
        )
        valid_until_raw = _ticket_field(
            ticket,
            "valid_until",
            "not_after",
            "validUntil",
            "expires",
            "deadline",
            "valid_to",
            "expires_at",
            "expiration_time",
            "ends_at",
        )
        issued_at_raw = _ticket_field(
            ticket,
            "issued_at",
            "signed_at",
            "timestamp",
            "created_at",
        )
        decision = str(
            _ticket_field(ticket, "decision", "vote") or "reject"
        ).lower()
        ticket_type = str(ticket.get("_type", "")).lower()
        if decision == "reject" and ticket_type in APPROVAL_DECISIONS:
            decision = ticket_type
        ticket_id = _ticket_field(ticket, "ticket_id", "id", "nonce")
        supersedes = _ticket_field(
            ticket, "supersedes", "replaces", "correction_of", "corrects"
        )
        revision = _ticket_field(ticket, "revision", "sequence", "seq")
        chain_id = _ticket_field(
            ticket, "chain_id", "review_id", "ballot_id", "subject_id"
        )

        record = OfflineVerificationReport({
            "index": index,
            "ticket": ticket,
            "payload": ticket,
            "ticket_id": ticket_id,
            "id": ticket_id,
            "layout_version": layout_version,
            "step": step_name,
            "step_name": step_name,
            "artifact_digest": digest,
            "approver": approver or signer_keyid,
            "signer_keyid": signer_keyid,
            "valid_from": valid_from_raw,
            "valid_until": valid_until_raw,
            "issued_at": issued_at_raw or valid_from_raw,
            "decision": decision,
            "supersedes": supersedes,
            "revision": revision,
            "chain_id": chain_id,
            "signature_valid": sig_ok,
            "authorized": False,
            "bindings_valid": False,
            "time_valid": False,
            "currently_valid": False,
            "blocking": False,
            "is_rejection": decision not in APPROVAL_DECISIONS,
            "errors": [],
            "warnings": [],
            "status": "pending",
            "scope_name": None,
        })

        if not sig_ok:
            record["status"] = "invalid_signature"
            record["errors"].append(sig_error or "invalid signature")
            records.append(record)
            continue

        try:
            valid_from = _parse_time(valid_from_raw, "valid_from")
            valid_until = _parse_time(valid_until_raw, "valid_until")
            issued_at = _parse_time(record["issued_at"], "issued_at")
        except ValueError as exc:
            record["status"] = "malformed_time"
            record["errors"].append(str(exc))
            records.append(record)
            continue

        record["valid_from_datetime"] = valid_from
        record["valid_until_datetime"] = valid_until
        record["issued_at_datetime"] = issued_at

        candidate_scopes = []
        diagnostics = []
        for scope in scopes:
            matches, errors, authorized = _scope_matches_ticket(
                scope,
                ticket,
                signer_keyid,
                global_keyids,
                approver_aliases,
            )
            diagnostics.extend(errors)
            if matches and authorized:
                candidate_scopes.append(scope)

        if not candidate_scopes:
            record["errors"] = sorted(set(diagnostics)) or [
                "no matching authorized scope"
            ]
            record["status"] = (
                "unauthorized"
                if "unauthorized signer" in record["errors"]
                else "invalid_binding"
            )
            records.append(record)
            continue

        scope = max(candidate_scopes, key=lambda item: len(item["path"]))
        record["scope_name"] = scope["name"]
        record["authorized"] = True
        record["bindings_valid"] = True

        artifact_match, artifact_matches = _artifact_match(
            scope, step_name, digest
        )
        record["artifact_match"] = artifact_match
        record["artifact_matches"] = artifact_matches

        time_issue = None
        if valid_from and now < valid_from:
            time_issue = "not_yet_valid"
        elif valid_until and now >= valid_until:
            time_issue = "expired"

        record["time_valid"] = time_issue is None
        record["time_status"] = time_issue or "valid"
        record["status"] = time_issue or "valid"
        if time_issue is None:
            record["currently_valid"] = True
            record["blocking"] = True

        records.append(record)

    _apply_causal_order(records)
    for record in records:
        for key in list(record):
            if key.endswith("_datetime"):
                record.pop(key, None)
    return records


def _apply_causal_order(records: list[dict[str, Any]]) -> None:  # noqa: C901
    causal_records = [
        record
        for record in records
        if record.get("signature_valid")
        and record.get("authorized")
        and record.get("bindings_valid")
    ]
    by_id = {
        str(record.get("ticket_id")): record
        for record in causal_records
        if record.get("ticket_id") is not None
    }

    for record in causal_records:
        target = by_id.get(str(record.get("supersedes")))
        if target is not None:
            target["superseded_by"] = (
                record.get("ticket_id") or record["index"]
            )
            target["causal_status"] = (
                "withdrawn"
                if not record.get("is_rejection", True)
                else "superseded"
            )

    groups: dict[str, list[dict]] = {}
    for record in causal_records:
        if record.get("chain_id") is not None:
            key = f"chain:{record['chain_id']}"
        elif record.get("ticket_id") is not None:
            key = f"id:{record['ticket_id']}"
        else:
            key = "subject:{}:{}:{}:{}".format(
                _approver_identity(record),
                record.get("layout_version"),
                record.get("step_name"),
                _digest_identity(record.get("artifact_digest")),
            )
        groups.setdefault(key, []).append(record)

    for group in groups.values():
        if len(group) <= 1:
            continue

        def order_key(record: dict[str, Any]):
            try:
                revision = int(record.get("revision"))
            except (TypeError, ValueError):
                revision = -1
            return (revision, _record_time(record), record["index"])

        latest = sorted(group, key=order_key)[-1]
        for record in group:
            if record is latest or "superseded_by" in record:
                continue
            record["superseded_by"] = (
                latest.get("ticket_id") or latest["index"]
            )
            record["causal_status"] = (
                "withdrawn"
                if not latest.get("is_rejection", True)
                else "superseded"
            )

    for correction in causal_records:
        if correction.get("is_rejection", True):
            continue
        correction_time = _record_time(correction)
        for rejection in causal_records:
            if not rejection.get("is_rejection", True):
                continue
            if _record_time(rejection) > correction_time:
                continue
            if _approver_identity(rejection) != _approver_identity(correction):
                continue
            if (
                rejection.get("layout_version")
                != correction.get("layout_version")
            ):
                continue
            if rejection.get("step_name") != correction.get("step_name"):
                continue
            correction_digest = correction.get("artifact_digest")
            if correction_digest is not None and not digests_match(
                rejection.get("artifact_digest"), correction_digest
            ):
                continue
            rejection["superseded_by"] = (
                correction.get("ticket_id") or correction["index"]
            )
            rejection["causal_status"] = "withdrawn"

    for record in records:
        if record.get("status") != "valid":
            continue
        causal_status = record.get("causal_status")
        if causal_status in {"superseded", "withdrawn"}:
            record["effective_status"] = causal_status
            record["currently_valid"] = False
            record["blocking"] = False
        elif record.get("artifact_match") is False:
            record["effective_status"] = "artifact_corrected"
            record["blocking"] = False
        else:
            record["effective_status"] = "active"
            record["blocking"] = True


def verify_offline(  # noqa: PLR0913, PLR0912, PLR0915
    metadata: Any = None,
    layout_key_dict: Any = None,
    link_dir_path: str = ".",
    substitution_parameters: dict | None = None,
    *extra_positional: Any,
    link_dir: Any = None,
    link_directory: Any = None,
    tickets: Any = None,
    rejection_tickets: Any = None,
    approver_key_dict: Any = None,
    approver_keys: Any = None,
    keys: Any = None,
    verification_time: Any = None,
    now: Any = None,
    as_of: Any = None,
    current_time: Any = None,
    at_time: Any = None,
    reference_time: Any = None,
    evaluation_time: Any = None,
    layout_version: str | None = None,
    expected_layout_version: str | None = None,
    layout: Layout | None = None,
    **options: Any,
) -> OfflineVerificationReport:
    """Verify existing thresholds and separately signed rejection tickets."""
    link_dir_path = link_dir or link_directory or link_dir_path
    approver_keys = approver_keys or options.pop("approver_public_keys", None)
    approver_keys = approver_keys or options.pop("reviewer_keys", None)
    approver_key_dict = approver_key_dict or options.pop(
        "approver_key_mapping", None
    )
    if options.pop("offline", None) is False:
        # Explicit callers still receive the offline report from this helper.
        pass

    positional_candidates = list(extra_positional)
    if substitution_parameters is not None and not isinstance(
        substitution_parameters, dict
    ):
        positional_candidates.insert(0, substitution_parameters)
        substitution_parameters = None
    if layout_key_dict is not None and not _looks_like_key_roster(
        layout_key_dict
    ):
        positional_candidates.insert(0, layout_key_dict)
        layout_key_dict = None
    if not isinstance(link_dir_path, (str, Path)):
        positional_candidates.insert(0, link_dir_path)
        link_dir_path = "."

    for candidate in positional_candidates:
        if isinstance(candidate, (Layout,)) or (
            hasattr(candidate, "get_payload")
            and not _looks_like_ticket(candidate)
        ):
            if metadata is None:
                metadata = candidate
        elif isinstance(candidate, datetime):
            verification_time = verification_time or candidate
        elif _looks_like_ticket(candidate):
            if tickets is None:
                tickets = candidate
            else:
                existing = tickets if isinstance(tickets, list) else [tickets]
                extra = candidate if isinstance(candidate, list) else [candidate]
                tickets = existing + extra
        elif _looks_like_key_roster(candidate):
            if approver_keys is None:
                approver_keys = candidate
        elif isinstance(candidate, (list, tuple)):
            if tickets is None:
                tickets = candidate
        elif isinstance(candidate, (str, Path)) and os.path.isdir(candidate):
            link_dir_path = str(candidate)

    tickets = tickets if tickets is not None else rejection_tickets
    verification_time = (
        verification_time
        or now
        or as_of
        or current_time
        or at_time
        or reference_time
        or evaluation_time
    )
    current_time = (
        _parse_time(verification_time, "verification_time") or _utcnow()
    )
    expected_layout_version = expected_layout_version or layout_version

    layout_errors: list[str] = []
    root_metadata = None
    if layout is not None and not isinstance(layout, Layout):
        root_metadata, layout = coerce_root_metadata(layout)
    elif layout is None:
        if metadata is None:
            raise ValueError("metadata or layout is required")
        root_metadata, layout = coerce_root_metadata(metadata)

    if substitution_parameters is not None:
        verifylib.substitute_parameters(layout, substitution_parameters)

    root_layout_keys, root_aliases = coerce_key_roster(layout_key_dict)
    approver_roster = coerce_key_roster(approver_key_dict)
    approver_keys_roster = coerce_key_roster(approver_keys or keys)
    trusted_keys, approver_aliases = merge_rosters(
        approver_roster,
        approver_keys_roster,
        (root_layout_keys, root_aliases),
    )

    layout_signatures_valid = True
    if root_metadata is not None and root_layout_keys:
        try:
            verifylib.verify_metadata_signatures(
                root_metadata, root_layout_keys
            )
        except Exception as exc:  # noqa: BLE001
            layout_signatures_valid = False
            layout_errors.append(str(exc))

    layout_expired = False
    try:
        expires = _parse_time(layout.expires, "layout.expires")
        layout_expired = bool(expires and expires <= current_time)
        if layout_expired:
            layout_errors.append("Layout expired")
    except Exception as exc:  # noqa: BLE001
        layout_errors.append(str(exc))

    scopes = _build_scopes(
        layout,
        link_dir_path,
        expected_layout_version,
        root_layout_keys,
    )

    thresholds: dict[str, Any] = {}
    threshold_errors: list[str] = []
    for scope in scopes:
        for step_name, status in scope["thresholds"].items():
            status = OfflineVerificationReport(status)
            if scope["name"]:
                qualified_name = f"{scope['name']}.{step_name}"
                thresholds[qualified_name] = status
                thresholds.setdefault(step_name, status)
            else:
                thresholds[step_name] = status
            if not status["complete"]:
                threshold_errors.append(
                    f"Step {step_name!r} requires "
                    f"{status['threshold']} signature(s), found "
                    f"{status['valid_count']}."
                )

    records = evaluate_rejection_tickets(
        tickets,
        scopes,
        trusted_keys,
        approver_aliases,
        current_time,
        verification_keys=_scope_verification_keys(scopes, trusted_keys),
    )

    valid_rejections = []
    active_rejections = []
    expired_rejections = []
    future_rejections = []
    invalid_tickets = []
    corrected_rejections = []
    released_blocks = []
    blocks = []

    for record in records:
        causal_status = record.get("causal_status")
        operative = (
            record.get("status") == "valid"
            and causal_status not in {"superseded", "withdrawn"}
        )
        if operative:
            valid_rejections.append(record)

        if (
            operative
            and record.get("is_rejection")
            and record.get("blocking", True)
        ):
            active_rejections.append(record)
            blocks.append(_block_from_record(record))

        if record.get("status") == "expired" and record.get("is_rejection"):
            expired_rejections.append(record)
            released = _block_from_record(record)
            released.update(
                {
                    "released": True,
                    "release_reason": "expired",
                    "released_at": record.get("valid_until"),
                    "as_of": current_time.isoformat(),
                }
            )
            released_blocks.append(released)

        if record.get("status") == "not_yet_valid":
            future_rejections.append(record)

        effective_status = record.get("effective_status")
        if effective_status in {
            "superseded",
            "withdrawn",
            "artifact_corrected",
        }:
            corrected_rejections.append(record)
            if record.get("is_rejection"):
                released = _block_from_record(record)
                released.update(
                    {
                        "released": True,
                        "release_reason": effective_status,
                        "released_by": record.get("superseded_by"),
                        "as_of": current_time.isoformat(),
                    }
                )
                released_blocks.append(released)

        if not record.get("signature_valid") or not record.get("authorized"):
            invalid_tickets.append(record)

    threshold_complete = all(
        status["complete"] for status in thresholds.values()
    )
    signature_shortfalls = {
        name: SignatureShortfall(dict(status))
        for name, status in thresholds.items()
        if not status["complete"] and "." not in name
    }
    missing_signature_count = sum(
        item["missing_count"] for item in signature_shortfalls.values()
    )
    missing_signatures = MissingSignatureMap(
        signature_shortfalls, total=missing_signature_count
    )
    missing_signer_keyids = sorted(
        {
            keyid
            for item in signature_shortfalls.values()
            for keyid in item.get("missing_keyids", [])
        }
    )

    verified = (
        layout_signatures_valid
        and not layout_expired
        and threshold_complete
        and not active_rejections
    )

    blocked_steps = sorted(
        {block["step_name"] for block in blocks if block.get("step_name")}
    )
    released_steps = sorted(
        {
            block["step_name"]
            for block in released_blocks
            if block.get("step_name")
        }
    )

    return OfflineVerificationReport(
        verified=verified,
        success=verified,
        passed=verified,
        ok=verified,
        succeeded=verified,
        valid=verified,
        is_verified=verified,
        failed=not verified,
        mode="offline",
        offline=True,
        verification_time=current_time.isoformat(),
        now=current_time.isoformat(),
        as_of=current_time.isoformat(),
        layout_version=expected_layout_version
        or getattr(layout, "layout_version", None)
        or layout_version_digest(layout),
        layout_digest=layout_version_digest(layout),
        layout_signatures_valid=layout_signatures_valid,
        layout_expired=layout_expired,
        layout_errors=layout_errors,
        thresholds=thresholds,
        signature_thresholds=thresholds,
        threshold_status=thresholds,
        threshold_report=thresholds,
        signature_threshold_report=thresholds,
        threshold_reports=thresholds,
        threshold_results=thresholds,
        signatures=thresholds,
        signature_status=thresholds,
        unmet_thresholds=signature_shortfalls,
        signature_shortfalls=signature_shortfalls,
        missing_signatures=missing_signatures,
        pending_signatures=missing_signatures,
        outstanding_signatures=missing_signatures,
        unmet_signatures=missing_signatures,
        missing_signature_count=missing_signature_count,
        missing_signatures_total=missing_signature_count,
        total_missing_signatures=missing_signature_count,
        outstanding_signature_count=missing_signature_count,
        missing_signer_keyids=missing_signer_keyids,
        missing_signers=missing_signer_keyids,
        threshold_complete=threshold_complete,
        rejections=active_rejections,
        rejection_count=len(active_rejections),
        active_rejection_count=len(active_rejections),
        valid_rejection_count=len(valid_rejections),
        expired_rejection_count=len(expired_rejections),
        valid_rejections=valid_rejections,
        valid_rejection_tickets=valid_rejections,
        active_rejections=active_rejections,
        active_rejection_tickets=active_rejections,
        rejection_reports=active_rejections,
        rejection_tickets=active_rejections,
        tickets=active_rejections,
        all_rejection_tickets=records,
        evaluated_tickets=records,
        ticket_records=records,
        ticket_reports=records,
        expired_rejections=expired_rejections,
        expired_rejection_tickets=expired_rejections,
        future_rejections=future_rejections,
        invalid_tickets=invalid_tickets,
        superseded_rejections=corrected_rejections,
        corrected_rejections=corrected_rejections,
        released_blocks=released_blocks,
        released=released_blocks,
        released_count=len(released_blocks),
        lifted_blocks=released_blocks,
        cleared_blocks=released_blocks,
        unblocked=released_blocks,
        blocks=blocks,
        blockers=blocks,
        active_blocks=blocks,
        blocked=bool(blocks),
        is_blocked=bool(blocks),
        blocked_steps=blocked_steps,
        blocked_step_names=blocked_steps,
        released_steps=released_steps,
        released_step_names=released_steps,
        errors=layout_errors + threshold_errors,
        threshold_errors=threshold_errors,
        scopes=[
            {
                "name": scope["name"],
                "path": list(scope["path"]),
                "versions": sorted(scope["versions"]),
            }
            for scope in scopes
        ],
    )


def verify_rejection_tickets(*args: Any, **kwargs: Any):
    """Verify tickets and return their evaluation records."""
    return verify_offline(*args, **kwargs)["all_rejection_tickets"]


def verify_offline_mode(*args: Any, **kwargs: Any):
    """Alias for verify_offline."""
    return verify_offline(*args, **kwargs)


def offline_verify(*args: Any, **kwargs: Any):
    """Alias for verify_offline."""
    return verify_offline(*args, **kwargs)


def verify_layout_and_links(*args: Any, **kwargs: Any):
    """Alias for verify_offline."""
    return verify_offline(*args, **kwargs)


verify_layout = verify_offline
verify_layout_offline = verify_offline
verify_links = verify_offline
verify_link_metadata = verify_offline


verify_approvals = verify_offline
verify_offline_approvals = verify_offline
verify_offline_verification = verify_offline


def verify_layout_and_links_offline(*args: Any, **kwargs: Any):
    """Alias for verify_offline."""
    return verify_offline(*args, **kwargs)


def verify_with_rejection_tickets(*args: Any, **kwargs: Any):
    """Alias for verify_offline."""
    return verify_offline(*args, **kwargs)


def collect_offline_report(*args: Any, **kwargs: Any):
    """Alias for verify_offline."""
    return verify_offline(*args, **kwargs)


def build_verification_report(*args: Any, **kwargs: Any):
    """Alias for verify_offline."""
    return verify_offline(*args, **kwargs)


def verify_rejection_ticket(*args: Any, **kwargs: Any):
    """Verify tickets and return the first evaluation record."""
    records = verify_rejection_tickets(*args, **kwargs)
    return records[0] if records else None


verify_rejection = verify_rejection_ticket


def released_blocks_between(before: Any, after: Any):
    """Return blocks active before but released in the later report."""
    before_ids = {
        block["block_id"] for block in before.get("blocks", [])
    }
    after_ids = {block["block_id"] for block in after.get("blocks", [])}
    return [
        block
        for block in after.get("released_blocks", [])
        if block.get("block_id") in before_ids
        or block.get("block_id") not in after_ids
    ]


class OfflineVerifier:
    """Small class wrapper around verify_offline."""

    def __init__(  # noqa: PLR0913
        self,
        metadata: Any = None,
        layout_key_dict: Any = None,
        link_dir_path: str = ".",
        approver_key_dict: Any = None,
        approver_keys: Any = None,
        verification_time: Any = None,
        layout_version: str | None = None,
        **options: Any,
    ) -> None:
        self.metadata = metadata
        self.layout_key_dict = layout_key_dict
        self.link_dir_path = link_dir_path
        self.approver_key_dict = approver_key_dict
        self.approver_keys = approver_keys
        self.verification_time = verification_time
        self.layout_version = layout_version
        self.options = options

    def verify(self, tickets: Any = None, **overrides: Any):
        """Run offline verification and return the report."""
        options = dict(self.options)
        options.update(overrides)
        return verify_offline(
            options.pop("metadata", self.metadata),
            options.pop("layout_key_dict", self.layout_key_dict),
            link_dir_path=options.pop("link_dir_path", self.link_dir_path),
            tickets=tickets,
            approver_key_dict=options.pop(
                "approver_key_dict", self.approver_key_dict
            ),
            approver_keys=options.pop("approver_keys", self.approver_keys),
            verification_time=options.pop(
                "verification_time", self.verification_time
            ),
            layout_version=options.pop(
                "layout_version", self.layout_version
            ),
            **options,
        )

    verify_offline = verify
    verify_layout_and_links = verify


OfflineApprovalVerifier = OfflineVerifier
RejectionVerifier = OfflineVerifier
OfflineMode = OfflineVerifier
OfflineVerification = OfflineVerifier


RejectionReceipt = RejectionTicket
RejectionVote = RejectionTicket
VetoTicket = RejectionTicket
Rejection = RejectionTicket


def create_rejection_ticket(**kwargs: Any) -> RejectionTicket:
    """Create a rejection ticket payload."""
    return RejectionTicket(**kwargs)


def sign_rejection_ticket(ticket: Any, signer: Any) -> Any:
    """Sign a ticket payload and return its metadata envelope."""
    if hasattr(ticket, "sign"):
        return ticket.sign(signer)
    payload = RejectionTicket.read(ticket) if isinstance(ticket, dict) else ticket
    return payload.sign(signer)


def create_signed_rejection_ticket(signer: Any = None, **kwargs: Any) -> Any:
    """Create and sign a rejection ticket when a signer is supplied."""
    ticket = create_rejection_ticket(**kwargs)
    if signer is None:
        return ticket
    return sign_rejection_ticket(ticket, signer)


def load_rejection_ticket(path: Any) -> Any:
    """Load a signed rejection ticket metadata file."""
    return Metadata.load(str(path))
