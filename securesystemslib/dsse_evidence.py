"""Offline verification evidence for DSSE envelopes.

The evidence document is deliberately self-describing: it records the exact
pre-authentication encoding (PAE), the public key material and algorithm used
for each accepted signature, and the artifact digest that the verification
input refers to.  Re-verification never infers an algorithm from current
defaults: the recorded key type and scheme are used as-is.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, TypeVar, cast

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64dec, b64enc
from securesystemslib.signer import GPGKey, Key, Signature, SigstoreKey, SSlibKey

if TYPE_CHECKING:
    from securesystemslib.dsse import Envelope

EvidenceError = exceptions.EvidenceError
EvidenceFormatError = exceptions.EvidenceFormatError


EVIDENCE_VERSION = "1"
EVIDENCE_KIND = "securesystemslib.dsse.verification-evidence"
REPORT_VERSION = "1"
REPORT_KIND = "securesystemslib.dsse.verification-report"
PAE_RULE = "DSSEv1-PAE"
PAE_DESCRIPTION = "DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>"

STATUS_VERIFIED = "verified"
STATUS_REJECTED = "rejected"
STATUS_UNVERIFIABLE = "unverifiable"

_BACKEND_ALIASES = {
    "cryptography": "pyca/cryptography",
    "pyca-cryptography": "pyca/cryptography",
    "pyca/cryptography": "pyca/cryptography",
    "gpg": "gnupg",
    "gnupg": "gnupg",
    "sigstore": "sigstore",
}

_PRIVATE_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
)

_T = TypeVar("_T")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: bytes) -> dict[str, str]:
    return {"sha256": _sha256(value)}


def _json_copy(value: _T) -> _T:
    return copy.deepcopy(value)


def _assert_no_private_material(value: Any, path: str = "$") -> None:
    if isinstance(value, str):
        upper = value.upper()
        for marker in _PRIVATE_MARKERS:
            if marker in upper:
                raise EvidenceError(f"private key material found at {path}")
    elif isinstance(value, Mapping):
        for name, child in value.items():
            lowered = str(name).lower()
            if lowered in {
                "private",
                "private_key",
                "privatekey",
                "private_key_pem",
                "secret",
            }:
                raise EvidenceError(f"private field {name!r} found at {path}")
            _assert_no_private_material(child, f"{path}.{name}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _assert_no_private_material(child, f"{path}[{index}]")


def _read_bytes(value: Any) -> tuple[bytes, str | None]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), None
    if isinstance(value, (str, os.PathLike)):
        path = Path(value)
        if path.exists():
            return path.read_bytes(), path.name
        if isinstance(value, str):
            return value.encode("utf-8"), None
        raise ValueError(f"artifact path does not exist: {value}")
    if hasattr(value, "read"):
        data = value.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        return bytes(data), getattr(value, "name", None)
    raise TypeError(f"unsupported artifact value: {type(value)}")


def _load_json(source: Any) -> dict[str, Any]:
    if isinstance(source, Mapping):
        return _json_copy(dict(source))
    if isinstance(source, (bytes, bytearray, memoryview)):
        text = bytes(source).decode("utf-8")
    elif isinstance(source, (str, os.PathLike)):
        if isinstance(source, str) and source.lstrip().startswith("{"):
            text = source
        else:
            text = Path(source).read_text(encoding="utf-8")
    elif hasattr(source, "read"):
        text = source.read()
        if isinstance(text, bytes):
            text = text.decode("utf-8")
    else:
        raise TypeError(f"unsupported evidence source: {type(source)}")

    try:
        value = json.loads(text)
    except (TypeError, ValueError) as e:
        raise EvidenceFormatError("evidence is not valid JSON") from e
    if not isinstance(value, dict):
        raise EvidenceFormatError("evidence must be a JSON object")
    return value


def _key_document(key: Key) -> dict[str, Any]:
    document = {"keyid": key.keyid, **key.to_dict()}
    _assert_no_private_material(document, "$.key")
    return document


def _key_material_digest(keytype: str, scheme: str, keyval: Mapping[str, Any]) -> str:
    material = {
        "keytype": keytype,
        "scheme": scheme,
        "keyval": dict(keyval),
    }
    return f"sha256:{_sha256(_canonical_json(material))}"


def _keyval_digest(keyval: Mapping[str, Any]) -> str:
    return f"sha256:{_sha256(_canonical_json(dict(keyval)))}"


def _spki_digest(keytype: str, keyval: Mapping[str, Any]) -> str | None:
    public = keyval.get("public")
    if not isinstance(public, str):
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )

        if keytype == "ed25519":
            crypto_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public))
        else:
            crypto_key = load_pem_public_key(public.encode("utf-8"))
        spki = crypto_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return f"sha256:{_sha256(spki)}"
    except Exception:
        return None


def _material_spki(value: Any) -> str | None:
    try:
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )

        if isinstance(value, str):
            data = value.encode("utf-8")
        else:
            data = bytes(value)
        public_key = load_pem_public_key(data)
        spki = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return f"sha256:{_sha256(spki)}"
    except Exception:
        return _certificate_spki(value)


def _backend_name(key: Key) -> str:
    if isinstance(key, SSlibKey):
        return "pyca/cryptography"
    if isinstance(key, GPGKey):
        return "gnupg"
    if isinstance(key, SigstoreKey):
        return "sigstore"
    module = type(key).__module__
    return f"{module}.{type(key).__qualname__}"


def _normalize_backend(value: str | None) -> str | None:
    if value is None:
        return None
    lowered = value.lower()
    return _BACKEND_ALIASES.get(lowered, lowered)


def _iter_values(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    return set(value)


def _backend_document(key: Key) -> dict[str, Any]:
    name = _backend_name(key)
    available = True
    if isinstance(key, SSlibKey) and name == "pyca/cryptography":
        from securesystemslib.signer._key import CRYPTO_IMPORT_ERROR  # noqa: PLC0415

        available = CRYPTO_IMPORT_ERROR is None or key.scheme == "ed25519"
    return {"name": name, "available": available}


def _signature_document(signature: Signature) -> dict[str, Any]:
    document = signature.to_dict()
    document["sig"] = b64enc(bytes.fromhex(document["sig"]))
    return document


def _artifact_document(
    envelope: Envelope,
    artifact: Any,
    artifact_name: str | None,
) -> tuple[dict[str, Any], bytes]:
    if artifact is None:
        data = envelope.payload
        name = artifact_name
        binding = "envelope-payload"
    else:
        data, read_name = _read_bytes(artifact)
        name = artifact_name or read_name
        binding = (
            "envelope-payload"
            if data == envelope.payload
            else "caller-provided-artifact"
        )

    document: dict[str, Any] = {
        "binding": binding,
        "size": len(data),
        "digest": _digest(data),
        "digestAlgorithm": "sha256",
    }
    if name is not None:
        document["name"] = name
    return document, data


def _signature_input_document(
    envelope: Envelope, artifact: Mapping[str, Any]
) -> dict[str, Any]:
    pae = envelope.pae()
    payload_type = envelope.payload_type.encode("utf-8")
    return {
        "rule": PAE_RULE,
        "description": PAE_DESCRIPTION,
        "encoding": "bytes",
        "paeEncoding": "base64",
        "pae": b64enc(pae),
        "paeBase64": b64enc(pae),
        "paeSha256": f"sha256:{_sha256(pae)}",
        "payloadType": envelope.payload_type,
        "payloadTypeUtf8Length": len(payload_type),
        "payloadLength": len(envelope.payload),
        "payloadSha256": f"sha256:{_sha256(envelope.payload)}",
        "artifactDigest": dict(artifact["digest"]),
    }


def _sealed_conclusion(
    threshold: int,
    signers: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    verified = [
        signer["keyid"]
        for signer in signers
        if signer["sealedVerdict"]["status"] == STATUS_VERIFIED
    ]
    failed = [
        signer["keyid"]
        for signer in signers
        if signer["sealedVerdict"]["status"] == "invalid"
    ]
    unverifiable = [
        signer["keyid"]
        for signer in signers
        if signer["sealedVerdict"]["status"] == STATUS_UNVERIFIABLE
    ]

    if len(verified) >= threshold:
        status = STATUS_VERIFIED
        recomputable = True
    elif unverifiable:
        status = STATUS_UNVERIFIABLE
        recomputable = False
    elif failed:
        status = STATUS_REJECTED
        recomputable = True
    else:
        status = STATUS_UNVERIFIABLE
        recomputable = False

    return {
        "status": status,
        "recomputable": recomputable,
        "passed": status == STATUS_VERIFIED,
        "threshold": threshold,
        "verifiedKeyids": verified,
        "failedKeyids": failed,
        "unverifiableKeyids": unverifiable,
    }


def _verify_one_signature(
    signature: Signature,
    keys: Sequence[Key],
    pae: bytes,
) -> tuple[str, bool, str | None, Key | None]:
    if not keys:
        return STATUS_UNVERIFIABLE, False, "key-material-not-provided", None

    saw_invalid = False
    saw_unverifiable = False
    last_reason: str | None = None

    for key in keys:
        try:
            key.verify_signature(signature, pae)
            return STATUS_VERIFIED, True, None, key
        except exceptions.VerificationError as e:
            saw_unverifiable = True
            last_reason = f"verification-process-error: {e.__class__.__name__}"
        except exceptions.UnverifiedSignatureError:
            saw_invalid = True
            last_reason = "signature-invalid"
        except (
            exceptions.UnsupportedLibraryError,
            exceptions.UnsupportedAlgorithmError,
            KeyError,
            TypeError,
            ValueError,
        ) as e:
            saw_unverifiable = True
            last_reason = f"verification-unavailable: {e.__class__.__name__}"
        except Exception as e:
            saw_unverifiable = True
            last_reason = f"verification-unavailable: {e.__class__.__name__}"

    if saw_invalid:
        return "invalid", True, last_reason or "signature-invalid", None
    if saw_unverifiable:
        return STATUS_UNVERIFIABLE, False, last_reason, None
    return STATUS_UNVERIFIABLE, False, "key-material-not-provided", None


def seal_evidence(  # noqa: PLR0913
    envelope: Envelope,
    keys: Sequence[Key] | Mapping[str, Key],
    threshold: int = 1,
    *,
    artifact: Any = None,
    artifact_name: str | None = None,
    certificates: Any = None,
    disabled_backends: Iterable[str] | None = None,
    disabled_algorithms: Iterable[str] | None = None,
    backend_status: Mapping[str, str] | None = None,
    key_factories: Mapping[str, Callable[[str, Mapping[str, Any]], Key]] | None = None,
) -> Evidence:
    """Verify an envelope once and seal an offline evidence document.

    Args:
        envelope: DSSE envelope that was verified.
        keys: Caller-provided public keys.  No key material is fetched or
            inferred.
        threshold: Number of unique public keys required for acceptance.
        artifact: Bytes, path, or file-like object identified by the
            verification input.  If omitted, the envelope payload itself is
            recorded as the artifact.
        artifact_name: Optional name recorded for the artifact.
        certificates: Optional caller-provided certificates. A certificate is
            recorded only when its public key matches a signer key.
        disabled_backends: Optional backends that must not be used. Their
            conclusions are sealed as unverifiable.
        disabled_algorithms: Optional algorithm names that must not be used.
        backend_status: Optional mapping of backend status names.
        key_factories: Optional custom factories for recorded implementations.

    The returned :class:`Evidence` object serializes to JSON.  It contains only
    public key material, the exact PAE bytes, and the artifact digest.
    """

    if threshold <= 0:
        raise ValueError("Threshold must be greater than 0")

    key_list = _normalize_keys(keys)
    if len(key_list) < threshold:
        raise ValueError("Number of keys can't be less than threshold")

    artifact_document, _ = _artifact_document(envelope, artifact, artifact_name)
    signature_input = _signature_input_document(envelope, artifact_document)
    pae = envelope.pae()
    disabled_backend_set = {
        _normalize_backend(value) or value.lower()
        for value in _iter_values(disabled_backends)
    }
    disabled_algorithm_set = _iter_values(disabled_algorithms)
    backend_status_map = dict(backend_status or {})

    signer_documents = []
    accepted_key_map: dict[str, Key] = {}
    for signature in envelope.signatures.values():
        matching_keys = [key for key in key_list if key.keyid == signature.keyid]
        accepted_key = None
        disabled_reason = None
        for key in matching_keys:
            signer_view = {
                "backend": _backend_document(key),
                "algorithm": {"keytype": key.keytype, "scheme": key.scheme},
            }
            disabled, reason = _is_disabled(
                signer_view,
                disabled_backend_set,
                disabled_algorithm_set,
                backend_status_map,
            )
            if disabled:
                disabled_reason = reason
                break

        if disabled_reason is not None:
            status, recomputable, reason = STATUS_UNVERIFIABLE, False, disabled_reason
        else:
            status, recomputable, reason, accepted_key = _verify_one_signature(
                signature, matching_keys, pae
            )
        document: dict[str, Any] = {
            "keyid": signature.keyid,
            "signature": _signature_document(signature),
            "signatureEncoding": "base64",
            "signedBytes": {
                "rule": PAE_RULE,
                "paeSha256": signature_input["paeSha256"],
                "artifactDigest": dict(artifact_document["digest"]),
            },
            "sealedVerdict": {
                "status": status,
                "recomputable": recomputable,
                "reason": reason,
            },
        }
        if accepted_key is not None:
            accepted_key_map[signature.keyid] = accepted_key
            implementation = (
                f"{type(accepted_key).__module__}.{type(accepted_key).__qualname__}"
            )
            document["algorithm"] = {
                "keytype": accepted_key.keytype,
                "scheme": accepted_key.scheme,
            }
            document["keytype"] = accepted_key.keytype
            document["scheme"] = accepted_key.scheme
            document["key"] = _key_document(accepted_key)
            document["implementation"] = implementation
            document["keyFingerprint"] = _key_material_digest(
                accepted_key.keytype,
                accepted_key.scheme,
                accepted_key.keyval,
            )
            document["spkiSha256"] = _spki_digest(
                accepted_key.keytype, accepted_key.keyval
            )
            document["backend"] = _backend_document(accepted_key)
            certificate = _matching_certificate(certificates, document["spkiSha256"])
            if certificate is not None:
                document["certificateSpkiSha256"] = document["spkiSha256"]
        signer_documents.append(document)

    conclusion = _sealed_conclusion(threshold, signer_documents)
    document = {
        "evidenceVersion": EVIDENCE_VERSION,
        "kind": EVIDENCE_KIND,
        "envelope": envelope.to_dict(),
        "signatureInput": signature_input,
        "artifact": artifact_document,
        "signatures": signer_documents,
        "threshold": threshold,
        "conclusion": conclusion,
    }
    _assert_no_private_material(document)
    evidence = Evidence(document)
    evidence.accepted_keys = accepted_key_map
    return evidence


def _normalize_keys(keys: Any) -> list[Key]:
    if keys is None:
        return []
    if isinstance(keys, Key):
        return [keys]
    if isinstance(keys, Mapping):
        result = []
        for keyid, value in keys.items():
            if isinstance(value, Key):
                result.append(value)
            elif isinstance(value, Mapping):
                result.append(_key_from_document(str(keyid), dict(value)))
            else:
                raise TypeError(f"unsupported key value for {keyid}")
        return result
    if isinstance(keys, Sequence) and not isinstance(keys, (str, bytes)):
        result = []
        for key in keys:
            if isinstance(key, Key):
                result.append(key)
            elif isinstance(key, Mapping):
                document = dict(key)
                keyid = str(document.pop("keyid"))
                result.append(_key_from_document(keyid, document))
            else:
                raise TypeError(f"unsupported key: {type(key)}")
        return result
    raise TypeError(f"unsupported keys value: {type(keys)}")


def _key_from_document(keyid: str, document: Mapping[str, Any]) -> Key:
    data = dict(document)
    keytype = data.pop("keytype")
    scheme = data.pop("scheme")
    keyval = data.pop("keyval")
    if not all(isinstance(item, str) for item in (keyid, keytype, scheme)):
        raise TypeError("keyid, keytype and scheme must be strings")
    if not isinstance(keyval, dict):
        raise TypeError("keyval must be an object")

    if scheme.startswith("pgp+"):
        return GPGKey(keyid, keytype, scheme, keyval, data)
    if keytype == SigstoreKey.DEFAULT_KEY_TYPE or scheme == SigstoreKey.DEFAULT_SCHEME:
        return SigstoreKey(keyid, keytype, scheme, keyval, data)
    return SSlibKey(keyid, keytype, scheme, keyval, data)


class Evidence:
    """A sealed, JSON-serializable DSSE verification evidence document."""

    def __init__(self, document: Mapping[str, Any]):
        self._document = _json_copy(dict(document))
        self._validate()
        _assert_no_private_material(self._document)
        self.accepted_keys: dict[str, Key] = {}

    def _validate(self) -> None:
        document = self._document
        required = (
            "evidenceVersion",
            "kind",
            "envelope",
            "signatureInput",
            "artifact",
            "signatures",
            "threshold",
            "conclusion",
        )
        missing = [name for name in required if name not in document]
        if missing:
            raise EvidenceFormatError(f"evidence is missing fields: {missing}")
        if document["kind"] != EVIDENCE_KIND:
            raise EvidenceFormatError(f"unexpected evidence kind: {document['kind']}")
        if not isinstance(document["envelope"], Mapping):
            raise EvidenceFormatError("envelope must be an object")
        for name in ("signatureInput", "artifact", "conclusion"):
            if not isinstance(document[name], Mapping):
                raise EvidenceFormatError(f"{name} must be an object")
        if not isinstance(document["conclusion"].get("status"), str):
            raise EvidenceFormatError("conclusion must contain a status")
        if not isinstance(document["signatures"], list):
            raise EvidenceFormatError("signatures must be an array")
        if not all(isinstance(signer, Mapping) for signer in document["signatures"]):
            raise EvidenceFormatError("signature entries must be objects")
        if not isinstance(document["threshold"], int) or document["threshold"] <= 0:
            raise EvidenceFormatError("threshold must be a positive integer")

    @property
    def document(self) -> dict[str, Any]:
        return _json_copy(self._document)

    @property
    def threshold(self) -> int:
        return int(self._document["threshold"])

    @property
    def sealed_status(self) -> str:
        return str(self._document["conclusion"]["status"])

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self._document)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(
            self._document,
            ensure_ascii=False,
            indent=indent,
            sort_keys=indent is not None,
        )

    def write(self, destination: str | os.PathLike[str] | BinaryIO) -> None:
        text = self.to_json(indent=2)
        if hasattr(destination, "write"):
            destination.write(text)  # type: ignore[union-attr]
            return
        path = cast(str | os.PathLike[str], destination)
        Path(path).write_text(text + "\n", encoding="utf-8")

    def verify(  # noqa: PLR0913
        self,
        *,
        keys: Any = None,
        certificates: Any = None,
        artifact: Any = None,
        disabled_backends: Iterable[str] | None = None,
        disabled_algorithms: Iterable[str] | None = None,
        backend_status: Mapping[str, str] | None = None,
        key_factories: Mapping[str, Callable[[str, Mapping[str, Any]], Key]]
        | None = None,
        allow_embedded_keys: bool = False,
    ) -> VerificationReport:
        return verify_evidence(
            self,
            keys=keys,
            certificates=certificates,
            artifact=artifact,
            disabled_backends=disabled_backends,
            disabled_algorithms=disabled_algorithms,
            backend_status=backend_status,
            key_factories=key_factories,
            allow_embedded_keys=allow_embedded_keys,
        )


class VerificationReport:
    """Result of recomputing a sealed evidence document."""

    def __init__(self, document: Mapping[str, Any]):
        self._document = _json_copy(dict(document))

    @property
    def status(self) -> str:
        return str(self._document["conclusion"]["status"])

    @property
    def passed(self) -> bool:
        return self.status == STATUS_VERIFIED

    @property
    def recomputable(self) -> bool:
        return bool(self._document["conclusion"]["recomputable"])

    @property
    def message(self) -> str | None:
        message = self._document["conclusion"].get("message")
        return message if isinstance(message, str) else None

    @property
    def document(self) -> dict[str, Any]:
        return _json_copy(self._document)

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self._document)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(
            self._document,
            ensure_ascii=False,
            indent=indent,
            sort_keys=indent is not None,
        )

    def write(self, destination: str | os.PathLike[str] | BinaryIO) -> None:
        text = self.to_json(indent=2)
        if hasattr(destination, "write"):
            destination.write(text)  # type: ignore[union-attr]
            return
        path = cast(str | os.PathLike[str], destination)
        Path(path).write_text(text + "\n", encoding="utf-8")

    def raise_for_status(self) -> None:
        if self.passed:
            return
        message = self.message or f"evidence verification ended as {self.status}"
        error = exceptions.VerificationError(message)
        error.report = self  # type: ignore[attr-defined]
        raise error

    def __getitem__(self, key: str) -> Any:
        return self._document[key]

    def __bool__(self) -> bool:
        return self.passed


def load_evidence(source: Any) -> Evidence:
    """Load evidence from a dict, JSON string, path, bytes, or file object."""

    if isinstance(source, Evidence):
        return source
    document = _load_json(source)
    return Evidence(document)


def _certificate_spki(certificate: Any) -> str | None:
    try:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
            PublicFormat,
        )

        if isinstance(certificate, x509.Certificate):
            cert = certificate
        else:
            if isinstance(certificate, str):
                data = certificate.encode("utf-8")
            else:
                data = bytes(certificate)
            if b"-----BEGIN CERTIFICATE-----" in data:
                cert = x509.load_pem_x509_certificate(data)
            else:
                cert = x509.load_der_x509_certificate(data)
        spki = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return f"sha256:{_sha256(spki)}"
    except Exception:
        return None


def _certificate_list(certificates: Any) -> list[Any]:
    if certificates is None:
        return []
    if isinstance(certificates, (str, bytes, bytearray)) or hasattr(
        certificates, "public_key"
    ):
        return [certificates]
    return list(certificates)


def _matching_certificate(certificates: Any, spki: str | None) -> Any:
    if spki is None:
        return None
    for certificate in _certificate_list(certificates):
        if _certificate_spki(certificate) == spki:
            return certificate
    return None


def _caller_key_values(keys: Any) -> list[Any]:
    if keys is None:
        return []
    if isinstance(keys, (Key, str, bytes, bytearray)):
        return [keys]
    if isinstance(keys, Mapping):
        if {"keytype", "scheme", "keyval"} <= set(keys):
            return [keys]
        values = []
        for keyid, item in keys.items():
            if isinstance(item, Mapping) and "keyid" not in item:
                copied = dict(item)
                copied["keyid"] = str(keyid)
                values.append(copied)
            else:
                values.append(item)
        return values
    return list(keys)


def _caller_key_indexes(  # noqa: PLR0912
    keys: Any,
    certificates: Any,
) -> tuple[dict[str, Key], dict[str, list[Any]], list[str]]:
    by_keyid: dict[str, Key] = {}
    by_spki: dict[str, list[Any]] = {}
    errors: list[str] = []

    for value in _caller_key_values(keys):
        try:
            if isinstance(value, Key):
                key = value
            elif isinstance(value, Mapping):
                document = dict(value)
                keyid = str(document.pop("keyid"))
                key = _key_from_document(keyid, document)
            elif isinstance(value, (str, bytes, bytearray)):
                spki = _material_spki(value)
                if spki is None:
                    errors.append("key-material-unreadable")
                else:
                    by_spki.setdefault(spki, []).append(value)
                continue
            else:
                errors.append(f"unsupported-key-material:{type(value)}")
                continue
        except (KeyError, TypeError, ValueError):
            errors.append("key-material-unreadable")
            continue

        by_keyid.setdefault(key.keyid, key)
        spki = _spki_digest(key.keytype, key.keyval)
        if spki:
            by_spki.setdefault(spki, []).append(key)

    if certificates is not None:
        if isinstance(certificates, (str, bytes, bytearray)):
            cert_list = [certificates]
        elif hasattr(certificates, "public_key"):
            cert_list = [certificates]
        else:
            cert_list = list(certificates)
        for certificate in cert_list:
            spki = _certificate_spki(certificate)
            if spki is None:
                errors.append("certificate-unreadable")

    return by_keyid, by_spki, errors


def _resolve_signer_key(  # noqa: PLR0911, PLR0912, PLR0913
    signer: Mapping[str, Any],
    by_keyid: Mapping[str, Key],
    by_spki: Mapping[str, list[Any]],
    certificates: Any,
    allow_embedded_keys: bool,
    key_factories: Mapping[str, Callable[[str, Mapping[str, Any]], Key]] | None,
) -> tuple[Key | None, str | None]:
    keyid = str(signer.get("keyid", ""))
    key_document = signer.get("key")
    if not isinstance(key_document, Mapping):
        return None, "key-material-not-provided"

    document = dict(key_document)
    document_keyid = str(document.pop("keyid", keyid))
    keytype = document.get("keytype")
    scheme = document.get("scheme")
    keyval = document.get("keyval")
    if not isinstance(keytype, str) or not isinstance(scheme, str):
        return None, "algorithm-not-recorded"
    if not isinstance(keyval, Mapping):
        return None, "key-material-not-provided"

    expected_fingerprint = signer.get("keyFingerprint")
    actual_fingerprint = _key_material_digest(keytype, scheme, keyval)
    if expected_fingerprint and expected_fingerprint != actual_fingerprint:
        return None, "key-material-fingerprint-mismatch"

    caller_key = by_keyid.get(document_keyid)
    if caller_key is not None:
        if _keyval_digest(caller_key.keyval) != _keyval_digest(keyval):
            return None, "caller-key-mismatch"
        document_key = _build_recorded_key(
            document_keyid, keytype, scheme, keyval, document, key_factories
        )
        if document_key is None:
            return None, "key-implementation-unavailable"
        return document_key, None

    expected_spki = signer.get("spkiSha256")
    if expected_spki:
        candidates = by_spki.get(str(expected_spki), [])
        if candidates:
            document_key = _build_recorded_key(
                document_keyid, keytype, scheme, keyval, document, key_factories
            )
            if document_key is None:
                return None, "key-implementation-unavailable"
            return document_key, None

    if certificates is not None and expected_spki:
        cert_list = (
            [certificates]
            if isinstance(certificates, (str, bytes, bytearray))
            or hasattr(certificates, "public_key")
            else list(certificates)
        )
        for certificate in cert_list:
            if _certificate_spki(certificate) == expected_spki:
                document_key = _build_recorded_key(
                    document_keyid, keytype, scheme, keyval, document, key_factories
                )
                if document_key is None:
                    return None, "key-implementation-unavailable"
                return document_key, None

    if not allow_embedded_keys:
        return None, "key-material-not-provided"

    document_key = _build_recorded_key(
        document_keyid, keytype, scheme, keyval, document, key_factories
    )
    if document_key is None:
        return None, "key-implementation-unavailable"
    return document_key, None


def _build_recorded_key(  # noqa: PLR0913
    keyid: str,
    keytype: str,
    scheme: str,
    keyval: Mapping[str, Any],
    document: Mapping[str, Any],
    key_factories: Mapping[str, Callable[[str, Mapping[str, Any]], Key]] | None,
) -> Key | None:
    implementation = document.get("implementation")
    if key_factories and isinstance(implementation, str):
        factory = key_factories.get(implementation)
        if factory is not None:
            return factory(keyid, document)
    try:
        return _key_from_document(keyid, document)
    except (ImportError, KeyError, TypeError, ValueError):
        return None


def _parse_signature(signer: Mapping[str, Any]) -> Signature | None:
    signature_document = signer.get("signature")
    if not isinstance(signature_document, Mapping):
        return None
    data = dict(signature_document)
    try:
        data["sig"] = b64dec(str(data["sig"])).hex()
        return Signature.from_dict(data)
    except Exception:
        return None


def _compare_artifact(
    envelope: Envelope,
    artifact_document: Mapping[str, Any],
    artifact: Any,
) -> tuple[dict[str, Any], bytes | None]:
    expected_digest = artifact_document.get("digest")
    expected_size = artifact_document.get("size")
    binding = artifact_document.get("binding")
    result: dict[str, Any] = {
        "name": artifact_document.get("name"),
        "binding": binding,
        "expected": {
            "size": expected_size,
            "digest": _json_copy(expected_digest),
        },
        "actual": None,
        "recomputable": True,
        "status": STATUS_UNVERIFIABLE,
        "reason": None,
    }

    if not isinstance(expected_digest, Mapping) or not isinstance(
        expected_digest.get("sha256"), str
    ):
        result["reason"] = "artifact-digest-not-recorded"
        result["recomputable"] = False
        return result, None

    if artifact is None:
        if binding != "envelope-payload":
            result["reason"] = "artifact-not-provided"
            result["recomputable"] = False
            return result, None
        data = envelope.payload
    else:
        data, _ = _read_bytes(artifact)

    actual_digest = _digest(data)
    result["actual"] = {"size": len(data), "digest": actual_digest}
    if actual_digest["sha256"] != expected_digest["sha256"]:
        result["status"] = "invalid"
        result["reason"] = "artifact-digest-mismatch"
    elif expected_size is not None and len(data) != expected_size:
        result["status"] = "invalid"
        result["reason"] = "artifact-size-mismatch"
    else:
        result["status"] = STATUS_VERIFIED
    return result, data


def _compare_signature_input(
    envelope: Envelope,
    signature_input: Mapping[str, Any],
) -> dict[str, Any]:
    actual_pae = envelope.pae()
    actual_payload = envelope.payload
    result: dict[str, Any] = {
        "rule": signature_input.get("rule"),
        "expectedPaeSha256": signature_input.get("paeSha256"),
        "actualPaeSha256": f"sha256:{_sha256(actual_pae)}",
        "expectedPayloadSha256": signature_input.get("payloadSha256"),
        "actualPayloadSha256": f"sha256:{_sha256(actual_payload)}",
        "status": STATUS_VERIFIED,
        "recomputable": True,
        "reason": None,
    }
    try:
        expected_pae = b64dec(str(signature_input["paeBase64"]))
    except Exception:
        result["status"] = "invalid"
        result["reason"] = "signature-input-not-decodable"
        return result

    if expected_pae != actual_pae:
        result["status"] = "invalid"
        result["reason"] = "signature-input-mismatch"
    elif signature_input.get("paeSha256") != result["actualPaeSha256"]:
        result["status"] = "invalid"
        result["reason"] = "signature-input-digest-mismatch"
    elif signature_input.get("payloadSha256") != result["actualPayloadSha256"]:
        result["status"] = "invalid"
        result["reason"] = "payload-digest-mismatch"
    elif signature_input.get("payloadType") != envelope.payload_type:
        result["status"] = "invalid"
        result["reason"] = "payload-type-mismatch"
    elif signature_input.get("payloadLength") != len(envelope.payload):
        result["status"] = "invalid"
        result["reason"] = "payload-length-mismatch"
    elif signature_input.get("payloadTypeUtf8Length") != len(
        envelope.payload_type.encode("utf-8")
    ):
        result["status"] = "invalid"
        result["reason"] = "payload-type-length-mismatch"
    return result


def _is_disabled(
    signer: Mapping[str, Any],
    disabled_backends: set[str],
    disabled_algorithms: set[str],
    backend_status: Mapping[str, str],
) -> tuple[bool, str | None]:
    backend = signer.get("backend")
    backend_name = None
    if isinstance(backend, Mapping):
        backend_name = backend.get("name")
    elif isinstance(backend, str):
        backend_name = backend
    normalized = _normalize_backend(str(backend_name) if backend_name else None)
    if normalized and normalized in disabled_backends:
        return True, "verification-backend-disabled"

    if normalized:
        for name, status in backend_status.items():
            if _normalize_backend(name) == normalized and status.lower() in {
                "disabled",
                "retired",
                "unavailable",
                "off",
            }:
                return True, f"verification-backend-{status.lower()}"

    algorithm = signer.get("algorithm")
    if isinstance(algorithm, Mapping):
        scheme = algorithm.get("scheme")
        keytype = algorithm.get("keytype")
        if isinstance(scheme, str) and scheme in disabled_algorithms:
            return True, "verification-algorithm-disabled"
        if (
            isinstance(keytype, str)
            and isinstance(scheme, str)
            and f"{keytype}/{scheme}" in disabled_algorithms
        ):
            return True, "verification-algorithm-disabled"
    return False, None


def verify_evidence(  # noqa: PLR0912, PLR0913, PLR0915
    evidence: Any,
    *,
    keys: Any = None,
    certificates: Any = None,
    artifact: Any = None,
    disabled_backends: Iterable[str] | None = None,
    disabled_algorithms: Iterable[str] | None = None,
    backend_status: Mapping[str, str] | None = None,
    key_factories: Mapping[str, Callable[[str, Mapping[str, Any]], Key]] | None = None,
    allow_embedded_keys: bool = False,
) -> VerificationReport:
    """Recompute a sealed DSSE evidence document.

    ``unverifiable`` means the recorded conclusion could not be recomputed
    (missing key material, a disabled verifier backend, or an unavailable
    implementation).  ``rejected`` means recomputation was possible and the
    artifact, signature input, or signature check failed.
    """

    evidence_object = load_evidence(evidence)
    document = evidence_object.to_dict()
    envelope_document = document["envelope"]
    signature_input = document["signatureInput"]
    artifact_document = document["artifact"]
    signer_documents = document["signatures"]

    from securesystemslib.dsse import Envelope  # noqa: PLC0415

    try:
        envelope = Envelope.from_dict(_json_copy(envelope_document))
    except Exception as e:
        raise EvidenceFormatError("recorded envelope is invalid") from e

    disabled_backend_set = {
        _normalize_backend(value) or value.lower()
        for value in _iter_values(disabled_backends)
    }
    disabled_algorithm_set = _iter_values(disabled_algorithms)
    backend_status_map = dict(backend_status or {})

    by_keyid, by_spki, certificate_errors = _caller_key_indexes(keys, certificates)

    artifact_result, _ = _compare_artifact(envelope, artifact_document, artifact)
    input_result = _compare_signature_input(envelope, signature_input)
    if signature_input.get("artifactDigest") != artifact_document.get("digest"):
        input_result["status"] = "invalid"
        input_result["reason"] = "artifact-binding-mismatch"

    signer_results = []
    for signer in signer_documents:
        keyid = str(signer.get("keyid", ""))
        sealed_verdict = _json_copy(signer.get("sealedVerdict"))
        result: dict[str, Any] = {
            "keyid": keyid,
            "sealedVerdict": sealed_verdict,
            "status": STATUS_UNVERIFIABLE,
            "recomputable": False,
            "reason": None,
            "algorithm": _json_copy(signer.get("algorithm")),
            "backend": _json_copy(signer.get("backend")),
        }

        signed_bytes = signer.get("signedBytes")
        if isinstance(signed_bytes, Mapping):
            if signed_bytes.get("paeSha256") != signature_input.get("paeSha256"):
                result["status"] = "invalid"
                result["recomputable"] = True
                result["reason"] = "signer-input-mismatch"
                signer_results.append(result)
                continue
            if signed_bytes.get("artifactDigest") != artifact_document.get("digest"):
                result["status"] = "invalid"
                result["recomputable"] = True
                result["reason"] = "signer-artifact-binding-mismatch"
                signer_results.append(result)
                continue

        disabled, disabled_reason = _is_disabled(
            signer,
            disabled_backend_set,
            disabled_algorithm_set,
            backend_status_map,
        )
        if disabled:
            result["reason"] = disabled_reason
            signer_results.append(result)
            continue

        signature = _parse_signature(signer)
        if signature is None:
            result["status"] = "invalid"
            result["recomputable"] = True
            result["reason"] = "signature-not-decodable"
            signer_results.append(result)
            continue

        key, key_error = _resolve_signer_key(
            signer,
            by_keyid,
            by_spki,
            certificates,
            allow_embedded_keys,
            key_factories,
        )
        if key is None:
            if key_error in {
                "caller-key-mismatch",
                "key-material-fingerprint-mismatch",
                "signature-not-decodable",
            }:
                result["status"] = "invalid"
                result["recomputable"] = True
            result["reason"] = key_error
            signer_results.append(result)
            continue

        status, recomputable, reason, _ = _verify_one_signature(
            signature, [key], envelope.pae()
        )
        result["status"] = status
        result["recomputable"] = recomputable
        result["reason"] = reason
        signer_results.append(result)

    verified = [
        signer["keyid"]
        for signer in signer_results
        if signer["status"] == STATUS_VERIFIED
    ]
    failed = [
        signer["keyid"] for signer in signer_results if signer["status"] == "invalid"
    ]
    unverifiable = [
        signer["keyid"]
        for signer in signer_results
        if signer["status"] == STATUS_UNVERIFIABLE
    ]
    preserved = [
        {
            "keyid": signer["keyid"],
            "sealedStatus": signer["sealedVerdict"].get("status")
            if isinstance(signer["sealedVerdict"], Mapping)
            else None,
            "status": signer["status"],
            "recomputable": signer["recomputable"],
            "reason": signer["reason"],
        }
        for signer in signer_results
        if signer["recomputable"] is False
        and isinstance(signer["sealedVerdict"], Mapping)
        and signer["sealedVerdict"].get("status") == STATUS_VERIFIED
    ]

    threshold = document["threshold"]
    if artifact_result["status"] == "invalid":
        overall = STATUS_REJECTED
        recomputable = True
        message = f"artifact rejected: {artifact_result['reason']}"
    elif input_result["status"] == "invalid":
        overall = STATUS_REJECTED
        recomputable = True
        message = f"signature input rejected: {input_result['reason']}"
    elif len(verified) >= threshold:
        overall = STATUS_VERIFIED
        recomputable = True
        message = None
    elif unverifiable or artifact_result["status"] == STATUS_UNVERIFIABLE:
        overall = STATUS_UNVERIFIABLE
        recomputable = False
        message = "recorded conclusion could not be recomputed"
    else:
        overall = STATUS_REJECTED
        recomputable = True
        message = (
            f"accepted signatures do not match threshold: found {len(verified)}, "
            f"expected {threshold}"
        )

    if certificate_errors and overall == STATUS_UNVERIFIABLE:
        message = f"{message}: {', '.join(certificate_errors)}"

    report = {
        "reportVersion": REPORT_VERSION,
        "kind": REPORT_KIND,
        "evidenceDigest": {
            "algorithm": "sha256",
            "canonicalization": "json-sort-keys-utf8",
            "value": f"sha256:{_sha256(_canonical_json(document))}",
        },
        "sealedConclusion": _json_copy(document["conclusion"]),
        "artifact": artifact_result,
        "signatureInput": input_result,
        "signers": signer_results,
        "conclusion": {
            "status": overall,
            "recomputable": recomputable,
            "passed": overall == STATUS_VERIFIED,
            "threshold": threshold,
            "verifiedKeyids": verified,
            "failedKeyids": failed,
            "unverifiableKeyids": unverifiable,
            "preservedConclusions": preserved,
            "message": message,
        },
    }
    return VerificationReport(report)


create_evidence = seal_evidence
verify_evidence_bundle = verify_evidence
EvidenceBundle = Evidence
EvidenceReport = VerificationReport
