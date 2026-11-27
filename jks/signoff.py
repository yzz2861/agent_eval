# vim: set et ai ts=4 sts=4 sw=4:
"""Offline certificate approval reuse checks for keystore manifests."""

from __future__ import print_function

import hashlib

from .jks import TrustedCertEntry


__all__ = [
    "STATUS_APPROVED",
    "STATUS_REAPPROVAL_REQUIRED",
    "SignoffResult",
    "certificate_digest",
    "chain_digest",
    "manifest_from_keystore",
    "check_signoff",
]


STATUS_APPROVED = "approved"
STATUS_REAPPROVAL_REQUIRED = "reapproval_required"


class SignoffResult(dict):
    """Machine-readable result for one manifest entry."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


def certificate_digest(certificate, algorithm="sha256"):
    """Return a lowercase hex digest for DER certificate bytes."""
    data = _certificate_bytes(certificate)
    return _new_hash(algorithm, data).hexdigest()


def chain_digest(chain, algorithm="sha256"):
    """Return an ordered digest over a certificate chain."""
    digest = _new_hash(algorithm)
    for certificate in _chain_certificates(chain):
        if _is_digest_text(certificate):
            digest.update(certificate.encode("ascii"))
        else:
            digest.update(_certificate_bytes(certificate))
    return digest.hexdigest()


def manifest_from_keystore(keystore, usage_by_alias=None, container_location=None):
    """Build certificate manifest records from a loaded JKS, JCEKS, BKS or UBER store."""
    usage_by_alias = usage_by_alias or {}
    location = container_location or keystore.store_type
    records = []

    for position, (alias, entry) in enumerate(keystore.entries.items()):
        certificates = _entry_certificates(entry)
        if not certificates:
            continue

        records.append({
            "entry_id": alias,
            "alias": alias,
            "container_location": location,
            "store_type": entry.store_type,
            "position": position,
            "usage": usage_by_alias.get(alias, alias),
            "public_certificate": certificates[0],
            "certificate_chain": certificates,
        })

    return records


def check_signoff(manifest, previous_approvals, algorithm="sha256"):
    """Compare manifest certificate records against approvals keyed by registered usage."""
    approvals = {}
    for approval in _as_records(previous_approvals):
        usage = _required_value(approval, "usage")
        if usage in approvals:
            raise ValueError("Duplicate previous approval for usage %r" % (usage,))
        approvals[usage] = _normalize_record(approval, algorithm)

    results = []
    for position, record in enumerate(_as_records(manifest)):
        current = _normalize_record(record, algorithm, default_position=position)
        previous = approvals.get(current["usage"])
        results.append(_compare_record(current, previous))
    return results


def _compare_record(current, previous):
    result = SignoffResult({
        "status": STATUS_APPROVED,
        "entry_id": current["entry_id"],
        "alias": current["alias"],
        "container_location": current["container_location"],
        "store_type": current["store_type"],
        "position": current["position"],
        "usage": current["usage"],
        "public_certificate_digest": current["public_certificate_digest"],
        "certificate_chain": list(current["certificate_chain"]),
        "certificate_chain_digest": current["certificate_chain_digest"],
        "differences": [],
    })

    if previous is None:
        result["status"] = STATUS_REAPPROVAL_REQUIRED
        result["differences"].append({
            "field": "usage",
            "reason": "no_previous_approval",
            "previous": None,
            "current": current["usage"],
        })
        return result

    result["previous_approval"] = {
        "entry_id": previous["entry_id"],
        "alias": previous["alias"],
        "container_location": previous["container_location"],
        "store_type": previous["store_type"],
        "position": previous["position"],
        "usage": previous["usage"],
        "public_certificate_digest": previous["public_certificate_digest"],
        "certificate_chain": list(previous["certificate_chain"]),
        "certificate_chain_digest": previous["certificate_chain_digest"],
    }

    if current["public_certificate_digest"] != previous["public_certificate_digest"]:
        result["status"] = STATUS_REAPPROVAL_REQUIRED
        result["differences"].append({
            "field": "public_certificate_digest",
            "reason": "digest_mismatch",
            "previous": previous["public_certificate_digest"],
            "current": current["public_certificate_digest"],
        })

    _compare_chain(result, previous, current)
    return result


def _compare_chain(result, previous, current):
    previous_chain = previous["certificate_chain"]
    current_chain = current["certificate_chain"]

    if len(previous_chain) != len(current_chain):
        result["status"] = STATUS_REAPPROVAL_REQUIRED
        result["differences"].append({
            "field": "certificate_chain.length",
            "reason": "length_mismatch",
            "previous": len(previous_chain),
            "current": len(current_chain),
        })

    for index in range(max(len(previous_chain), len(current_chain))):
        if index == 0 and any(difference["field"] == "public_certificate_digest"
                              for difference in result["differences"]):
            continue
        if index >= len(previous_chain):
            previous_digest = None
        else:
            previous_digest = previous_chain[index]

        if index >= len(current_chain):
            current_digest = None
        else:
            current_digest = current_chain[index]

        if previous_digest != current_digest:
            result["status"] = STATUS_REAPPROVAL_REQUIRED
            result["differences"].append({
                "field": "certificate_chain[%d].certificate_digest" % index,
                "reason": "digest_mismatch",
                "index": index,
                "previous": previous_digest,
                "current": current_digest,
            })


def _normalize_record(record, algorithm, default_position=None):
    usage = _required_value(record, "usage")
    alias = _value(record, "alias", "entry_id", default=usage)
    entry_id = _value(record, "entry_id", "alias", default=alias)
    position = _value(record, "position", "entry_position", "container_position", default=default_position)
    leaf_digest, leaf_source = _leaf_digest(record, algorithm)
    chain = _record_chain(record, algorithm, leaf_digest, leaf_source)

    return {
        "entry_id": entry_id,
        "alias": alias,
        "container_location": _value(record, "container_location", "location", "container", default=None),
        "store_type": _value(record, "store_type", "keystore_type", default=None),
        "position": position,
        "usage": usage,
        "public_certificate_digest": leaf_digest,
        "certificate_chain": chain,
        "certificate_chain_digest": _chain_digest_from_digests(chain, algorithm),
    }


def _leaf_digest(record, algorithm):
    explicit = _value(record, "public_certificate_digest", "certificate_digest", "public_cert_digest", "digest")
    certificate = _value(record, "public_certificate", "public_cert", "certificate", "cert")

    if explicit is not None:
        explicit = _normalize_digest(explicit)
        if certificate is not None:
            computed = certificate_digest(certificate, algorithm)
            if computed != explicit:
                raise ValueError("Public certificate digest does not match certificate data")
        return explicit, True

    if certificate is None:
        raise ValueError("Record is missing a public certificate or digest")
    return certificate_digest(certificate, algorithm), False


def _record_chain(record, algorithm, leaf_digest, leaf_explicit):
    explicit_chain = _value(record, "certificate_chain_digests", "chain_digests")
    chain = _value(record, "certificate_chain", "chain")

    if explicit_chain is not None:
        digests = [_normalize_digest(item) for item in _as_records(explicit_chain)]
        if chain is not None:
            computed = [certificate_digest(item, algorithm) for item in _chain_certificates(chain)]
            if computed != digests:
                raise ValueError("Certificate chain digests do not match chain data")
        if not digests:
            raise ValueError("Certificate chain must not be empty")
        if digests[0] != leaf_digest:
            raise ValueError("First certificate in chain must be the public certificate")
        return digests

    if chain is None:
        if leaf_explicit:
            return [leaf_digest]
        raise ValueError("Record is missing a certificate chain")

    certificates = _chain_certificates(chain)
    if not certificates:
        raise ValueError("Certificate chain must not be empty")

    digests = [certificate_digest(item, algorithm) for item in certificates]
    if digests[0] != leaf_digest:
        raise ValueError("First certificate in chain must be the public certificate")
    return digests


def _entry_certificates(entry):
    if isinstance(entry, TrustedCertEntry):
        certificates = [entry.cert]
        certificates.extend(_certificate_from_chain_item(item) for item in getattr(entry, "cert_chain", []))
        return _dedupe_certificates(certificates)

    cert_chain = entry.__dict__.get("cert_chain")
    if cert_chain:
        return [_certificate_from_chain_item(item) for item in cert_chain]

    return []


def _dedupe_certificates(certificates):
    result = []
    seen = set()
    for certificate in certificates:
        marker = bytes(bytearray(certificate))
        if marker not in seen:
            seen.add(marker)
            result.append(certificate)
    return result


def _chain_certificates(chain):
    return [_certificate_from_chain_item(item) for item in _as_records(chain)]


def _certificate_from_chain_item(item):
    if isinstance(item, tuple) and len(item) == 2:
        return item[1]
    if hasattr(item, "cert"):
        return item.cert
    if isinstance(item, dict):
        certificate = _value(item, "certificate", "cert", "public_certificate", "public_cert")
        if certificate is not None:
            return certificate
        digest = _value(item, "certificate_digest", "digest", "public_certificate_digest")
        if digest is not None:
            return digest
    return item


def _certificate_bytes(certificate):
    if isinstance(certificate, bytes):
        return certificate
    if isinstance(certificate, str):
        return certificate.encode("ascii") if _is_hex(certificate) else certificate.encode("utf-8")
    if hasattr(certificate, "cert"):
        return certificate.cert
    raise TypeError("Unsupported certificate type %r" % (type(certificate),))


def _normalize_digest(digest):
    if isinstance(digest, bytes):
        digest = as_hex_digest(digest)
    if not _is_hex(digest):
        raise ValueError("Certificate digest must be hexadecimal")
    return digest.lower()


def as_hex_digest(digest):
    return "".join("%02x" % byte for byte in bytearray(digest))


def _is_digest_text(value):
    return isinstance(value, str) and _is_hex(value)


def _is_hex(value):
    if not isinstance(value, str) or not value:
        return False
    lowered = value.lower()
    if lowered.startswith("0x"):
        lowered = lowered[2:]
    try:
        int(lowered, 16)
    except ValueError:
        return False
    return True


def _chain_digest_from_digests(digests, algorithm):
    return chain_digest(digests, algorithm)


def _new_hash(algorithm, data=b""):
    normalized_name = algorithm.lower().replace("-", "")
    return hashlib.new(normalized_name, data)


def _as_records(value):
    if isinstance(value, dict) and not _looks_like_record(value):
        return list(value.values())
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _looks_like_record(value):
    record_keys = set([
        "usage", "certificate_chain", "chain", "certificate_chain_digests",
        "chain_digests", "public_certificate", "public_cert", "certificate",
        "cert", "public_certificate_digest", "certificate_digest",
        "public_cert_digest", "digest",
    ])
    return bool(record_keys.intersection(value.keys()))


def _required_value(record, *names):
    value = _value(record, *names)
    if value is None:
        raise ValueError("Record is missing required field %s" % (names[0],))
    return value


def _value(record, *names, **kwargs):
    default = kwargs.get("default")
    if isinstance(record, dict):
        for name in names:
            if name in record:
                return record[name]
    else:
        for name in names:
            if hasattr(record, name):
                return getattr(record, name)
    return default
