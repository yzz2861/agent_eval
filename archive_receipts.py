"""Archive receipt timeline analysis built on asn1crypto.

The module parses caller-supplied synthetic CMS/RFC 3161 timestamp receipts,
verifies digest math and exact byte ranges, and links protected archive records
through predecessor receipt digests. Signature trust/certificate validity is
never inferred here; callers supply that conclusion.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from asn1crypto import cms, pem, tsp


HASH_ALIASES = {
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha224": "sha224",
    "sha-224": "sha224",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha384": "sha384",
    "sha-384": "sha384",
    "sha512": "sha512",
    "sha-512": "sha512",
}

TRUSTED_VALUES = {"true", "trusted", "trust", "ok", "valid", "accepted", "1"}
UNTRUSTED_VALUES = {"false", "untrusted", "invalid", "revoked", "rejected", "0"}


def digest_bytes(data: bytes, algorithm: str = "sha256") -> bytes:
    key = HASH_ALIASES.get((algorithm or "sha256").lower())
    if not key:
        raise ValueError("unsupported digest algorithm: %r" % algorithm)
    return getattr(hashlib, key)(data).digest()


def hex_digest(data: bytes, algorithm: str = "sha256") -> str:
    return digest_bytes(data, algorithm).hex()


def constant_time_equals(left: Optional[bytes], right: Optional[bytes]) -> bool:
    if left is None or right is None:
        return False
    import hmac

    return hmac.compare_digest(left, right)


def iso_time(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return value.astimezone().isoformat().replace("+00:00", "Z")
    return str(value)


# ---------------------------------------------------------------------------
# Minimal DER/BER TLV walker.  asn1crypto owns semantic parsing; this walker
# only supplies true source offsets for byte-range commitments.
# ---------------------------------------------------------------------------


@dataclass
class TLVNode:
    start: int
    header_end: int
    end: int
    tag: int
    constructed: bool
    cls: int
    indefinite: bool = False
    children: List["TLVNode"] = field(default_factory=list)

    @property
    def content_start(self) -> int:
        return self.header_end

    @property
    def content_end(self) -> int:
        return self.end - (2 if self.indefinite else 0)


def _read_tag(data: bytes, pos: int) -> Tuple[int, bool, int, int]:
    first = data[pos]
    pos += 1
    cls = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            byte = data[pos]
            pos += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                break
    return cls, constructed, tag, pos


def _read_length(data: bytes, pos: int) -> Tuple[Optional[int], int, bool]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos, False
    count = first & 0x7F
    if count == 0:
        return None, pos, True
    length = int.from_bytes(data[pos:pos + count], "big")
    return length, pos + count, False


def parse_tlv_node(data: bytes, start: int = 0) -> TLVNode:
    cls, constructed, tag, pos = _read_tag(data, start)
    length, header_end, indefinite = _read_length(data, pos)

    if not indefinite:
        end = header_end + int(length)
        node = TLVNode(start, header_end, end, tag, constructed, cls, False)
        if constructed:
            cursor = header_end
            while cursor < end:
                child = parse_tlv_node(data, cursor)
                node.children.append(child)
                cursor = child.end
        return node

    node = TLVNode(start, header_end, -1, tag, constructed, cls, True)
    cursor = header_end
    if not constructed:
        raise ValueError("indefinite length is only valid for constructed TLVs")
    while True:
        child = parse_tlv_node(data, cursor)
        if child.cls == 0 and child.tag == 0 and not child.constructed:
            node.end = child.end
            break
        node.children.append(child)
        cursor = child.end
    return node


def parse_tlv_roots(data: bytes) -> List[TLVNode]:
    roots: List[TLVNode] = []
    pos = 0
    while pos < len(data):
        node = parse_tlv_node(data, pos)
        roots.append(node)
        pos = node.end
    return roots


def cms_econtent_tlv(der: bytes, content_info: Optional[TLVNode] = None) -> Optional[TLVNode]:
    """Return the OCTET STRING node containing CMS EncapsulatedContent bytes."""
    try:
        node = content_info or parse_tlv_roots(der)[0]
        # ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ... }
        explicit = node.children[1]
        signed_data_or_content = explicit.children[0]

        # The caller may pass the [0] wrapper or SignedData itself.
        signed_data = signed_data_or_content
        if signed_data.tag == 4:
            return signed_data

        # SignedData ::= SEQUENCE { version, digestAlgorithms,
        # encapContentInfo, ..., signerInfos }
        encap_content_info = signed_data.children[2]
        econtent_explicit = encap_content_info.children[1]
        return econtent_explicit.children[0]
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Materials and byte ranges
# ---------------------------------------------------------------------------


@dataclass
class ByteRange:
    source: str
    start: int
    end: int
    role: str
    basis: str = "raw"
    record_id: Optional[str] = None
    note: Optional[str] = None

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "basis": self.basis,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "role": self.role,
            "record_id": self.record_id,
            "note": self.note,
        }


class RangeIndex:
    def __init__(self) -> None:
        self.ranges: List[ByteRange] = []

    def add(
        self,
        source: str,
        start: int,
        end: int,
        role: str,
        basis: str = "raw",
        record_id: Optional[str] = None,
        note: Optional[str] = None,
    ) -> ByteRange:
        if start < 0 or end < start:
            raise ValueError("invalid byte range %d..%d" % (start, end))
        item = ByteRange(source, start, end, role, basis, record_id, note)
        self.ranges.append(item)
        return item

    def find_digest(
        self,
        algorithm: str,
        expected_hex: str,
        store: "MaterialStore",
        roles: Optional[Sequence[str]] = None,
    ) -> List[ByteRange]:
        expected = (expected_hex or "").lower().replace(":", "")
        wanted_roles = set(roles or [])
        matches: List[ByteRange] = []
        for item in self.ranges:
            if wanted_roles and item.role not in wanted_roles:
                continue
            try:
                actual = hex_digest(store.range_bytes(item), algorithm)
            except (KeyError, ValueError, IndexError):
                continue
            if actual == expected:
                matches.append(item)
        return matches


@dataclass
class Material:
    source_id: str
    raw: bytes
    der: bytes
    encoding: str
    pem_label: Optional[str] = None


class MaterialStore:
    def __init__(self) -> None:
        self.materials: Dict[str, Material] = {}

    def add(self, source_id: str, raw: bytes) -> Material:
        der, encoding, pem_label = decode_material(raw)
        material = Material(source_id, raw, der, encoding, pem_label)
        self.materials[source_id] = material
        return material

    def resolve_source(self, reference: Optional[str]) -> Optional[Material]:
        if not reference:
            return None
        ref = str(reference)
        if ref in self.materials:
            return self.materials[ref]
        base = Path(ref).name
        if base in self.materials:
            return self.materials[base]
        for source_id, material in self.materials.items():
            if Path(source_id).name == base:
                return material
        ref_stem = Path(ref).name.split(".")[0]
        for source_id, material in self.materials.items():
            if Path(source_id).name.split(".")[0] == ref_stem:
                return material
        return None

    def range_bytes(self, item: ByteRange) -> bytes:
        material = self.materials[item.source]
        data = material.der if item.basis == "der" else material.raw
        if item.end > len(data):
            raise IndexError("range %d..%d outside %s" % (item.start, item.end, item.source))
        return data[item.start:item.end]


def decode_material(raw: bytes) -> Tuple[bytes, str, Optional[str]]:
    stripped = raw.lstrip()
    if stripped.startswith(b"-----BEGIN"):
        name, _headers, der = pem.unarmor(raw)
        return der, "pem", name
    return raw, "der", None


# ---------------------------------------------------------------------------
# Caller-supplied trust
# ---------------------------------------------------------------------------


def _normalize_trust_value(value: Any) -> str:
    if isinstance(value, bool):
        return "trusted" if value else "untrusted"
    text = str(value).strip().lower()
    if text in TRUSTED_VALUES:
        return "trusted"
    if text in UNTRUSTED_VALUES:
        return "untrusted"
    return "not_provided"


def resolve_trust(
    trust: Any,
    source_id: str,
    receipt_id: Optional[str] = None,
    record_id: Optional[str] = None,
) -> Dict[str, Any]:
    if trust is None:
        return {"verdict": "not_provided", "provided": False, "basis": "caller"}

    if callable(trust):
        result = trust(source_id=source_id, receipt_id=receipt_id, record_id=record_id)
        return {"verdict": _normalize_trust_value(result), "provided": True, "basis": "caller"}

    decisions: Mapping[str, Any] = trust
    nested = decisions.get("materials") if isinstance(decisions, Mapping) else None
    maps = [nested, decisions] if isinstance(nested, Mapping) else [decisions]
    keys = [
        source_id,
        Path(source_id).name,
        receipt_id,
        record_id,
        Path(source_id).name.split(".")[0],
        "*",
        "all",
        "all_signatures",
    ]
    for decision_map in maps:
        if not isinstance(decision_map, Mapping):
            continue
        for key in keys:
            if key and key in decision_map:
                return {
                    "verdict": _normalize_trust_value(decision_map[key]),
                    "provided": True,
                    "basis": "caller",
                    "key": key,
                }
    return {"verdict": "not_provided", "provided": False, "basis": "caller"}


# ---------------------------------------------------------------------------
# Record normalization
# ---------------------------------------------------------------------------


def _digest_ref(value: Any, default_algorithm: str = "sha256") -> Tuple[str, Optional[str]]:
    if isinstance(value, Mapping):
        algorithm = str(value.get("algorithm", default_algorithm))
        digest = value.get("value") or value.get("digest") or value.get("hex")
        return algorithm, digest
    return default_algorithm, value


def normalize_record(data: Mapping[str, Any], source_id: str) -> Dict[str, Any]:
    segment_in = data.get("segment") or data.get("target") or data.get("original_segment") or {}
    if not isinstance(segment_in, Mapping):
        segment_in = {"sha256": segment_in}

    algorithm, expected_digest = _digest_ref(
        segment_in.get("digest")
        or segment_in.get("sha256")
        or segment_in.get("sha_256")
        or segment_in.get("hash"),
        str(segment_in.get("algorithm", "sha256")),
    )
    start = segment_in.get("start", segment_in.get("offset", 0))
    end = segment_in.get("end")
    length = segment_in.get("length")
    if end is None and length is not None:
        end = int(start) + int(length)

    predecessor_in = data.get("predecessor") or data.get("previous_receipt") or data.get("prior_receipt")
    predecessor: Optional[Dict[str, Any]] = None
    if isinstance(predecessor_in, Mapping):
        pred_alg, pred_token_digest = _digest_ref(
            predecessor_in.get("token_digest")
            or predecessor_in.get("token_sha256")
            or predecessor_in.get("digest"),
            str(predecessor_in.get("algorithm", "sha256")),
        )
        _response_alg, response_digest = _digest_ref(
            predecessor_in.get("response_digest")
            or predecessor_in.get("response_sha256"),
            pred_alg,
        )
        predecessor = {
            "receipt_id": predecessor_in.get("receipt_id") or predecessor_in.get("id"),
            "record_id": predecessor_in.get("record_id"),
            "sequence": predecessor_in.get("sequence"),
            "after_receipt_id": predecessor_in.get("after_receipt_id"),
            "algorithm": pred_alg,
            "token_digest": pred_token_digest,
            "response_digest": response_digest,
        }

    return {
        "schema": data.get("schema"),
        "record_id": data.get("record_id") or data.get("id"),
        "receipt_id": data.get("receipt_id"),
        "sequence": data.get("sequence"),
        "created_at": data.get("created_at") or data.get("signed_at"),
        "source_id": source_id,
        "segment": {
            "source": segment_in.get("source") or segment_in.get("material_id") or segment_in.get("file"),
            "start": int(start or 0),
            "end": int(end) if end is not None else None,
            "algorithm": algorithm,
            "expected_digest": expected_digest.lower() if isinstance(expected_digest, str) else None,
            "kind": segment_in.get("kind"),
        },
        "predecessor": predecessor,
        "raw": dict(data),
    }


def is_archive_record_object(data: Any) -> bool:
    return (
        isinstance(data, Mapping)
        and (
            str(data.get("schema", "")).startswith("archive-commitment-record")
            or ("record_id" in data and ("segment" in data or "target" in data))
        )
    )


# ---------------------------------------------------------------------------
# CMS inspection
# ---------------------------------------------------------------------------


def _attr_value_bytes(attr: Any) -> Optional[bytes]:
    values = attr.get("values") if hasattr(attr, "get") else None
    try:
        if values is not None and len(values):
            value = values[0]
            native = value.native
            if isinstance(native, bytes):
                return native
    except Exception:
        pass
    return None


def cms_digest_commitments(
    signed_data: Any,
    der: bytes,
    source_id: str,
    econtent_range: Optional[ByteRange],
) -> List[Dict[str, Any]]:
    commitments: List[Dict[str, Any]] = []
    signer_infos = signed_data["signer_infos"]
    for signer_index, signer_info in enumerate(signer_infos):
        algorithm = signer_info["digest_algorithm"]["algorithm"].native
        claimed: Optional[bytes] = None
        attr_type: Optional[str] = None
        try:
            signed_attrs = signer_info["signed_attrs"]
        except Exception:
            signed_attrs = []
        for attr in signed_attrs:
            oid = attr["type"].dotted
            native_name = attr["type"].native
            if oid == "1.2.840.113549.1.9.4" or native_name == "message_digest":
                claimed = _attr_value_bytes(attr)
                attr_type = native_name or oid
                break

        actual: Optional[bytes] = None
        verified = False
        if econtent_range is not None:
            actual = digest_bytes(der[econtent_range.start:econtent_range.end], algorithm)
            verified = constant_time_equals(claimed, actual)

        commitments.append(
            {
                "kind": "cms_message_digest",
                "signer_index": signer_index,
                "attribute": attr_type,
                "algorithm": algorithm,
                "claimed_digest": claimed.hex() if claimed else None,
                "actual_digest": actual.hex() if actual else None,
                "verified": verified,
                "byte_range": econtent_range.to_dict() if econtent_range else None,
                "signature_verification": "delegated_to_caller",
            }
        )
    return commitments


def inspect_original_cms(data: bytes, source_id: str, base_offset: int = 0) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "is_cms": False,
        "source": source_id,
        "base_offset": base_offset,
        "content_type": None,
        "encap_content_type": None,
        "signer_count": 0,
        "message_digests": [],
        "message_digest_verified": None,
        "error": None,
    }
    try:
        content_info = cms.ContentInfo.load(data)
        result["is_cms"] = True
        result["content_type"] = content_info["content_type"].native
        signed_data = content_info["content"]
        encap = signed_data["encap_content_info"]
        result["encap_content_type"] = encap["content_type"].native
        result["signer_count"] = len(signed_data["signer_infos"])

        local_octet = cms_econtent_tlv(data)
        global_range: Optional[ByteRange] = None
        if local_octet is not None:
            global_range = ByteRange(
                source_id,
                base_offset + local_octet.content_start,
                base_offset + local_octet.content_end,
                "cms_econtent",
                "raw",
            )
        # cms_digest_commitments expects ranges relative to `data`; build a
        # local range then shift its serialized form after calculation.
        local_range: Optional[ByteRange] = None
        if local_octet is not None:
            local_range = ByteRange(
                source_id,
                local_octet.content_start,
                local_octet.content_end,
                "cms_econtent",
                "raw",
            )
        commitments = cms_digest_commitments(signed_data, data, source_id, local_range)
        for commitment in commitments:
            if commitment.get("byte_range") and global_range is not None:
                commitment["byte_range"] = global_range.to_dict()
        result["message_digests"] = commitments
        result["message_digest_verified"] = all(
            item["verified"] for item in commitments
        ) if commitments else None
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    return result


# ---------------------------------------------------------------------------
# Timestamp receipt parsing
# ---------------------------------------------------------------------------


def classify_timestamp(der: bytes) -> Optional[Tuple[str, Any, Any]]:
    try:
        response = tsp.TimeStampResp.load(der)
        token = response["time_stamp_token"]
        encap = token["content"]["encap_content_info"]
        if encap["content_type"].native == "tst_info":
            return "time_stamp_response", response, token
    except Exception:
        pass
    try:
        token = cms.ContentInfo.load(der)
        if token["content_type"].native == "signed_data":
            encap = token["content"]["encap_content_info"]
            if encap["content_type"].native == "tst_info":
                return "timestamp_token_content_info", None, token
    except Exception:
        pass
    return None


def logical_receipt_id(source_id: str, record: Optional[Mapping[str, Any]] = None) -> str:
    if record and record.get("receipt_id"):
        return str(record["receipt_id"])
    if record and record.get("record_id") and str(record["record_id"]).startswith("receipt-"):
        return str(record["record_id"])
    name = Path(source_id).name
    for part in name.split("/")[-1:]:
        if part.startswith("receipt-"):
            digits = "receipt-" + part.split("receipt-", 1)[1].split(".", 1)[0]
            if digits != "receipt-":
                return digits
    return name.split(".", 1)[0]


def parse_timestamp_receipt(
    material: Material,
    index: RangeIndex,
    trust: Any,
) -> Optional[Dict[str, Any]]:
    classified = classify_timestamp(material.der)
    if classified is None:
        return None
    outer_kind, response, token_ci = classified
    der = material.der
    roots = parse_tlv_roots(der)
    root = roots[0]

    if outer_kind == "time_stamp_response":
        token_node = root.children[1]
    else:
        token_node = root

    token_range = index.add(
        material.source_id,
        token_node.start,
        token_node.end,
        "timestamp_token",
        "der",
    )
    octet_node = cms_econtent_tlv(der, token_node)
    tst_range: Optional[ByteRange] = None
    if octet_node is not None:
        tst_range = index.add(
            material.source_id,
            octet_node.content_start,
            octet_node.content_end,
            "tst_info_econtent",
            "der",
        )

    signed_data = token_ci["content"]
    cms_commitments = cms_digest_commitments(
        signed_data,
        der,
        material.source_id,
        tst_range,
    )

    encap = signed_data["encap_content_info"]
    tst_info_object = encap["content"]
    parsed_tst = getattr(tst_info_object, "parsed", None)
    if parsed_tst is None:
        parsed_tst = tsp.TSTInfo.load(tst_info_object.native)

    imprint_algorithm = parsed_tst["message_imprint"]["hash_algorithm"]["algorithm"].native
    imprint_digest = parsed_tst["message_imprint"]["hashed_message"].native
    if isinstance(imprint_digest, bytes):
        imprint_hex = imprint_digest.hex()
    else:
        imprint_hex = bytes(imprint_digest).hex()

    serial = parsed_tst["serial_number"].native
    if hasattr(serial, "__int__"):
        try:
            serial = int(serial)
        except Exception:
            serial = str(serial)

    source_trust = resolve_trust(trust, material.source_id)
    outer_digest = hex_digest(material.raw, "sha256")
    der_digest = hex_digest(material.der, "sha256")
    token_bytes = der[token_range.start:token_range.end]
    token_digest = hashlib.sha256(token_bytes).hexdigest()
    tst_digest = (
        hashlib.sha256(der[tst_range.start:tst_range.end]).hexdigest()
        if tst_range is not None
        else None
    )

    return {
        "receipt_id": logical_receipt_id(material.source_id),
        "source_id": material.source_id,
        "source_file": Path(material.source_id).name,
        "outer_kind": outer_kind,
        "encoding": material.encoding,
        "pem_label": material.pem_label,
        "gen_time": iso_time(parsed_tst["gen_time"].native),
        "serial_number": str(serial),
        "policy": parsed_tst["policy"].dotted,
        "imprint_algorithm": imprint_algorithm,
        "imprint_digest": imprint_hex,
        "outer_sha256": outer_digest,
        "der_sha256": der_digest,
        "token_sha256": token_digest,
        "tst_info_sha256": tst_digest,
        "token_range": token_range.to_dict(),
        "tst_info_range": tst_range.to_dict() if tst_range else None,
        "cms_commitments": cms_commitments,
        "cms_digest_verified": all(item["verified"] for item in cms_commitments),
        "imprint_commitment": {
            "kind": "timestamp_message_imprint",
            "algorithm": imprint_algorithm,
            "claimed_digest": imprint_hex,
            "verified": False,
            "byte_range": None,
            "matching_ranges": [],
            "signature_verification": "delegated_to_caller",
        },
        "trust": source_trust,
        "record": None,
        "predecessor": None,
        "packaging": None,
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Case analysis and timeline construction
# ---------------------------------------------------------------------------
 

def _public_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    result = dict(record)
    result.pop("raw", None)
    return result


def analyze_materials(
    materials: Mapping[str, Union[bytes, str, Path]],
    trust: Any = None,
    case_name: Optional[str] = None,
) -> Dict[str, Any]:
    store = MaterialStore()
    index = RangeIndex()
    errors: List[Dict[str, str]] = []
    records: List[Dict[str, Any]] = []
    record_by_source: Dict[str, Dict[str, Any]] = {}

    for source_id, value in sorted(materials.items()):
        try:
            if isinstance(value, (str, Path)) and not isinstance(value, bytes):
                raw = Path(value).read_bytes()
            else:
                raw = bytes(value)
            material = store.add(source_id, raw)
            index.add(source_id, 0, len(raw), "file", "raw")
            if material.encoding == "pem":
                index.add(source_id, 0, len(material.der), "decoded_der", "der")

            try:
                parsed_json = json.loads(raw.decode("utf-8"))
            except Exception:
                parsed_json = None
            if is_archive_record_object(parsed_json):
                record = normalize_record(parsed_json, source_id)
                records.append(record)
                record_by_source[source_id] = record
                index.add(
                    source_id,
                    0,
                    len(raw),
                    "archive_record",
                    "raw",
                    record_id=record.get("record_id"),
                )
        except Exception as exc:
            errors.append({"source": source_id, "error": "%s: %s" % (type(exc).__name__, exc)})

    # Verify explicit segment ranges and inspect embedded CMS material.
    for record in records:
        segment = record["segment"]
        source_material = store.resolve_source(segment["source"])
        segment["byte_range"] = None
        segment["verified"] = False
        segment["actual_digest"] = None
        segment["cms"] = None
        segment["error"] = None
        if source_material is None or segment["end"] is None:
            segment["error"] = "segment source or end is missing"
            continue
        source_id = source_material.source_id
        item = index.add(
            source_id,
            segment["start"],
            segment["end"],
            "original_signed_segment",
            "raw",
            record_id=record.get("record_id"),
        )
        segment["byte_range"] = item.to_dict()
        try:
            actual = hex_digest(store.range_bytes(item), segment["algorithm"])
            segment["actual_digest"] = actual
            segment["verified"] = constant_time_equals(
                segment["expected_digest"].encode() if segment["expected_digest"] else None,
                actual.encode(),
            )
            segment_bytes = store.range_bytes(item)
            if segment_bytes[:1] == b"0":
                segment["cms"] = inspect_original_cms(segment_bytes, source_id, item.start)
        except Exception as exc:
            segment["error"] = "%s: %s" % (type(exc).__name__, exc)

    receipts: List[Dict[str, Any]] = []
    for material in store.materials.values():
        try:
            receipt = parse_timestamp_receipt(material, index, trust)
            if receipt is not None:
                receipts.append(receipt)
        except Exception as exc:
            errors.append(
                {
                    "source": material.source_id,
                    "error": "timestamp parse failed: %s: %s" % (type(exc).__name__, exc),
                }
            )

    # Resolve timestamp message imprints to exact archive-record byte ranges.
    for receipt in receipts:
        imprint = receipt["imprint_commitment"]
        matches = index.find_digest(
            imprint["algorithm"],
            imprint["claimed_digest"],
            store,
        )
        archive_matches = [item for item in matches if item.role == "archive_record"]
        chosen_matches = archive_matches or [item for item in matches if item.role == "file"]
        imprint["matching_ranges"] = [item.to_dict() for item in chosen_matches]
        if chosen_matches:
            chosen = chosen_matches[0]
            imprint["verified"] = True
            imprint["byte_range"] = chosen.to_dict()
            record = record_by_source.get(chosen.source)
            if record is not None:
                receipt["record"] = _public_record(record)
                receipt["receipt_id"] = logical_receipt_id(receipt["source_id"], record)
                receipt["trust"] = resolve_trust(
                    trust,
                    receipt["source_id"],
                    receipt["receipt_id"],
                    record.get("record_id"),
                )
        else:
            imprint["error"] = "no supplied byte range matches message imprint"

    receipts_by_token = {item["token_sha256"]: item for item in receipts}

    # Resolve predecessor digest commitments.
    for receipt in receipts:
        record = next(
            (item for item in records if item.get("record_id") == (receipt.get("record") or {}).get("record_id")),
            None,
        )
        if record is None:
            continue
        predecessor_ref = record.get("predecessor")
        if not predecessor_ref or not predecessor_ref.get("token_digest"):
            receipt["predecessor"] = {
                "kind": "genesis",
                "verified": True,
                "receipt_id": None,
                "byte_range": None,
            }
            continue

        expected_token = predecessor_ref["token_digest"].lower().replace(":", "")
        matched = receipts_by_token.get(expected_token)
        response_match = None
        if predecessor_ref.get("response_digest"):
            expected_response = predecessor_ref["response_digest"].lower().replace(":", "")
            for material in store.materials.values():
                if hex_digest(material.raw, "sha256") == expected_response:
                    response_match = material.source_id
                    break
                if hex_digest(material.der, "sha256") == expected_response:
                    response_match = material.source_id + "#der"
                    break

        predecessor_info: Dict[str, Any] = {
            "kind": "predecessor_receipt_digest",
            "expected_receipt_id": predecessor_ref.get("receipt_id"),
            "expected_record_id": predecessor_ref.get("record_id"),
            "expected_sequence": predecessor_ref.get("sequence"),
            "algorithm": predecessor_ref.get("algorithm", "sha256"),
            "expected_token_digest": expected_token,
            "expected_response_digest": predecessor_ref.get("response_digest"),
            "response_package_found": response_match,
            "verified": matched is not None,
            "matched_receipt_id": matched["receipt_id"] if matched else None,
            "matched_source_id": matched["source_id"] if matched else None,
            "byte_range": matched["token_range"] if matched else None,
            "outer_package_changed": bool(
                predecessor_ref.get("response_digest")
                and response_match is None
                and matched is not None
            ),
        }
        if matched is None and predecessor_ref.get("receipt_id"):
            candidate = next(
                (
                    item
                    for item in receipts
                    if item["receipt_id"] == predecessor_ref["receipt_id"]
                    or item["source_file"] == Path(str(predecessor_ref["receipt_id"])).name
                ),
                None,
            )
            if candidate is not None:
                predecessor_info["replacement_candidate"] = {
                    "receipt_id": candidate["receipt_id"],
                    "source_id": candidate["source_id"],
                    "token_sha256": candidate["token_sha256"],
                    "gen_time": candidate["gen_time"],
                }
        receipt["predecessor"] = predecessor_info

    # Group outer packaging variants around the same token/TST commitment.
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for receipt in receipts:
        groups.setdefault(receipt["token_sha256"], []).append(receipt)

    canonical: List[Dict[str, Any]] = []
    package_order = {"time_stamp_response": 0, "timestamp_token_content_info": 1}
    for token_digest, variants in groups.items():
        ordered = sorted(
            variants,
            key=lambda item: (
                package_order.get(item["outer_kind"], 9),
                0 if item["encoding"] == "der" else 1,
                item["source_id"],
            ),
        )
        primary = copy.deepcopy(ordered[0])
        outer_packages = sorted({item["outer_sha256"] for item in variants})
        outer_kinds = sorted({item["outer_kind"] for item in variants})
        commitment_intact = all(item["cms_digest_verified"] for item in variants) and all(
            item["imprint_commitment"]["verified"] for item in variants
        )
        primary["packaging"] = {
            "token_sha256": token_digest,
            "variant_count": len(variants),
            "outer_packaging_changed": len(outer_packages) > 1 or len(outer_kinds) > 1,
            "outer_package_count": len(outer_packages),
            "outer_kinds": outer_kinds,
            "commitment_still_verifiable": commitment_intact,
            "packaging_change_with_commitment_intact": (
                (len(outer_packages) > 1 or len(outer_kinds) > 1) and commitment_intact
            ),
            "variants": [
                {
                    "source_id": item["source_id"],
                    "outer_kind": item["outer_kind"],
                    "encoding": item["encoding"],
                    "outer_sha256": item["outer_sha256"],
                    "trust": item["trust"],
                }
                for item in ordered
            ],
        }
        canonical.append(primary)

    canonical_by_token = {item["token_sha256"]: item for item in canonical}

    for node in canonical:
        record = node.get("record")
        segment = (record or {}).get("segment") or {}
        cms_ok = bool(node["cms_commitments"]) and node["cms_digest_verified"]
        imprint_ok = bool(node["imprint_commitment"]["verified"])
        segment_ok = bool(segment.get("verified"))
        original_cms = segment.get("cms") or {}
        if original_cms.get("is_cms") and original_cms.get("message_digest_verified") is False:
            segment_ok = False
        trust_verdict = node.get("trust", {}).get("verdict")
        node["proof"] = {
            "cms_digest_verified": cms_ok,
            "imprint_verified": imprint_ok,
            "segment_verified": segment_ok,
            "signature_trusted_by_caller": trust_verdict == "trusted",
            "trust_verdict": trust_verdict,
            "self_verifiable": cms_ok and imprint_ok and segment_ok,
            "self_provable": cms_ok and imprint_ok and segment_ok and trust_verdict == "trusted",
        }

    def sort_key(node: Dict[str, Any]) -> Tuple[int, int, str]:
        record = node.get("record") or {}
        sequence = record.get("sequence")
        if isinstance(sequence, int):
            return (0, sequence, node.get("gen_time") or "")
        return (1, 10**9, node.get("gen_time") or node["source_id"])

    canonical.sort(key=sort_key)

    # Recompute predecessor links against canonical packaging nodes.
    gaps: List[Dict[str, Any]] = []
    for node in canonical:
        record = node.get("record")
        if not record:
            node["chain"] = {
                "expected_predecessor": None,
                "status": "uncommitted_receipt",
                "note": "Receipt parses, but no supplied archive record matches its imprint.",
            }
            continue
        predecessor_ref = record.get("predecessor")
        if not predecessor_ref:
            node["chain"] = {"status": "genesis", "predecessor_id": None}
            continue
        expected_token = predecessor_ref["token_digest"]
        predecessor_node = canonical_by_token.get(expected_token)
        base_chain = node.get("predecessor") or {}
        if predecessor_node is None:
            gap = {
                "type": "missing_predecessor_receipt",
                "missing_sequence": predecessor_ref.get("sequence"),
                "missing_record_id": predecessor_ref.get("record_id"),
                "missing_receipt_id": predecessor_ref.get("receipt_id"),
                "expected_token_sha256": expected_token,
                "expected_response_sha256": predecessor_ref.get("response_digest"),
                "after_receipt_id": predecessor_ref.get("after_receipt_id"),
                "before_receipt_id": node["receipt_id"],
                "known_from": "protected predecessor digest in " + node["source_id"],
                "content_reconstructable": False,
                "replacement_candidate": base_chain.get("replacement_candidate"),
                "message": (
                    "Later receipt %s attests to predecessor %s with token digest %s, "
                    "but that exact receipt byte range was not supplied. No original "
                    "segment is reconstructed from the digest."
                    % (node["receipt_id"], predecessor_ref.get("receipt_id"), expected_token[:16])
                ),
            }
            gaps.append(gap)
            node["chain"] = {
                "status": "predecessor_missing",
                "expected": predecessor_ref,
                "gap": gap,
            }
        else:
            predecessor_proof = predecessor_node.get("proof", {})
            predecessor_provable = bool(predecessor_proof.get("self_provable"))
            chain_status = "linked" if predecessor_provable else "predecessor_history_unprovable"
            node["chain"] = {
                "status": chain_status,
                "predecessor_id": predecessor_node["receipt_id"],
                "predecessor_source_id": predecessor_node["source_id"],
                "token_digest_verified": True,
                "predecessor_self_provable": predecessor_provable,
                "byte_range": base_chain.get("byte_range"),
                "outer_package_changed": base_chain.get("outer_package_changed"),
            }
            if not predecessor_provable:
                pred_record = predecessor_node.get("record") or {}
                gap = {
                    "type": "missing_provable_history",
                    "missing_sequence": predecessor_ref.get("sequence", pred_record.get("sequence")),
                    "missing_record_id": predecessor_ref.get("record_id", pred_record.get("record_id")),
                    "missing_receipt_id": predecessor_node["receipt_id"],
                    "expected_token_sha256": expected_token,
                    "present_source_id": predecessor_node["source_id"],
                    "reason": (
                        "predecessor receipt bytes match, but its imprinted archive "
                        "record/segment cannot be verified"
                    ),
                    "before_receipt_id": node["receipt_id"],
                    "known_from": "token link from " + node["source_id"],
                    "content_reconstructable": False,
                    "message": (
                        "Receipt %s is present and linked, but its own committed bytes "
                        "do not verify; the provable history at this position is missing."
                        % predecessor_node["receipt_id"]
                    ),
                }
                if predecessor_node.get("imprint_commitment", {}).get("verified") is False:
                    gap["reason"] = "timestamp imprint does not match the supplied record bytes"
                gaps.append(gap)

    # Build maximal self-provable runs. A later node may start a run after a
    # missing middle history; we never extend backwards through a gap.
    provable_runs: List[List[str]] = []
    current_run: List[str] = []
    previous_node: Optional[Dict[str, Any]] = None
    for node in canonical:
        proof = node.get("proof", {})
        chain = node.get("chain", {})
        can_attach = False
        if proof.get("self_provable"):
            if previous_node is not None and current_run:
                predecessor_id = chain.get("predecessor_id")
                can_attach = (
                    chain.get("status") == "linked"
                    and predecessor_id == previous_node["receipt_id"]
                    and bool(previous_node.get("proof", {}).get("self_provable"))
                )
            if can_attach:
                current_run.append(node["receipt_id"])
            else:
                if current_run:
                    provable_runs.append(current_run)
                current_run = [node["receipt_id"]]
        elif current_run:
            provable_runs.append(current_run)
            current_run = []
        previous_node = node
    if current_run:
        provable_runs.append(current_run)

    packaging_changes = [
        {
            "receipt_id": node["receipt_id"],
            **(node.get("packaging") or {}),
        }
        for node in canonical
        if (node.get("packaging") or {}).get("packaging_change_with_commitment_intact")
    ]

    verified_segment_count = sum(
        1 for record in records if record.get("segment", {}).get("verified")
    )
    summary = {
        "case_name": case_name,
        "material_count": len(materials),
        "archive_record_count": len(records),
        "receipt_group_count": len(canonical),
        "receipt_variant_count": len(receipts),
        "verified_segment_count": verified_segment_count,
        "provable_runs": provable_runs,
        "gap_count": len(gaps),
        "packaging_change_count": len(packaging_changes),
        "has_complete_chain": len(provable_runs) == 1
        and len(gaps) == 0
        and bool(canonical)
        and len(provable_runs[0]) == len(
            [node for node in canonical if node.get("proof", {}).get("self_provable")]
        ),
    }
    summary["conclusion"] = conclude_timeline(summary, gaps, provable_runs)

    return {
        "schema": "archive-receipt-timeline/v1",
        "summary": summary,
        "receipts": canonical,
        "gaps": gaps,
        "provable_runs": provable_runs,
        "packaging_changes": packaging_changes,
        "records": [_public_record(record) for record in records],
        "parse_errors": errors,
    }


def conclude_timeline(
    summary: Mapping[str, Any],
    gaps: Sequence[Mapping[str, Any]],
    runs: Sequence[Sequence[str]],
) -> str:
    if not summary.get("receipt_group_count"):
        return "没有解析到 CMS 或时间回执。"
    if not gaps and len(runs) == 1:
        return "三段以内的摘要承诺、字节范围和前置回执均已连通；外包装变化不影响原承诺核对。"
    if gaps:
        descriptions = []
        for gap in gaps:
            sequence = gap.get("missing_sequence")
            label = gap.get("missing_record_id") or gap.get("missing_receipt_id") or "未知记录"
            if sequence is not None:
                descriptions.append("第 %s 段（%s）" % (sequence, label))
            else:
                descriptions.append(str(label))
        return (
            "时间表存在 %d 个断点：缺少 %s。只能证明当前可连通的后段 %s；"
            "摘要不用于倒推缺失原件。"
            % (len(gaps), "、".join(descriptions), " / ".join("→".join(run) for run in runs) or "无")
        )
    return "时间表未完全连通；可证段为 %s。" % (" / ".join("→".join(run) for run in runs) or "无")


def analyze_directory(
    directory: Union[str, Path],
    trust: Any = None,
) -> Dict[str, Any]:
    root = Path(directory)
    trust_value = trust
    trust_path = root / "trust.json"
    if trust_value is None and trust_path.exists():
        trust_value = json.loads(trust_path.read_text(encoding="utf-8"))
    materials: Dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {".DS_Store", "trust.json", "timeline.json", "timeline.txt", "analysis.json"}:
            continue
        materials[path.relative_to(root).as_posix()] = path.read_bytes()
    return analyze_materials(materials, trust_value, case_name=root.name)


def analyze_case(case: Any, trust: Any = None) -> Dict[str, Any]:
    if isinstance(case, (str, Path)):
        path = Path(case)
        if path.is_dir():
            return analyze_directory(path, trust)
        return analyze_materials({path.name: path.read_bytes()}, trust, case_name=path.name)
    if isinstance(case, Mapping):
        return analyze_materials(case, trust)
    raise TypeError("case must be a directory path or mapping of source id to bytes")


# ---------------------------------------------------------------------------
# Text rendering and CLI
# ---------------------------------------------------------------------------


def render_timeline(result: Mapping[str, Any]) -> str:
    lines: List[str] = []
    summary = result["summary"]
    lines.append("档案回执时间表：%s" % summary.get("case_name") or "case")
    lines.append("=" * 72)
    for node in result.get("receipts", []):
        record = node.get("record") or {}
        segment = record.get("segment") or {}
        proof = node.get("proof", {})
        sequence = record.get("sequence", "?")
        lines.append("")
        lines.append(
            "[%s] seq=%s time=%s serial=%s"
            % (node["receipt_id"], sequence, node.get("gen_time"), node.get("serial_number"))
        )
        if segment.get("byte_range"):
            br = segment["byte_range"]
            lines.append(
                "  原签名段: %s:%d-%d (%d bytes) digest=%s verified=%s"
                % (
                    br["source"],
                    br["start"],
                    br["end"],
                    br["length"],
                    (segment.get("actual_digest") or "未算出")[:16],
                    segment.get("verified"),
                )
            )
        else:
            lines.append("  原签名段: 未定位（%s）" % segment.get("error", "缺少记录或范围"))
        imprint = node.get("imprint_commitment") or {}
        lines.append(
            "  时间摘要: %s:%s verified=%s range=%s"
            % (
                imprint.get("algorithm"),
                (imprint.get("claimed_digest") or "")[:16],
                imprint.get("verified"),
                (imprint.get("byte_range") or {}).get("source") if imprint.get("byte_range") else None,
            )
        )
        chain = node.get("chain") or {}
        if chain.get("status") == "genesis":
            lines.append("  前置回执: 创世记录，无前置回执")
        elif chain.get("predecessor_id"):
            lines.append(
                "  前置回执: %s token匹配=%s status=%s"
                % (chain.get("predecessor_id"), chain.get("token_digest_verified"), chain.get("status"))
            )
        else:
            expected = chain.get("expected") or {}
            lines.append(
                "  前置回执: 缺失 %s expected_token=%s..."
                % (expected.get("receipt_id"), str(expected.get("token_digest"))[:16])
            )
        packaging = node.get("packaging") or {}
        if packaging.get("outer_packaging_changed"):
            lines.append(
                "  外包装: 已变化但原承诺可核对=%s variants=%d kinds=%s"
                % (
                    packaging.get("packaging_change_with_commitment_intact"),
                    packaging.get("variant_count"),
                    ",".join(packaging.get("outer_kinds") or []),
                )
            )
        lines.append(
            "  结论: self_provable=%s trust=%s cms=%s imprint=%s segment=%s"
            % (
                proof.get("self_provable"),
                proof.get("trust_verdict"),
                proof.get("cms_digest_verified"),
                proof.get("imprint_verified"),
                proof.get("segment_verified"),
            )
        )

    if result.get("gaps"):
        lines.append("")
        lines.append("断点 / 缺失可证历史")
        lines.append("-" * 72)
        for gap in result["gaps"]:
            lines.append(
                "- seq=%s record=%s receipt=%s type=%s"
                % (
                    gap.get("missing_sequence"),
                    gap.get("missing_record_id"),
                    gap.get("missing_receipt_id"),
                    gap.get("type"),
                )
            )
            lines.append("  " + gap.get("message", ""))
            candidate = gap.get("replacement_candidate")
            if candidate:
                lines.append("  发现同标识替换件: %s %s" % (candidate.get("source_id"), candidate.get("token_sha256", "")[:16]))

    lines.append("")
    lines.append("可证连续段: " + (" ; ".join(" -> ".join(run) for run in result.get("provable_runs", [])) or "无"))
    lines.append("结论: " + summary.get("conclusion", ""))
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze archive CMS/timestamp receipt chains.")
    parser.add_argument("case_dir", help="Directory containing receipts, records, and materials")
    parser.add_argument("--trust", help="JSON file with caller-supplied signature trust decisions")
    parser.add_argument("--json-output", help="Write full JSON timeline to this path")
    parser.add_argument("--check", action="store_true", help="Exit 2 if gaps or unverified nodes exist")
    args = parser.parse_args(argv)

    trust = None
    if args.trust:
        trust = json.loads(Path(args.trust).read_text(encoding="utf-8"))
    result = analyze_directory(args.case_dir, trust)
    print(render_timeline(result))
    if args.json_output:
        Path(args.json_output).write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=False),
            encoding="utf-8",
        )
    if args.check and (result["summary"]["gap_count"] or not result["summary"]["has_complete_chain"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
