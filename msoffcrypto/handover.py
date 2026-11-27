"""Receiving check (接收核对) for protected document handover between warehouses.

Two warehouses share protected Office documents, but each receiving domain may
retain a different set of fields.  This module hooks into the format entry
point :func:`msoffcrypto.OfficeFile` and builds a *receiving slip* (接收单) per
document and domain.  A slip separates:

* the public protection metadata the tool can see without decrypting
  (公开保护资料),
* the fields the receiving domain is allowed to keep (可以交付的字段),
* the sign-off state an auditor still has to complete (审核员仍需补签的状态).

The same file handed to different domains gets different field permissions;
the preservation identifier (保全标识, a SHA-256 digest of the source bytes)
proves that both slips describe the identical source document.  When a domain
policy marks a field as required but does not permit retaining it, the slip is
explicitly suspended (挂起) until an auditor countersigns it.

Examples:
    >>> from msoffcrypto.handover import DomainPolicy, build_receiving_slip
    >>> policy_a = DomainPolicy(
    ...     domain="vault-a",
    ...     allowed_fields={"format", "encrypted", "encryption_type"},
    ...     required_fields={"encryption_type"},
    ... )
    >>> slip_a = build_receiving_slip("tests/inputs/example_password.xlsx", policy_a)
    >>> slip_a.status
    'RECEIVED'
    >>> slip_a.preservation_id.startswith("sha256:")
    True

    >>> policy_b = DomainPolicy(
    ...     domain="vault-b",
    ...     allowed_fields={"format"},
    ...     required_fields={"password_salt"},
    ... )
    >>> slip_b = build_receiving_slip("tests/inputs/example_password.xlsx", policy_b)
    >>> slip_b.status
    'SUSPENDED'
    >>> slip_b.missing_required_fields
    ['password_salt']
    >>> slip_b.preservation_id == slip_a.preservation_id
    True
"""

import base64
import hashlib
import io
import logging
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional

from msoffcrypto import OfficeFile

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

#: Handover accepted; every required field is deliverable.
STATUS_RECEIVED = "RECEIVED"
#: Handover suspended; a required field is restricted and an auditor must countersign.
STATUS_SUSPENDED = "SUSPENDED"
#: A suspended handover released by an auditor's countersignature.
STATUS_RELEASED = "RELEASED"


def _to_snake_case(name):
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", str(name))
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _encode_value(value):
    if isinstance(value, bytes):
        return "base64:" + base64.b64encode(value).decode("ascii")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _flatten_info(info, prefix=""):
    for key, value in info.items():
        name = prefix + _to_snake_case(key)
        if isinstance(value, dict):
            yield from _flatten_info(value, prefix=name + "_")
        else:
            yield name, _encode_value(value)


def inspect_protection(file):
    """Collect the public protection metadata of a document.

    Args:
        file: Path or binary file-like object of the document.

    Returns:
        dict: Field name to JSON-safe value, as visible to the tool without
        decrypting the document.
    """
    if hasattr(file, "read"):
        officefile = OfficeFile(file)
    else:
        with open(file, "rb") as f:
            officefile = OfficeFile(f)
    fields = {
        "format": getattr(officefile, "format", None),
        "encrypted": bool(officefile.is_encrypted()),
        "encryption_type": getattr(officefile, "type", None),
        "key_types": sorted(getattr(officefile, "keyTypes", ()) or ()),
    }
    info = getattr(officefile, "info", None)
    if isinstance(info, dict):
        for name, value in _flatten_info(info):
            fields[name] = value
    return fields


@dataclass(frozen=True)
class DomainPolicy:
    """Field permission of one receiving domain (接收域字段许可).

    Args:
        domain: Name of the receiving domain (warehouse).
        allowed_fields: Field names the domain may retain; `None` means the
            domain may retain every public field.
        required_fields: Field names the domain must receive for the handover
            to be accepted.  A required field that is not allowed suspends the
            receiving slip.
    """

    domain: str
    allowed_fields: Optional[FrozenSet[str]] = None
    required_fields: FrozenSet[str] = frozenset()

    def __post_init__(self):
        if self.allowed_fields is not None:
            object.__setattr__(self, "allowed_fields", frozenset(self.allowed_fields))
        object.__setattr__(self, "required_fields", frozenset(self.required_fields))

    def permits(self, field_name):
        return self.allowed_fields is None or field_name in self.allowed_fields


@dataclass
class ReceivingSlip:
    """Receiving slip (接收单) for one document in one receiving domain."""

    preservation_id: str
    domain: str
    status: str
    public_fields: Dict[str, object]
    deliverable_fields: Dict[str, object]
    withheld_fields: List[str]
    missing_required_fields: List[str]
    auditor_signoff: Optional[Dict[str, str]] = None

    @property
    def pending_auditor_signoff(self):
        """Whether an auditor still has to countersign this slip."""
        return self.status == STATUS_SUSPENDED


def preservation_id_of(data):
    """Return the preservation identifier (保全标识) of the source bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_receiving_slip(source, policy):
    """Build a receiving slip for `source` under the given domain policy.

    Args:
        source: Path or binary file-like object of the document.
        policy (:obj:`DomainPolicy`): Field permission of the receiving domain.

    Returns:
        ReceivingSlip: The receiving slip for this document and domain.
    """
    if hasattr(source, "read"):
        data = source.read()
    else:
        with open(source, "rb") as f:
            data = f.read()
    public_fields = inspect_protection(io.BytesIO(data))

    deliverable = {}
    withheld = []
    for name in sorted(public_fields):
        if policy.permits(name):
            deliverable[name] = public_fields[name]
        else:
            withheld.append(name)

    missing_required = sorted(
        name for name in policy.required_fields if not policy.permits(name)
    )
    status = STATUS_SUSPENDED if missing_required else STATUS_RECEIVED

    slip = ReceivingSlip(
        preservation_id=preservation_id_of(data),
        domain=policy.domain,
        status=status,
        public_fields=public_fields,
        deliverable_fields=deliverable,
        withheld_fields=withheld,
        missing_required_fields=missing_required,
    )
    logger.debug("Receiving slip for %s: %s", policy.domain, status)
    return slip


def countersign(slip, auditor, note=""):
    """Record an auditor's countersignature on a suspended slip.

    Raises:
        ValueError: If the slip is not suspended.
    """
    if slip.status != STATUS_SUSPENDED:
        raise ValueError(
            "Only a suspended slip can be countersigned (status: {})".format(
                slip.status
            )
        )
    slip.auditor_signoff = {"auditor": auditor, "note": note}
    slip.status = STATUS_RELEASED
    return slip


def render_slip(slip):
    """Render a receiving slip as a human-readable receipt (接收单)."""
    status_labels = {
        STATUS_RECEIVED: "已接收（可交付）",
        STATUS_SUSPENDED: "挂起（待审核员补签）",
        STATUS_RELEASED: "已放行（审核员已补签）",
    }
    lines = [
        "接收单 / RECEIVING SLIP",
        "接收域: {}".format(slip.domain),
        "保全标识: {}".format(slip.preservation_id),
        "状态: {}".format(status_labels[slip.status]),
        "公开保护资料（工具可见）: {}".format(
            ", ".join(sorted(slip.public_fields)) or "（无）"
        ),
        "可交付字段: {}".format(", ".join(sorted(slip.deliverable_fields)) or "（无）"),
        "受限保留字段: {}".format(", ".join(slip.withheld_fields) or "（无）"),
        "缺失必填字段: {}".format(
            ", ".join(slip.missing_required_fields) or "（无）"
        ),
    ]
    if slip.auditor_signoff:
        lines.append(
            "审核员补签: {}（{}）".format(
                slip.auditor_signoff["auditor"], slip.auditor_signoff["note"] or "无备注"
            )
        )
    else:
        lines.append("审核员补签: 未签")
    return "\n".join(lines)
