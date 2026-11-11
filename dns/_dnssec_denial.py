"""Offline validation of DNSSEC denial-of-existence responses."""

from __future__ import annotations

import base64
import enum
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import NoReturn, cast

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.rdtypes.ANY.NSEC3 as nsec3module
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import dns.rdtypes.ANY.NSEC3PARAM
import dns.rdtypes.ANY.RRSIG
import dns.rrset
from dns.exception import DNSException

# RFC 5155 limits the wire field to 65535.  A much lower local limit keeps a
# hostile response from turning validation into a CPU-amplification loop.
MAX_NSEC3_ITERATIONS = 100


class DenialStatus(enum.StrEnum):
    """Authentication status for a denial-of-existence response."""

    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"


@dataclass(frozen=True)
class DenialValidationResult:
    """The result of offline denial-of-existence validation."""

    status: DenialStatus
    """Whether the denial is secure, insecure, or bogus."""
    reason: str
    """A machine-readable explanation of the validation decision."""
    proofs: tuple[dns.rrset.RRset, ...] = field(default_factory=tuple)
    """NSEC or NSEC3 RRsets used by the successful or attempted proof."""
    closest_encloser: dns.name.Name | None = None
    """The closest encloser proved by NSEC or NSEC3."""
    next_closer: dns.name.Name | None = None
    """The next closer name used by an NXDOMAIN proof."""
    wildcard: dns.name.Name | None = None
    """The wildcard owner name used by a wildcard proof."""
    wildcard_expanded: bool = False
    """Whether a wildcard was expanded to synthesize the response."""


class _Bogus(Exception):
    pass


TrustAnchor = (
    dns.rdtypes.ANY.DS.DS
    | dns.rdtypes.ANY.DNSKEY.DNSKEY
    | dns.rrset.RRset
    | Iterable[dns.rdtypes.ANY.DS.DS | dns.rdtypes.ANY.DNSKEY.DNSKEY | dns.rrset.RRset]
    | None
)
ProofKey = tuple[dns.name.Name, dns.rdatatype.RdataType, dns.rdatatype.RdataType]


def _bogus(reason: str) -> NoReturn:
    raise _Bogus(reason)


def _absolute_name(name: dns.name.Name | str) -> dns.name.Name:
    if isinstance(name, str):
        name = dns.name.from_text(name)
    if not name.is_absolute():
        _bogus("relative DNS name")
    return name


def _bitmap_has_type(
    windows: tuple[tuple[int, bytes], ...], rdtype: dns.rdatatype.RdataType
) -> bool:
    window = int(rdtype) // 256
    byte = int(rdtype) % 256 // 8
    bit = int(rdtype) % 8
    for candidate_window, bitmap in windows:
        if candidate_window == window and byte < len(bitmap):
            return bool(bitmap[byte] & (0x80 >> bit))
    return False


def _hash_name(name: dns.name.Name, salt: bytes, iterations: int) -> bytes:
    encoded = base64.b32hexdecode(
        dns.dnssec.nsec3_hash(name, salt, iterations, 1).encode("ascii")
    )
    return encoded


def _owner_hash(name: dns.name.Name, apex: dns.name.Name) -> bytes:
    if not name.is_subdomain(apex) or name == apex:
        _bogus("NSEC3 owner name is not a hashed name below the apex")
    labels = name.relativize(apex).labels
    if len(labels) != 1:
        _bogus("NSEC3 owner name has labels below the hashed owner name")
    try:
        hash_value = base64.b32hexdecode(labels[0].upper())
    except ValueError:
        _bogus("malformed NSEC3 owner hash")
    if len(hash_value) != 20:
        _bogus("malformed NSEC3 owner hash length")
    return hash_value


def _wildcard_for(name: dns.name.Name, parent: dns.name.Name) -> dns.name.Name:
    return dns.name.from_text("*", parent) if parent != name else name


def _suffix(name: dns.name.Name, labels: int) -> dns.name.Name:
    return name.split(labels)[1]


def _in_nsec_interval(
    name: dns.name.Name,
    owner: dns.name.Name,
    next_name: dns.name.Name,
    apex: dns.name.Name,
) -> bool:
    if not name.is_subdomain(apex):
        return False
    if owner == next_name:
        return owner == apex and name != apex
    if owner < next_name:
        return owner < name < next_name
    return name > owner or name < next_name


class _Validator:
    def __init__(
        self,
        qname: dns.name.Name | str,
        qtype: dns.rdatatype.RdataType | str,
        apex: dns.name.Name | str,
        trust_anchor: TrustAnchor,
        rrsets: Iterable[dns.rrset.RRset],
        rcode: int | str | None,
        now: float | None,
    ):
        self.qname = _absolute_name(qname)
        self.qtype = dns.rdatatype.RdataType.make(qtype)
        self.apex = _absolute_name(apex)
        self.now = now
        self.index: dict[ProofKey, dns.rrset.RRset] = {}
        self.keys: dict[dns.name.Name, dns.rrset.RRset] = {}
        self.trusted_ds: list[dns.rdtypes.ANY.DS.DS] = []
        self.trusted_dnskeys: list[dns.rdtypes.ANY.DNSKEY.DNSKEY] = []
        self.proof_sets: list[dns.rrset.RRset] = []
        self.closest_encloser: dns.name.Name | None = None
        self.next_closer: dns.name.Name | None = None
        self.wildcard: dns.name.Name | None = None
        self.wildcard_expanded = False

        if not self.qname.is_subdomain(self.apex):
            _bogus("qname is not below the zone apex")
        if self.qtype == dns.rdatatype.RRSIG:
            _bogus("RRSIG is not a query type")

        for rrset in rrsets:
            self._index_rrset(rrset)

        self._load_trust_anchor(trust_anchor)
        self._build_keys()
        if rcode is None:
            self.rcode = (
                dns.rcode.Rcode.NXDOMAIN
                if self.qtype == dns.rdatatype.ANY
                else dns.rcode.Rcode.NOERROR
            )
        else:
            self.rcode = dns.rcode.Rcode.make(rcode)
        if self.rcode not in (
            dns.rcode.Rcode.NOERROR,
            dns.rcode.Rcode.NXDOMAIN,
        ):
            _bogus("rcode is not NOERROR or NXDOMAIN")
        if self.qtype == dns.rdatatype.ANY and self.rcode == dns.rcode.Rcode.NOERROR:
            _bogus("ANY queries cannot use NODATA denial validation")

    def _index_rrset(self, rrset: dns.rrset.RRset) -> None:
        name = _absolute_name(rrset.name)
        if rrset.rdclass != dns.rdataclass.IN:
            _bogus("only Internet class RRsets are supported")
        if not name.is_subdomain(self.apex):
            return
        key = (name, rrset.rdtype, rrset.covers)
        existing = self.index.get(key)
        if existing is None:
            self.index[key] = rrset
        else:
            existing.union_update(rrset)
        if rrset.rdtype == dns.rdatatype.RdataType.NSEC3:
            self.proof_sets.append(rrset)
            for rdata in rrset:
                nsec3 = cast(dns.rdtypes.ANY.NSEC3.NSEC3, rdata)
                if nsec3.iterations > MAX_NSEC3_ITERATIONS:
                    _bogus("NSEC3 iterations exceed the local limit")
        elif rrset.rdtype == dns.rdatatype.RdataType.NSEC3PARAM:
            for rdata in rrset:
                param = cast(dns.rdtypes.ANY.NSEC3PARAM.NSEC3PARAM, rdata)
                if param.iterations > MAX_NSEC3_ITERATIONS:
                    _bogus("NSEC3PARAM iterations exceed the local limit")

    def get(
        self,
        name: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
    ) -> dns.rrset.RRset | None:
        return self.index.get((name, rdtype, covers))

    def require_signed(self, rrset: dns.rrset.RRset) -> None:
        sigs = self.get(rrset.name, dns.rdatatype.RRSIG, rrset.rdtype)
        if sigs is None:
            _bogus(f"no RRSIG covers {dns.rdatatype.to_text(rrset.rdtype)}")
        try:
            dns.dnssec.validate(rrset, sigs, self.keys, now=self.now)
        except DNSException as exc:
            _bogus(str(exc))

    def valid_rrsig(self, rrset: dns.rrset.RRset) -> dns.rdtypes.ANY.RRSIG.RRSIG | None:
        sigs = self.get(rrset.name, dns.rdatatype.RRSIG, rrset.rdtype)
        if sigs is None:
            return None
        for rrsig in sigs:
            try:
                dns.dnssec.validate_rrsig(
                    rrset,
                    cast(dns.rdtypes.ANY.RRSIG.RRSIG, rrsig),
                    self.keys,
                    now=self.now,
                )
                return cast(dns.rdtypes.ANY.RRSIG.RRSIG, rrsig)
            except DNSException:
                continue
        return None

    def _anchor_rdatas(self, trust_anchor: TrustAnchor) -> list[dns.rdata.Rdata]:
        if trust_anchor is None:
            return []
        if isinstance(trust_anchor, dns.rdata.Rdata):
            if trust_anchor.rdclass != dns.rdataclass.IN:
                _bogus("trust anchor must have Internet class")
            return [trust_anchor]
        if isinstance(trust_anchor, dns.rrset.RRset):
            if trust_anchor.rdclass != dns.rdataclass.IN:
                _bogus("trust anchor must have Internet class")
            return list(trust_anchor)
        result = []
        for item in trust_anchor:
            if isinstance(item, dns.rrset.RRset):
                if item.rdclass != dns.rdataclass.IN:
                    _bogus("trust anchor must have Internet class")
                result.extend(item)
            else:
                if item.rdclass != dns.rdataclass.IN:
                    _bogus("trust anchor must have Internet class")
                result.append(item)
        return result

    def _load_trust_anchor(self, trust_anchor: TrustAnchor) -> None:
        for rdata in self._anchor_rdatas(trust_anchor):
            if isinstance(rdata, dns.rdtypes.ANY.DS.DS):
                self.trusted_ds.append(rdata)
            elif isinstance(rdata, dns.rdtypes.ANY.DNSKEY.DNSKEY):
                self.trusted_dnskeys.append(rdata)
            else:
                _bogus("trust anchor must be DS or DNSKEY data")

    def _build_keys(self) -> None:
        dnskey_rrset = self.get(self.apex, dns.rdatatype.DNSKEY)
        if dnskey_rrset is not None:
            self.keys[self.apex] = dnskey_rrset

        if self.trusted_dnskeys:
            if dnskey_rrset is None:
                self.keys[self.apex] = dns.rrset.from_rdata_list(
                    self.apex, 3600, self.trusted_dnskeys
                )
            else:
                if all(key not in dnskey_rrset for key in self.trusted_dnskeys):
                    _bogus("DNSKEY trust anchor is absent from the DNSKEY RRset")
                self.require_signed(dnskey_rrset)
                self.keys[self.apex] = dns.rrset.from_rdata_list(
                    self.apex, dnskey_rrset.ttl, self.trusted_dnskeys
                )
            return

        if not self.trusted_ds:
            return
        if dnskey_rrset is None:
            _bogus("DS trust anchor requires an apex DNSKEY RRset")
        matching = []
        for dnskey in dnskey_rrset:
            key = cast(dns.rdtypes.ANY.DNSKEY.DNSKEY, dnskey)
            for ds in self.trusted_ds:
                try:
                    candidate = dns.dnssec.make_ds(
                        self.apex,
                        key,
                        ds.digest_type,
                        policy=dns.dnssec.allow_all_policy,
                    )
                except DNSException as exc:
                    _bogus(str(exc))
                if candidate == ds:
                    matching.append(key)
                    break
        if not matching:
            _bogus("no apex DNSKEY matches the DS trust anchor")
        self.require_signed(dnskey_rrset)
        self.keys[self.apex] = dns.rrset.from_rdata_list(
            self.apex, dnskey_rrset.ttl, matching
        )

    def _is_unsigned_delegation(self, name: dns.name.Name) -> bool:
        if name == self.apex:
            return False
        ns = self.get(name, dns.rdatatype.NS)
        if ns is None:
            return False
        ds = self.get(name, dns.rdatatype.DS)
        return ds is None or len(ds) == 0

    def _follow_cname(self, target: dns.name.Name) -> dns.name.Name:
        seen = set()
        while True:
            if target in seen:
                _bogus("CNAME loop")
            seen.add(target)
            if not target.is_subdomain(self.apex):
                _bogus("CNAME chain leaves the validated zone")
            cname = self.get(target, dns.rdatatype.CNAME)
            if cname is None:
                break
            if len(cname) != 1:
                _bogus("malformed CNAME RRset")
            rrsig = self.valid_rrsig(cname)
            if rrsig is None:
                _bogus("CNAME RRset is not validly signed")
            if rrsig.labels < len(target) - 1:
                self.wildcard_expanded = True
            target = _absolute_name(cast(dns.rdtypes.ANY.CNAME.CNAME, cname[0]).target)
        return target

    def _find_nsec_covering(self, name: dns.name.Name) -> (
        tuple[
            dns.rrset.RRset,
            dns.rdtypes.ANY.NSEC.NSEC,
        ]
        | None
    ):
        for (owner, rdtype, _), rrset in self.index.items():
            if rdtype != dns.rdatatype.NSEC:
                continue
            for rdata in rrset:
                nsec = cast(dns.rdtypes.ANY.NSEC.NSEC, rdata)
                if (
                    nsec.next.is_subdomain(self.apex)
                    and owner.is_subdomain(self.apex)
                    and _in_nsec_interval(name, owner, nsec.next, self.apex)
                ):
                    return rrset, nsec
        return None

    def _exact_nsec(self, name: dns.name.Name) -> (
        tuple[
            dns.rrset.RRset,
            dns.rdtypes.ANY.NSEC.NSEC,
        ]
        | None
    ):
        rrset = self.get(name, dns.rdatatype.NSEC)
        if rrset is None:
            return None
        if len(rrset) != 1:
            _bogus("multiple NSEC records at one owner")
        return rrset, cast(dns.rdtypes.ANY.NSEC.NSEC, rrset[0])

    def _select_proofs(
        self, selected: list[dns.rrset.RRset]
    ) -> tuple[dns.rrset.RRset, ...]:
        unique: dict[ProofKey, dns.rrset.RRset] = {}
        for rrset in selected:
            unique[(rrset.name, rrset.rdtype, rrset.covers)] = rrset
        return tuple(unique.values())

    def _validate_nsec(self, target: dns.name.Name) -> DenialValidationResult:
        selected: list[dns.rrset.RRset] = []
        insecure_reason: str | None = None
        if self.rcode == dns.rcode.Rcode.NXDOMAIN:
            closest: dns.name.Name | None = None
            for depth in range(len(target), len(self.apex) - 1, -1):
                candidate = _suffix(target, depth)
                exact = self._exact_nsec(candidate)
                if exact is not None:
                    closest = candidate
                    selected.append(exact[0])
                    break
            if closest is None:
                _bogus("no NSEC closest encloser")
            self.closest_encloser = closest
            if len(target) == len(closest):
                _bogus("NXDOMAIN proof has no next closer")
            missing = target.relativize(closest).labels
            next_closer = dns.name.Name((missing[0],) + closest.labels)
            self.next_closer = next_closer
            covering = self._find_nsec_covering(next_closer)
            if covering is None:
                _bogus("no NSEC covers the next closer")
            selected.append(covering[0])
        else:
            wildcard: dns.name.Name | None = None
            wildcard_exact: (
                tuple[
                    dns.rrset.RRset,
                    dns.rdtypes.ANY.NSEC.NSEC,
                ]
                | None
            ) = None
            exact = self._exact_nsec(target)
            if exact is not None:
                rrset, nsec = exact
                if _bitmap_has_type(nsec.windows, self.qtype):
                    _bogus("NSEC bitmap contains the queried type")
                selected.append(rrset)
                if self.qtype == dns.rdatatype.DS and self._is_unsigned_delegation(
                    target
                ):
                    insecure_reason = "NSEC proof reaches a zone cut without DS"
            else:
                wildcard = None
                for depth in range(len(target) - 1, len(self.apex) - 1, -1):
                    parent = _suffix(target, depth)
                    candidate = _wildcard_for(target, parent)
                    wildcard_exact = self._exact_nsec(candidate)
                    if wildcard_exact is not None:
                        wildcard = candidate
                        selected.append(wildcard_exact[0])
                        break
                if wildcard is not None:
                    assert wildcard_exact is not None
                    self.wildcard = wildcard
                    self.wildcard_expanded = True
                    if _bitmap_has_type(wildcard_exact[1].windows, self.qtype):
                        _bogus("wildcard NSEC bitmap contains the queried type")
                else:
                    covering = self._find_nsec_covering(target)
                    if covering is None:
                        _bogus("no NSEC covers the qname")
                    selected.append(covering[0])
                    parent = target.parent()
                    parent_exact = self._exact_nsec(parent)
                    if parent_exact is None:
                        _bogus("no NSEC proves the qname parent")
                    selected.append(parent_exact[0])
                    self.closest_encloser = parent
                    if self._is_unsigned_delegation(parent):
                        insecure_reason = "unsigned delegation; NSEC proof reaches a zone cut without DS"
        for rrset in self._select_proofs(selected):
            self.require_signed(rrset)
        if insecure_reason is not None:
            return self._insecure(insecure_reason, selected)
        return self._secure("valid NSEC denial-of-existence proof", selected)

    def _nsec3_groups(
        self,
    ) -> dict[
        tuple[int, int, int, bytes],
        list[dns.rrset.RRset],
    ]:
        groups: dict[tuple[int, int, int, bytes], list[dns.rrset.RRset]] = {}
        for rrset in self.proof_sets:
            for rdata in rrset:
                nsec3 = cast(dns.rdtypes.ANY.NSEC3.NSEC3, rdata)
                if len(nsec3.next) != 20:
                    _bogus("malformed NSEC3 next hash length")
                key = (
                    nsec3.algorithm,
                    nsec3.flags,
                    nsec3.iterations,
                    nsec3.salt,
                )
                groups.setdefault(key, [])
                if rrset not in groups[key]:
                    groups[key].append(rrset)
        return groups

    def _nsec3_owner_hash(
        self,
        name: dns.name.Name,
        parameters: tuple[int, int, int, bytes],
    ) -> bytes:
        algorithm, _flags, iterations, salt = parameters
        if algorithm != 1:
            _bogus("unsupported NSEC3 hash algorithm")
        if iterations > MAX_NSEC3_ITERATIONS:
            _bogus("NSEC3 iterations exceed the local limit")
        return _hash_name(name, salt, iterations)

    def _nsec3_covers(
        self,
        hash_value: bytes,
        owner_hash: bytes,
        next_hash: bytes,
        parameters: tuple[int, int, int, bytes],
    ) -> bool:
        if len(hash_value) != 20 or len(owner_hash) != 20 or len(next_hash) != 20:
            _bogus("malformed NSEC3 hash length")
        if owner_hash == next_hash:
            _algorithm, _flags, iterations, salt = parameters
            apex_hash = _hash_name(self.apex, salt, iterations)
            return owner_hash == apex_hash and hash_value != owner_hash
        if owner_hash < next_hash:
            return owner_hash < hash_value < next_hash
        return hash_value > owner_hash or hash_value < next_hash

    def _find_nsec3(
        self,
        parameters: tuple[int, int, int, bytes],
        sets: list[dns.rrset.RRset],
        hash_value: bytes,
        exact: bool,
    ) -> tuple[dns.rrset.RRset, dns.rdtypes.ANY.NSEC3.NSEC3] | None:
        for rrset in sets:
            owner_hash = _owner_hash(rrset.name, self.apex)
            for rdata in rrset:
                nsec3 = cast(dns.rdtypes.ANY.NSEC3.NSEC3, rdata)
                if (
                    nsec3.algorithm,
                    nsec3.flags,
                    nsec3.iterations,
                    nsec3.salt,
                ) != parameters:
                    continue
                if exact:
                    if owner_hash == hash_value:
                        return rrset, nsec3
                elif self._nsec3_covers(hash_value, owner_hash, nsec3.next, parameters):
                    return rrset, nsec3
        return None

    def _validate_nsec3param(self, parameters: tuple[int, int, int, bytes]) -> None:
        rrset = self.get(self.apex, dns.rdatatype.NSEC3PARAM)
        if rrset is None:
            return
        if len(rrset) != 1:
            _bogus("multiple NSEC3PARAM records at the apex")
        param = cast(dns.rdtypes.ANY.NSEC3PARAM.NSEC3PARAM, rrset[0])
        actual = (param.algorithm, param.flags, param.iterations, param.salt)
        if actual != parameters:
            _bogus("NSEC3 proof parameters do not match NSEC3PARAM")
        self.require_signed(rrset)

    def _validate_nsec3_group(
        self,
        parameters: tuple[int, int, int, bytes],
        sets: list[dns.rrset.RRset],
        target: dns.name.Name,
    ) -> DenialValidationResult | None:
        algorithm, flags, iterations, salt = parameters
        if algorithm != 1 or iterations > MAX_NSEC3_ITERATIONS:
            _bogus("unsupported NSEC3 hash algorithm or iterations")
        if flags & ~nsec3module.OPTOUT:
            _bogus("unsupported NSEC3 flags")
        opt_out = bool(flags & nsec3module.OPTOUT)
        selected: list[dns.rrset.RRset] = []
        insecure_reason = None
        self.closest_encloser = None
        self.next_closer = None
        self.wildcard = None
        self.wildcard_expanded = False

        def find_exact(name: dns.name.Name):
            return self._find_nsec3(
                parameters,
                sets,
                self._nsec3_owner_hash(name, parameters),
                True,
            )

        def find_covering(name: dns.name.Name):
            return self._find_nsec3(
                parameters,
                sets,
                self._nsec3_owner_hash(name, parameters),
                False,
            )

        if self.rcode == dns.rcode.Rcode.NXDOMAIN:
            closest_name: dns.name.Name | None = None
            closest_proof: (
                tuple[
                    dns.rrset.RRset,
                    dns.rdtypes.ANY.NSEC3.NSEC3,
                ]
                | None
            ) = None
            for depth in range(len(target), len(self.apex) - 1, -1):
                candidate = _suffix(target, depth)
                proof = find_exact(candidate)
                if proof is not None:
                    closest_name = candidate
                    closest_proof = proof
                    break
            if closest_name is None or closest_proof is None:
                return None
            selected.append(closest_proof[0])
            self.closest_encloser = closest_name
            if len(target) == len(closest_name):
                _bogus("NSEC3 NXDOMAIN proof has no next closer")
            missing = target.relativize(closest_name).labels
            next_closer = dns.name.Name((missing[0],) + closest_name.labels)
            self.next_closer = next_closer
            next_proof = find_covering(next_closer)
            if next_proof is None:
                return None
            selected.append(next_proof[0])
            if opt_out and self._is_unsigned_delegation(closest_name):
                insecure_reason = (
                    "opt-out NSEC3 proof does not secure the unsigned delegation"
                )
        else:
            exact = find_exact(target)
            if exact is not None:
                rrset, nsec3 = exact
                if _bitmap_has_type(nsec3.windows, self.qtype):
                    _bogus("NSEC3 bitmap contains the queried type")
                selected.append(rrset)
                if self.qtype == dns.rdatatype.DS and self._is_unsigned_delegation(
                    target
                ):
                    insecure_reason = "NSEC3 proof reaches a zone cut without DS"
                elif opt_out and nsec3.flags & dns.rdtypes.ANY.NSEC3.OPTOUT:
                    if self._is_unsigned_delegation(target):
                        insecure_reason = "opt-out NSEC3 proof does not secure the unsigned delegation"
            else:
                wildcard: dns.name.Name | None = None
                wildcard_proof: (
                    tuple[
                        dns.rrset.RRset,
                        dns.rdtypes.ANY.NSEC3.NSEC3,
                    ]
                    | None
                ) = None
                for depth in range(len(target) - 1, len(self.apex) - 1, -1):
                    parent = _suffix(target, depth)
                    candidate = _wildcard_for(target, parent)
                    proof = find_exact(candidate)
                    if proof is not None:
                        wildcard = candidate
                        wildcard_proof = proof
                        break
                if wildcard is not None and wildcard_proof is not None:
                    selected.append(wildcard_proof[0])
                    self.wildcard = wildcard
                    self.wildcard_expanded = True
                    if _bitmap_has_type(wildcard_proof[1].windows, self.qtype):
                        _bogus("NSEC3 wildcard bitmap contains the queried type")
                    if (
                        opt_out
                        and wildcard_proof[1].flags & dns.rdtypes.ANY.NSEC3.OPTOUT
                        and self._is_unsigned_delegation(wildcard.parent())
                    ):
                        insecure_reason = "opt-out wildcard proof does not secure an unsigned delegation"
                else:
                    closest_name: dns.name.Name | None = None
                    closest_proof: (
                        tuple[
                            dns.rrset.RRset,
                            dns.rdtypes.ANY.NSEC3.NSEC3,
                        ]
                        | None
                    ) = None
                    for depth in range(len(target), len(self.apex) - 1, -1):
                        candidate = _suffix(target, depth)
                        proof = find_exact(candidate)
                        if proof is not None:
                            closest_name = candidate
                            closest_proof = proof
                            break
                    if closest_name is None or closest_proof is None:
                        return None
                    selected.append(closest_proof[0])
                    self.closest_encloser = closest_name
                    next_closer = dns.name.Name(
                        (target.relativize(closest_name).labels[0],)
                        + closest_name.labels
                    )
                    self.next_closer = next_closer
                    covering = find_covering(next_closer)
                    if covering is None:
                        return None
                    selected.append(covering[0])
                    if (
                        opt_out
                        and covering[1].flags & dns.rdtypes.ANY.NSEC3.OPTOUT
                        and self._is_unsigned_delegation(closest_name)
                    ):
                        insecure_reason = "opt-out NSEC3 proof does not secure the unsigned delegation"

        self._validate_nsec3param(parameters)
        for rrset in self._select_proofs(selected):
            self.require_signed(rrset)
        if insecure_reason is not None:
            return self._insecure(insecure_reason, selected)
        return self._secure("valid NSEC3 denial-of-existence proof", selected)

    def _validate_nsec3(self, target: dns.name.Name) -> DenialValidationResult:
        failure: str | None = None
        for parameters, sets in self._nsec3_groups().items():
            try:
                result = self._validate_nsec3_group(parameters, sets, target)
            except _Bogus as exc:
                failure = str(exc)
                continue
            if result is not None:
                return result
        _bogus(failure or "no NSEC3 proof closes the required name interval")

    def _secure(
        self, reason: str, selected: list[dns.rrset.RRset]
    ) -> DenialValidationResult:
        return DenialValidationResult(
            DenialStatus.SECURE,
            reason,
            self._select_proofs(selected),
            self.closest_encloser,
            self.next_closer,
            self.wildcard,
            self.wildcard_expanded,
        )

    def _insecure(
        self,
        reason: str,
        selected: list[dns.rrset.RRset] | None = None,
    ) -> DenialValidationResult:
        return DenialValidationResult(
            DenialStatus.INSECURE,
            reason,
            self._select_proofs(selected if selected is not None else self.proof_sets),
            self.closest_encloser,
            self.next_closer,
            self.wildcard,
            self.wildcard_expanded,
        )

    def validate(self) -> DenialValidationResult:
        if not self.trusted_ds and not self.trusted_dnskeys:
            return DenialValidationResult(
                DenialStatus.INSECURE,
                "no trust anchor for the zone",
                self._select_proofs(self.proof_sets),
            )
        target = self._follow_cname(self.qname)
        has_nsec = any(key[1] == dns.rdatatype.NSEC for key in self.index)
        has_nsec3 = bool(self.proof_sets)
        if has_nsec and has_nsec3:
            _bogus("response contains both NSEC and NSEC3 denial records")
        if has_nsec3:
            return self._validate_nsec3(target)
        if has_nsec:
            return self._validate_nsec(target)
        _bogus("no NSEC or NSEC3 denial records were supplied")


def validate_denial(
    qname: dns.name.Name | str,
    qtype: dns.rdatatype.RdataType | str,
    apex: dns.name.Name | str,
    trust_anchor: TrustAnchor,
    rrsets: Iterable[dns.rrset.RRset],
    rcode: int | str | None = None,
    now: float | None = None,
) -> DenialValidationResult:
    """Validate an offline NXDOMAIN, NODATA, or wildcard denial response.

    *qname* and *qtype* describe the original query. *apex* is the zone apex
    that should own the proof. *trust_anchor* is a DS or DNSKEY rdata, an
    RRset containing DS or DNSKEY rdata, or an iterable of those values. If it
    is ``None``, the zone is treated as insecure rather than bogus.

    *rrsets* contains all response RRsets, including DNSKEY, DS, CNAME, RRSIG,
    NSEC, NSEC3, and NSEC3PARAM RRsets. *rcode* is ``dns.rcode.Rcode.NOERROR``
    for NODATA or wildcard NODATA and ``dns.rcode.Rcode.NXDOMAIN`` for name
    errors; it defaults to NOERROR. *now* overrides RRSIG time validation.

    All validation uses *rrsets* and *trust_anchor*; this function does not
    perform network or resolver access.

    :rtype: :py:class:`DenialValidationResult`
    """

    try:
        return _Validator(
            qname, qtype, apex, trust_anchor, rrsets, rcode, now
        ).validate()
    except _Bogus as exc:
        return DenialValidationResult(DenialStatus.BOGUS, str(exc))
    except DNSException as exc:
        return DenialValidationResult(DenialStatus.BOGUS, str(exc))
    except (TypeError, ValueError) as exc:
        return DenialValidationResult(DenialStatus.BOGUS, str(exc))
