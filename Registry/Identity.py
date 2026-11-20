"""
Read-only user identity correlation for Registry evidence.

The module deliberately keeps three kinds of information apart:

* ``SourceKind.MOUNT_NOTE`` - labels, export names and mount annotations.
  They describe how a hive arrived in the case, not who owns it.
* ``SourceKind.HIVE`` - user clues read from the hive itself (SAM account
  records, ProfileList entries, NTUSER environment values, and so on).
  They are evidence, but they still came from the same acquisition.
* ``SourceKind.TRUSTED_SID_TABLE`` - an explicitly supplied, independent
  SID cross-reference.

The central policy is intentionally strict: a unique user attribution is
only produced when the trusted SID table supports it.  Without that table,
the report still explains every clue, groups obvious copies, and exposes
provisional candidates - but ``unique`` is always ``False`` and
``attribution`` is ``None``.  Internal clues alone are never promoted to a
final identity.

The code only reads hives and tables.  It never opens the host registry,
never consults environment variables or the network, and never writes to a
source hive.
"""
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import csv
import hashlib
import io
import json
import os
import re
import struct
import sys

from enum import Enum

from .Registry import (
    HiveType,
    Registry,
    RegistryKeyNotFoundException,
    RegistryValueNotFoundException,
)


__all__ = [
    "ClueKind",
    "Confidence",
    "Conflict",
    "EvidenceAttribution",
    "EvidenceClue",
    "HiveEvidence",
    "IdentityHypothesis",
    "IdentityReport",
    "IdentityResolver",
    "MountNote",
    "ResolutionStatus",
    "SourceKind",
    "TrustedSidRecord",
    "TrustedSidTable",
    "TrustedSidTableError",
    "analyze_hive",
    "build_identity_report",
    "correlate_identities",
    "extract_hive_clues",
    "load_trusted_sid_table",
    "normalize_sid",
    "parse_mount_note",
    "parse_sid",
    "read_hive_evidence",
    "resolve_identities",
    "resolve_user_identities",
    "sid_from_binary",
    "username_from_profile_path",
]


class SourceKind(str, Enum):
    """Where a clue came from."""

    MOUNT_NOTE = "mount_note"
    HIVE = "hive"
    TRUSTED_SID_TABLE = "trusted_sid_table"


class Confidence(str, Enum):
    """
    Qualitative confidence attached to each clue.

    The labels are deliberately source-aware.  A trusted table is the only
    ``AUTHORITATIVE`` source; a mount note can never exceed ``MEDIUM``.
    """

    AUTHORITATIVE = "authoritative"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"

    @property
    def score(self):
        return {
            Confidence.AUTHORITATIVE: 1.0,
            Confidence.HIGH: 0.85,
            Confidence.MEDIUM: 0.60,
            Confidence.LOW: 0.35,
            Confidence.UNVERIFIED: 0.10,
        }[self]


class ResolutionStatus(str, Enum):
    """Terminal state of an identity or evidence attribution."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    CONFLICT = "conflict"
    MACHINE_DEFAULT = "machine_default"
    MACHINE_SCOPE = "machine_scope"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class TrustedSidTableError(ValueError):
    """Raised when an explicitly supplied SID table cannot be trusted."""


class ClueKind(str, Enum):
    """Kinds of identity-relevant clue extracted from a source."""

    USERNAME = "username"
    DOMAIN = "domain"
    SID = "sid"
    MACHINE_SID = "machine_sid"
    RID = "rid"
    PROFILE_PATH = "profile_path"


_SID_TEXT_RE = re.compile(r"^[Ss]-(\d+)-(\d+)((?:-\d+)+)$")
_SID_PREFIX_RE = re.compile(r"^[Ss]-")


def _fspath(value):
    if hasattr(os, "fspath"):
        return os.fspath(value)
    return str(value)


def _int_from_bytes_be(data):
    value = 0
    for byte in data:
        value = (value << 8) | byte
    return value


def _canonical_sid(revision, authority, subauthorities):
    parts = ["S", str(int(revision)), str(int(authority))]
    parts.extend(str(int(item)) for item in subauthorities)
    return "-".join(parts)


def sid_from_binary(data, offset=0):
    """
    Decode a binary Windows SID at ``offset``.

    @type data: bytes
    @rtype: str
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("a binary SID must be bytes")
    if offset < 0 or offset >= len(data):
        raise ValueError("SID offset is outside the buffer")
    revision = data[offset]
    count = data[offset + 1]
    if count == 0 or count > 15:
        raise ValueError("invalid SID sub-authority count %d" % (count,))
    end = offset + 8 + (4 * count)
    if end > len(data):
        raise ValueError("truncated binary SID")
    authority = _int_from_bytes_be(data[offset + 2:offset + 8])
    subauthorities = list(struct.unpack_from("<" + ("I" * count),
                                             data, offset + 8))
    return _canonical_sid(revision, authority, subauthorities)


def parse_sid(value):
    """
    Parse and canonicalize a textual or binary SID.

    Text is accepted in the normal ``S-1-5-21-...`` form.  Bytes are decoded
    as a binary SID.  Invalid input raises ``ValueError`` rather than being
    guessed at.
    """
    if isinstance(value, (bytes, bytearray)):
        stripped = bytes(value).strip()
        if stripped[:2].upper() == b"S-":
            value = stripped.decode("ascii")
        else:
            return sid_from_binary(stripped)

    if value is None:
        raise ValueError("SID is missing")
    text = str(value).strip().strip('"')
    if not text:
        raise ValueError("SID is empty")

    match = _SID_TEXT_RE.match(text)
    if not match:
        raise ValueError("not a canonical SID: %r" % (text,))

    revision = int(match.group(1))
    authority = int(match.group(2))
    subauthorities = [int(part) for part in match.group(3).split("-")[1:]]
    if revision < 0 or revision > 255:
        raise ValueError("SID revision is out of range")
    if authority < 0:
        raise ValueError("SID authority is out of range")
    if not subauthorities or len(subauthorities) > 15:
        raise ValueError("SID sub-authority count is out of range")
    for item in subauthorities:
        if item < 0 or item > 0xFFFFFFFF:
            raise ValueError("SID sub-authority is out of range")
    return _canonical_sid(revision, authority, subauthorities)


def normalize_sid(value):
    """Alias for :func:`parse_sid` kept for discoverability."""
    return parse_sid(value)


def _try_sid(value):
    try:
        return parse_sid(value)
    except (TypeError, ValueError):
        return None


def _sid_subauthorities(sid):
    return [int(part) for part in sid.split("-")[3:]]


def _sid_rid(sid):
    parts = _sid_subauthorities(sid)
    return parts[-1] if parts else None


_MACHINE_ACCOUNT_SIDS = frozenset((
    "S-1-5-18",   # LOCAL SYSTEM
    "S-1-5-19",   # LOCAL SERVICE
    "S-1-5-20",   # NETWORK SERVICE
    "S-1-5-6",    # SERVICE
    "S-1-5-7",    # ANONYMOUS LOGON
))

_MACHINE_DEFAULT_NAMES = frozenset((
    "default",
    "default user",
    "defaultuser",
    "public",
    "all users",
    "allusers",
    "system",
    "local service",
    "localservice",
    "network service",
    "networkservice",
    "systemprofile",
    "defaultaccount",
    "wdagutilityaccount",
    "defaultapppool",
))

_MACHINE_DEFAULT_RIDS = frozenset((501, 503, 504))


def _is_machine_account_sid(sid):
    return sid in _MACHINE_ACCOUNT_SIDS


def _is_machine_default_name(name):
    if not name:
        return False
    return name.strip().casefold() in _MACHINE_DEFAULT_NAMES


def _is_machine_default_sid(sid):
    if not sid:
        return False
    if _is_machine_account_sid(sid):
        return True
    return _sid_rid(sid) in _MACHINE_DEFAULT_RIDS


def _is_machine_default_path(path):
    if not path:
        return False
    lower = str(path).replace("/", "\\").casefold()
    return ("\\users\\default" in lower
            or "\\users\\public" in lower
            or "\\documents and settings\\default" in lower
            or "\\system32\\config\\systemprofile" in lower)


_PATH_USER_MARKERS = ("users", "documents and settings")
_PATH_RESERVED_NAMES = _MACHINE_DEFAULT_NAMES | frozenset((
    "ntuser",
    "usrclass",
    "ntuser.dat",
    "usrclass.dat",
    "sam",
    "software",
    "system",
    "security",
    "default",
    "hive",
    "registry",
    "evidence",
    "mount",
    "unknown",
))


def _normalize_name(domain, username):
    """
    Normalize a name into ``(domain, username)`` while preserving case.

    Matching uses a case-folded key; evidence output keeps the original
    spelling.  ``DOMAIN\\user`` and ``user@domain`` are both accepted.
    """
    if username is None:
        raise ValueError("username is missing")
    username = str(username).strip().strip('"').strip()
    domain = str(domain).strip().strip('"').strip() if domain else None

    if "\\" in username:
        embedded_domain, username = username.rsplit("\\", 1)
        if not domain:
            domain = embedded_domain or None
    elif "/" in username and not _looks_like_path(username):
        embedded_domain, username = username.rsplit("/", 1)
        if not domain:
            domain = embedded_domain or None
    elif "@" in username and not domain:
        username, domain = username.rsplit("@", 1)

    username = username.strip()
    domain = domain.strip() if domain else None
    if not username or username in (".", ".."):
        raise ValueError("username is empty")
    if any(char in username for char in ("\\", "/", "\x00", "\r", "\n")):
        raise ValueError("username contains a path or control character")
    if len(username) > 256 or (domain and len(domain) > 256):
        raise ValueError("username or domain is too long")
    return domain, username


def _name_key(domain, username):
    return ((domain or "").casefold(), username.casefold())


def _display_name(domain, username):
    if domain:
        return "%s\\%s" % (domain, username)
    return username


def _looks_like_path(text):
    if not text:
        return False
    return ("\\" in text or "/" in text or ":" in text
            or text.casefold().startswith(("%userprofile%", "%systemdrive%",
                                           "%systemroot%")))


def _path_parts(path):
    text = str(path).strip().strip('"')
    text = text.replace("/", "\\")
    text = re.sub(r"^\\\\[?.]\\", "", text)
    return [part for part in text.split("\\") if part and part != "."]


def _profile_name_from_path(path):
    if not path:
        return None
    parts = _path_parts(path)
    for index, part in enumerate(parts[:-1]):
        if part.casefold() in _PATH_USER_MARKERS:
            return parts[index + 1] or None
    lower = str(path).replace("/", "\\").casefold()
    if "\\system32\\config\\systemprofile" in lower:
        return "systemprofile"
    return None


def username_from_profile_path(path):
    """
    Return ``(domain, username, is_machine_default)`` from a profile path.

    Only the explicit Windows profile markers ``Users`` and
    ``Documents and Settings`` are used.  A generic path is not treated as
    a username; reserved default-profile names are returned as ``None`` so
    they cannot become ordinary user identities.
    """
    candidate = _profile_name_from_path(path)
    if not candidate or candidate.casefold() in _PATH_RESERVED_NAMES:
        return None
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", candidate):
        return (None, candidate, _is_machine_default_name(candidate))
    return None


def _decode_text(data):
    if isinstance(data, str):
        return data
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    raw = bytes(data)
    for encoding in ("utf-8-sig", "utf-16", "utf-16le", "windows-1252"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace")


def _clean_text(value):
    if value is None:
        return None
    text = _decode_text(value)
    text = text.replace("\x00", "").strip().strip('"').strip()
    return text or None


class EvidenceClue(object):
    """
    One identity-relevant observation with full provenance.

    ``group`` is an extraction-local grouping key.  Two values that describe
    the same account record (for example a SAM account name and its SID)
    share a group; unrelated values in the same hive do not get paired just
    because they happen to coexist.
    """

    def __init__(self, kind, value, source, evidence_id=None, locator=None,
                 confidence=Confidence.MEDIUM, domain=None, detail=None,
                 tags=(), group=None):
        self.kind = ClueKind(kind)
        self.source = SourceKind(source)
        self.evidence_id = evidence_id
        self.locator = locator or ""
        self.confidence = Confidence(confidence)
        self.domain = domain
        self.detail = detail
        self.tags = tuple(sorted(set(tags or ())))
        self.group = group or self.locator

        if self.kind == ClueKind.SID:
            self.value = parse_sid(value)
            self.domain = None
        elif self.kind == ClueKind.MACHINE_SID:
            self.value = parse_sid(value)
            self.domain = None
        elif self.kind == ClueKind.USERNAME:
            domain, username = _normalize_name(domain, value)
            self.domain = domain
            self.value = username
        elif self.kind == ClueKind.DOMAIN:
            self.value = _clean_text(value)
            self.domain = None
        elif self.kind == ClueKind.RID:
            self.value = int(value)
            self.domain = None
        else:
            self.value = _clean_text(value)
            self.domain = None

    @property
    def confidence_score(self):
        return self.confidence.score

    @property
    def normalized(self):
        if self.kind in (ClueKind.SID, ClueKind.MACHINE_SID):
            return self.value
        if self.kind == ClueKind.USERNAME:
            return _name_key(self.domain, self.value)
        if self.kind == ClueKind.DOMAIN:
            return (self.value or "").casefold()
        if self.kind == ClueKind.PROFILE_PATH:
            return (self.value or "").replace("/", "\\").casefold()
        return self.value

    def provenance(self):
        return {
            "source": self.source.value,
            "evidence_id": self.evidence_id,
            "locator": self.locator,
            "group": self.group,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence.score,
        }

    def to_dict(self):
        result = {
            "kind": self.kind.value,
            "value": self.value,
            "domain": self.domain,
            "source": self.source.value,
            "evidence_id": self.evidence_id,
            "locator": self.locator,
            "group": self.group,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence.score,
            "tags": list(self.tags),
        }
        if self.detail:
            result["detail"] = self.detail
        return result

    def __repr__(self):
        return ("EvidenceClue(kind=%s, value=%r, source=%s, locator=%r, "
                "confidence=%s)" % (self.kind.value, self.value,
                                     self.source.value, self.locator,
                                     self.confidence.value))


_EXPLICIT_USER_RE = re.compile(
    r"(?i)\b(?:username|user|account|sam_account_name|owner)\s*[=:]\s*"
    r"[\"']?([^;,\"'\\s]+)")
_EXPLICIT_DOMAIN_RE = re.compile(
    r"(?i)\b(?:domain|user_domain|netbios_domain)\s*[=:]\s*"
    r"[\"']?([^;,\"'\\s]+)")
_EXPLICIT_SID_RE = re.compile(
    r"(?i)\bsid\s*[=:]\s*[\"']?(S-\d+(?:-\d+)+)")
_ENCODED_USERS_RE = re.compile(
    r"(?i)(?:^|[_\\/-])(?:users|documents and settings)[_\\/-]"
    r"([A-Za-z0-9][A-Za-z0-9._-]*?)(?=(?:_|-)(?:NTUSER|UsrClass)(?:\.DAT)?"
    r"(?:\.(?:xz|bz2|gz|7z|zip))?(?:$|[?#])|[\\/]|$)")
_PROFILE_PATH_RE = re.compile(
    r"(?i)(?:[A-Za-z]:[\\/]|[/\\]|%systemdrive%[\\/])[^\"'<>|]*?"
    r"(?:users|documents and settings)[\\/]([^\\/\s\"'<>|]+)")


class MountNote(object):
    """
    An export name, directory label, or explicit mount annotation.

    A mount note is provenance-only.  It can suggest a username or SID but
    never makes an attribution unique.
    """

    def __init__(self, text, evidence_id=None, clues=None, origin="note",
                 note=None):
        if clues is None and text:
            parsed = parse_mount_note(text, evidence_id=evidence_id)
            self.text = parsed.text
            self.evidence_id = evidence_id or parsed.evidence_id
            self.clues = list(parsed.clues)
            self.origin = parsed.origin
            self.note = note
            return
        self.text = text or ""
        self.evidence_id = evidence_id
        self.clues = list(clues or ())
        self.origin = origin
        self.note = note

    @classmethod
    def parse(cls, text, evidence_id=None):
        return parse_mount_note(text, evidence_id=evidence_id)

    @property
    def source(self):
        return SourceKind.MOUNT_NOTE

    @property
    def usernames(self):
        return [clue for clue in self.clues if clue.kind == ClueKind.USERNAME]

    @property
    def sids(self):
        return [clue for clue in self.clues if clue.kind == ClueKind.SID]

    def to_dict(self):
        return {
            "text": self.text,
            "evidence_id": self.evidence_id,
            "origin": self.origin,
            "note": self.note,
            "clues": [clue.to_dict() for clue in self.clues],
        }

    def __repr__(self):
        return "MountNote(text=%r, clues=%d)" % (self.text, len(self.clues))


def _mount_clue(kind, value, evidence_id, text, origin, confidence,
                domain=None, group=None, tags=()):
    return EvidenceClue(
        kind=kind,
        value=value,
        source=SourceKind.MOUNT_NOTE,
        evidence_id=evidence_id,
        locator="mount_note:%s" % (origin,),
        confidence=confidence,
        domain=domain,
        detail=text,
        tags=tags,
        group=group or ("mount:%s" % (evidence_id,)),
    )


def parse_mount_note(text, evidence_id=None):
    """
    Extract conservative identity candidates from a mount label or path.

    Supported examples include ``C:\\Users\\alice\\NTUSER.DAT``,
    ``C__Users_alice_NTUSER.DAT``, ``user=alice; sid=S-1-5-...`` and a bare
    export label such as ``alice``.  Free-form prose is not mined for names.
    """
    if isinstance(text, MountNote):
        return text
    if text is None:
        return MountNote("", evidence_id=evidence_id, clues=[])
    if isinstance(text, dict):
        raw = (text.get("text") or text.get("label")
               or text.get("path") or text.get("mount")
               or text.get("note") or "")
        parsed = parse_mount_note(raw, evidence_id=evidence_id)
        clues = list(parsed.clues)
        group = "mount:%s" % (evidence_id,)
        for field, kind in (("username", ClueKind.USERNAME),
                            ("user", ClueKind.USERNAME),
                            ("sid", ClueKind.SID),
                            ("domain", ClueKind.DOMAIN)):
            value = text.get(field)
            if not value:
                continue
            try:
                if kind == ClueKind.USERNAME:
                    domain, username = _normalize_name(
                        text.get("domain"), value)
                    clues.append(_mount_clue(
                        kind, username, evidence_id, raw,
                        "structured_%s" % (field,), Confidence.MEDIUM,
                        domain=domain, group=group))
                else:
                    clues.append(_mount_clue(
                        kind, value, evidence_id, raw,
                        "structured_%s" % (field,), Confidence.MEDIUM,
                        group=group))
            except (TypeError, ValueError):
                continue
        return MountNote(raw, evidence_id=evidence_id, clues=clues,
                         origin="structured", note=text.get("note"))

    raw = _decode_text(text).strip()
    if not raw:
        return MountNote("", evidence_id=evidence_id, clues=[])

    clues = []
    group = "mount:%s" % (evidence_id,)

    explicit_user = _EXPLICIT_USER_RE.search(raw)
    explicit_domain = _EXPLICIT_DOMAIN_RE.search(raw)
    explicit_sid = _EXPLICIT_SID_RE.search(raw)

    if explicit_sid:
        try:
            clues.append(_mount_clue(
                ClueKind.SID, explicit_sid.group(1), evidence_id, raw,
                "explicit_sid", Confidence.MEDIUM, group=group))
        except ValueError:
            pass

    if explicit_user:
        try:
            domain, username = _normalize_name(
                explicit_domain.group(1) if explicit_domain else None,
                explicit_user.group(1))
            clues.append(_mount_clue(
                ClueKind.USERNAME, username, evidence_id, raw,
                "explicit_username", Confidence.MEDIUM, domain=domain,
                group=group))
            if domain:
                clues.append(_mount_clue(
                    ClueKind.DOMAIN, domain, evidence_id, raw,
                    "explicit_domain", Confidence.MEDIUM, group=group))
        except ValueError:
            pass

    path_match = _PROFILE_PATH_RE.search(raw)
    if path_match:
        candidate = path_match.group(1)
        if candidate and candidate.casefold() not in _PATH_RESERVED_NAMES:
            profile = username_from_profile_path(raw)
            try:
                domain, username = _normalize_name(
                    explicit_domain.group(1) if explicit_domain else None,
                    candidate)
                clues.append(_mount_clue(
                    ClueKind.USERNAME, username, evidence_id, raw,
                    "profile_path", Confidence.LOW, domain=domain,
                    group=group))
                if domain:
                    clues.append(_mount_clue(
                        ClueKind.DOMAIN, domain, evidence_id, raw,
                        "profile_path_domain", Confidence.LOW, domain=domain,
                        group=group))
                if profile:
                    clues.append(_mount_clue(
                        ClueKind.PROFILE_PATH, raw, evidence_id, raw,
                        "profile_path", Confidence.LOW, group=group))
            except ValueError:
                pass

    encoded_match = _ENCODED_USERS_RE.search(raw)
    if encoded_match:
        candidate = encoded_match.group(1)
        if candidate:
            machine_default = candidate.casefold() in _PATH_RESERVED_NAMES
            try:
                domain, username = _normalize_name(
                    explicit_domain.group(1) if explicit_domain else None,
                    candidate)
                clues.append(_mount_clue(
                    ClueKind.USERNAME, username, evidence_id, raw,
                    "encoded_export_name", Confidence.LOW, domain=domain,
                    tags=(("machine_default",) if machine_default else ()),
                    group=group))
            except ValueError:
                pass

    if not clues:
        basename = raw.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        basename = re.sub(
            r"(?i)(?:\.(?:dat|hive|reg|bin|log[12]?))?(?:\.(?:xz|bz2|gz|7z"
            r"|zip))?$", "", basename)
        basename = re.sub(r"(?i)(?:_|-)(?:NTUSER|UsrClass)$", "", basename)
        encoded_fallback = re.search(
            r"(?i)(?:^|[_\\/-])(?:users|documents and settings)[_\\/-]"
            r"([^_\\/]+)", raw)
        if encoded_fallback:
            basename = encoded_fallback.group(1)
        lower = basename.casefold()
        if (lower not in _PATH_RESERVED_NAMES
                and re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", basename)
                and not basename.isdigit()):
            try:
                domain, username = _normalize_name(
                    explicit_domain.group(1) if explicit_domain else None,
                    basename)
                clues.append(_mount_clue(
                    ClueKind.USERNAME, username, evidence_id, raw,
                    "export_label", Confidence.LOW, domain=domain,
                    group=group))
            except ValueError:
                pass

    origin = "explicit" if (explicit_user or explicit_sid) else (
        "path" if (path_match or encoded_match) else "label")
    return MountNote(raw, evidence_id=evidence_id, clues=clues, origin=origin)


class TrustedSidRecord(object):
    """One row of an independent SID cross-reference."""

    def __init__(self, username, sid, domain=None, note=None, source_row=None):
        domain, username = _normalize_name(domain, username)
        self.username = username
        self.domain = domain
        self.sid = parse_sid(sid)
        self.note = note
        self.source_row = source_row

    @property
    def display_name(self):
        return _display_name(self.domain, self.username)

    @property
    def name_key(self):
        return _name_key(self.domain, self.username)

    @property
    def source(self):
        return SourceKind.TRUSTED_SID_TABLE

    @property
    def confidence(self):
        return Confidence.AUTHORITATIVE

    @property
    def confidence_score(self):
        return Confidence.AUTHORITATIVE.score

    def to_dict(self):
        return {
            "username": self.username,
            "domain": self.domain,
            "display_name": self.display_name,
            "sid": self.sid,
            "note": self.note,
            "source_row": self.source_row,
            "source": SourceKind.TRUSTED_SID_TABLE.value,
            "confidence": Confidence.AUTHORITATIVE.value,
            "confidence_score": Confidence.AUTHORITATIVE.score,
        }

    def __repr__(self):
        return "TrustedSidRecord(%r, %r)" % (self.display_name, self.sid)


_USERNAME_COLUMNS = frozenset((
    "user", "username", "user_name", "name", "account", "account_name",
    "sam_account_name", "samaccountname", "login", "login_name",
    "用户名", "用户", "账号", "帐户", "账户",
))
_SID_COLUMNS = frozenset((
    "sid", "user_sid", "usersid", "object_sid", "objectsid",
    "security_identifier", "securityidentifier", "s_id",
    "安全标识符", "用户sid",
))
_DOMAIN_COLUMNS = frozenset((
    "domain", "user_domain", "userdomain", "netbios_domain",
    "netbiosdomain", "domain_name", "域", "域名",
))
_NOTE_COLUMNS = frozenset((
    "note", "notes", "comment", "source", "evidence", "description",
    "备注", "说明", "来源",
))


def _column_key(text):
    return re.sub(r"[\s\-]+", "_", _clean_text(text).casefold())


def _pick(mapping, *names):
    """Read a field from a record dict, tolerating header case/spelling."""
    if not isinstance(mapping, dict):
        return None
    for name in names:
        if name in mapping:
            return mapping[name]
    folded = dict((_column_key(str(key)), value)
                  for key, value in mapping.items())
    for name in names:
        key = _column_key(name)
        if key in folded:
            return folded[key]
    return None


def _looks_like_header(fields):
    keys = set(_column_key(field) for field in fields)
    return bool(keys & _USERNAME_COLUMNS) and bool(keys & _SID_COLUMNS)


def _sniff_delimiter(line):
    best = ","
    best_count = -1
    for delimiter in (",", "\t", ";", "|"):
        count = line.count(delimiter)
        if count > best_count:
            best = delimiter
            best_count = count
    return best


def _split_mount_line(line):
    text = line.strip()
    if not text or text.startswith("#") or text.startswith("//"):
        return None
    text = text.split("#", 1)[0].strip()
    if not text:
        return None
    if "->" in text:
        left, right = text.split("->", 1)
        return [left.strip(), right.strip()]
    if "=" in text:
        left, right = text.split("=", 1)
        if left.strip() and right.strip():
            return [left.strip(), right.strip()]
    if (":" in text and not re.match(r"(?i)^[A-Za-z]:[\\/]", text)):
        left, right = text.split(":", 1)
        if left.strip() and right.strip():
            return [left.strip(), right.strip()]
    delimiter = None
    if any(char in text for char in (",", "\t", ";", "|")):
        delimiter = _sniff_delimiter(text)
    if delimiter:
        try:
            return [item.strip() for item in
                    next(csv.reader([text], delimiter=delimiter))]
        except (csv.Error, StopIteration):
            pass
    return [item.strip() for item in re.split(r"\s+", text) if item.strip()]


def _record_from_fields(fields, source_row=None, strict=True):
    fields = [field.strip().strip('"').strip("'")
              for field in fields if field is not None and field.strip()]
    if not fields:
        return None

    sid_index = None
    sid_value = None
    invalid_sid = None
    for index, field in enumerate(fields):
        parsed = _try_sid(field)
        if parsed:
            sid_index = index
            sid_value = parsed
            break
        if _SID_PREFIX_RE.match(field):
            invalid_sid = field

    if sid_index is None:
        if invalid_sid is not None or strict:
            raise TrustedSidTableError(
                "row %s does not contain a valid SID" % (source_row,))
        return None

    before = fields[:sid_index]
    after = fields[sid_index + 1:]
    name_fields = before if before else after
    domain = None
    username = None

    if len(name_fields) == 1:
        domain, username = _normalize_name(None, name_fields[0])
    elif len(name_fields) >= 2:
        domain, username = _normalize_name(name_fields[0], name_fields[1])
    else:
        raise TrustedSidTableError(
            "row %s has a SID but no username" % (source_row,))

    note_fields = after[2:] if (before and len(after) >= 2) else (
        after[2:] if (not before and len(after) >= 3) else [])
    note = ", ".join(note_fields) if note_fields else None
    return TrustedSidRecord(username, sid_value, domain=domain, note=note,
                            source_row=source_row)


def _record_from_mapping(username, sid, source_row=None):
    return TrustedSidRecord(username, sid, source_row=source_row)


class TrustedSidTable(object):
    """
    An independent, caller-supplied SID cross-reference.

    Conflicting rows are preserved rather than silently de-duplicated.  The
    resolver refuses to make a name-only attribution unique when one name
    maps to more than one SID.
    """

    def __init__(self, records=(), source=None):
        self.source = source
        self._records = []
        self._by_sid = {}
        self._by_name = {}
        for record in records:
            if isinstance(record, TrustedSidRecord):
                item = record
            elif isinstance(record, dict):
                item = TrustedSidRecord(
                    _pick(record, "username", "user", "user_name",
                          "name", "account", "account_name",
                          "sam_account_name"),
                    _pick(record, "sid", "user_sid", "object_sid",
                          "security_identifier"),
                    domain=_pick(record, "domain", "user_domain",
                                 "netbios_domain"),
                    note=_pick(record, "note", "notes", "comment"),
                    source_row=_pick(record, "source_row", "row"))
            elif isinstance(record, (list, tuple)):
                item = _record_from_fields(record, strict=True)
            else:
                raise TrustedSidTableError(
                    "unsupported trusted SID record %r" % (record,))
            self._records.append(item)
            self._by_sid.setdefault(item.sid, []).append(item)
            self._by_name.setdefault(item.name_key, []).append(item)

        self.conflicts = self._find_conflicts()

    @property
    def present(self):
        return bool(self._records)

    def is_empty(self):
        return not self._records

    def __len__(self):
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    def records(self):
        return list(self._records)

    def records_for_sid(self, sid):
        if not sid:
            return []
        return list(self._by_sid.get(parse_sid(sid), ()))

    def records_for_name(self, username, domain=None):
        try:
            domain, username = _normalize_name(domain, username)
        except ValueError:
            return []
        if domain:
            key = _name_key(domain, username)
            result = list(self._by_name.get(key, ()))
            # A table row without a domain is still usable when the caller
            # supplied a domain, but a domain-qualified row is not silently
            # applied to a different domain.
            wildcard = _name_key(None, username)
            if wildcard != key:
                result.extend(self._by_name.get(wildcard, ()))
            return result

        # With no domain in the evidence, return every table row with this
        # username.  If the rows resolve to different SIDs the caller sees an
        # explicit ambiguity instead of a false "no mapping" or a silent pick.
        folded = username.casefold()
        result = []
        for name_key, records in self._by_name.items():
            if name_key[1] == folded:
                result.extend(records)
        return result

    def distinct_sids_for_name(self, username, domain=None):
        return sorted(set(record.sid for record in
                          self.records_for_name(username, domain=domain)))

    def conflicts_for_name(self):
        result = []
        for key, records in sorted(self._by_name.items()):
            sids = sorted(set(record.sid for record in records))
            if len(sids) > 1:
                result.append({
                    "kind": "trusted_name_has_multiple_sids",
                    "domain": key[0] or None,
                    "username": records[0].username,
                    "sids": sids,
                    "source_rows": [record.source_row for record in records],
                })
        return result

    def _find_conflicts(self):
        conflicts = []
        for key, records in sorted(self._by_name.items()):
            sids = sorted(set(record.sid for record in records))
            if len(sids) > 1:
                conflicts.append({
                    "kind": "trusted_name_has_multiple_sids",
                    "domain": key[0] or None,
                    "username": records[0].username,
                    "sids": sids,
                    "source_rows": [record.source_row for record in records],
                })
        for sid, records in sorted(self._by_sid.items()):
            names = sorted(set(record.name_key for record in records))
            if len(names) > 1:
                conflicts.append({
                    "kind": "trusted_sid_has_multiple_names",
                    "sid": sid,
                    "names": [_display_name(domain or None, username)
                              for domain, username in names],
                    "source_rows": [record.source_row for record in records],
                })
        return conflicts

    def records_for_name_and_sid(self, username, domain=None, sid=None):
        records = self.records_for_name(username, domain=domain)
        if sid is None:
            return records
        normalized = parse_sid(sid)
        return [record for record in records if record.sid == normalized]

    def to_dict(self):
        return {
            "present": self.present,
            "source": self.source,
            "entry_count": len(self._records),
            "records": [record.to_dict() for record in self._records],
            "conflicts": list(self.conflicts),
        }

    @classmethod
    def from_records(cls, records, source=None):
        return cls(records, source=source)

    @classmethod
    def from_mapping(cls, mapping, source=None):
        if not mapping:
            return cls((), source=source)
        records = []
        keys = list(mapping.keys())
        values = list(mapping.values())
        keys_are_sids = all(_try_sid(key) for key in keys)
        values_are_sids = all(_try_sid(value) for value in values)
        values_are_records = all(isinstance(value, dict) for value in values)
        if keys_are_sids and values_are_records:
            for sid_value, record in mapping.items():
                records.append(TrustedSidRecord(
                    _pick(record, "username", "user", "name",
                          "account"),
                    sid_value,
                    domain=_pick(record, "domain", "user_domain"),
                    note=_pick(record, "note", "notes", "comment")))
        elif values_are_records and not keys_are_sids:
            for name, record in mapping.items():
                sid_value = _pick(record, "sid", "user_sid",
                                  "object_sid")
                if sid_value is None:
                    raise TrustedSidTableError(
                        "mapping value for %r has no SID" % (name,))
                records.append(TrustedSidRecord(
                    name, sid_value,
                    domain=_pick(record, "domain", "user_domain"),
                    note=_pick(record, "note", "notes", "comment")))
        elif keys_are_sids and not values_are_sids:
            for sid_value, name in mapping.items():
                records.append(TrustedSidRecord(name, sid_value))
        elif values_are_sids and not keys_are_sids:
            for name, sid_value in mapping.items():
                records.append(TrustedSidRecord(name, sid_value))
        else:
            raise TrustedSidTableError(
                "ambiguous mapping: exactly one side must contain SIDs")
        return cls(records, source=source)

    @classmethod
    def from_json(cls, payload, source=None):
        if isinstance(payload, (bytes, bytearray)):
            payload = json.loads(_decode_text(payload))
        if isinstance(payload, str):
            payload = json.loads(payload)
        if isinstance(payload, list):
            records = []
            for index, item in enumerate(payload, 1):
                if isinstance(item, dict):
                    records.append(TrustedSidRecord(
                        _pick(item, "username", "user", "user_name",
                              "name", "account", "account_name",
                              "sam_account_name"),
                        _pick(item, "sid", "user_sid", "object_sid",
                              "security_identifier"),
                        domain=_pick(item, "domain", "user_domain",
                                     "netbios_domain"),
                        note=_pick(item, "note", "notes", "comment"),
                        source_row=_pick(item, "source_row", "row")
                        or index))
                elif isinstance(item, (list, tuple)):
                    records.append(_record_from_fields(item,
                                                       source_row=index))
                else:
                    record = _record_from_fields(_split_mount_line(str(item)),
                                                 source_row=index)
                    if record:
                        records.append(record)
            return cls(records, source=source)
        if isinstance(payload, dict):
            for key in ("records", "entries", "users", "mappings", "table"):
                if key in payload:
                    return cls.from_json(payload[key], source=source)
            if (_pick(payload, "username", "user", "name",
                      "account") is not None
                    and _pick(payload, "sid", "user_sid",
                              "object_sid") is not None):
                record = TrustedSidRecord(
                    _pick(payload, "username", "user", "name",
                          "account"),
                    _pick(payload, "sid", "user_sid", "object_sid"),
                    domain=_pick(payload, "domain", "user_domain"),
                    note=_pick(payload, "note", "notes", "comment"))
                return cls([record], source=source)
            return cls.from_mapping(payload, source=source)
        raise TrustedSidTableError("unsupported JSON SID table")

    @classmethod
    def from_text(cls, text, source=None):
        records = []
        for index, line in enumerate(_decode_text(text).splitlines(), 1):
            fields = _split_mount_line(line)
            if not fields:
                continue
            record = _record_from_fields(fields, source_row=index)
            if record:
                records.append(record)
        if not records:
            return cls((), source=source)
        return cls(records, source=source)

    @classmethod
    def from_csv(cls, text, source=None):
        lines = [line for line in _decode_text(text).splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if not lines:
            return cls((), source=source)
        delimiter = _sniff_delimiter(lines[0])
        rows = list(csv.reader(lines, delimiter=delimiter))
        records = []
        header = None
        if rows and _looks_like_header(rows[0]):
            header = [_column_key(field) for field in rows[0]]
            rows = rows[1:]

        for index, row in enumerate(rows, 1):
            if not any(field.strip() for field in row):
                continue
            if header:
                data = {}
                for column, field in zip(header, row):
                    data[column] = field.strip()
                username = None
                sid_value = None
                domain = None
                note = None
                for column, field in data.items():
                    if column in _USERNAME_COLUMNS and username is None:
                        username = field
                    elif column in _SID_COLUMNS and sid_value is None:
                        sid_value = field
                    elif column in _DOMAIN_COLUMNS and domain is None:
                        domain = field
                    elif column in _NOTE_COLUMNS and note is None:
                        note = field
                if not username or not sid_value:
                    raise TrustedSidTableError(
                        "row %s is missing username or SID" % (index,))
                records.append(TrustedSidRecord(
                    username, sid_value, domain=domain, note=note,
                    source_row=index))
            else:
                record = _record_from_fields(row, source_row=index)
                if record:
                    records.append(record)
        if not records:
            return cls((), source=source)
        return cls(records, source=source)

    @classmethod
    def load(cls, source, format=None, strict=True):
        if isinstance(source, TrustedSidTable):
            return source
        if source is None:
            return cls(())
        if isinstance(source, dict):
            return cls.from_json(source)
        if isinstance(source, (list, tuple)):
            return cls.from_records(source)

        label = None
        if isinstance(source, (bytes, bytearray)):
            payload = bytes(source)
        elif isinstance(source, str):
            # A caller may pass the table text directly (especially with an
            # explicit ``format``) instead of a filename.  Only an existing
            # path is opened; otherwise a string containing a newline,
            # delimiter, or an explicit format is treated as content.
            path_exists = False
            try:
                path_exists = os.path.exists(source)
            except (OSError, ValueError):
                path_exists = False
            if path_exists:
                label = source
                with open(label, "rb") as stream:
                    payload = stream.read()
            elif (format is not None or "\n" in source or "\r" in source
                  or any(delimiter in source
                         for delimiter in (",", ";", "\t"))
                  or "S-1-" in source.upper()):
                payload = source.encode("utf-8")
            else:
                label = source
                with open(label, "rb") as stream:
                    payload = stream.read()
        else:
            if hasattr(source, "read"):
                label = getattr(source, "name", None)
                if hasattr(source, "seek"):
                    try:
                        source.seek(0)
                    except Exception:
                        pass
                payload = source.read()
            else:
                label = _fspath(source)
                with open(label, "rb") as stream:
                    payload = stream.read()

        if not isinstance(payload, (bytes, bytearray)):
            payload = _decode_text(payload).encode("utf-8")
        text = _decode_text(payload)
        guessed = format
        if guessed is None and label:
            extension = os.path.splitext(str(label))[1].lower()
            guessed = {
                ".json": "json",
                ".csv": "csv",
                ".tsv": "tsv",
                ".txt": "text",
            }.get(extension)
        if guessed is None:
            stripped = text.lstrip("\ufeff \t\r\n")
            if stripped.startswith(("{", "[")):
                guessed = "json"
            elif "\t" in text.splitlines()[0] if text.splitlines() else False:
                guessed = "tsv"
            elif any(char in (text.splitlines()[0] if text.splitlines()
                              else "") for char in (",", ";")):
                guessed = "csv"
            else:
                guessed = "text"

        if guessed == "json":
            return cls.from_json(text, source=label)
        if guessed in ("csv", "tsv"):
            return cls.from_csv(text, source=label)
        return cls.from_text(text, source=label)

    from_file = load


def load_trusted_sid_table(source, format=None, strict=True):
    """Load an explicit SID cross-reference from a path, file, or records."""
    return TrustedSidTable.load(source, format=format, strict=strict)


class HiveEvidence(object):
    """
    One physical hive occurrence in the case.

    Two occurrences with the same bytes remain two provenance records but
    are grouped as a mirror; they do not become two users.
    """

    def __init__(self, evidence_id, source_path=None, registry=None,
                 sha256=None, hive_type=None, label=None, mount_notes=(),
                 clues=(), errors=(), metadata=None, scope=None, size=None):
        self.evidence_id = evidence_id
        self.source_path = source_path
        self.explicit_label = label is not None
        self.label = label or (os.path.basename(source_path)
                               if source_path else None)
        self._registry = registry
        self.sha256 = sha256
        self.hive_type = hive_type or "unknown"
        self.mount_notes = list(mount_notes)
        self.clues = list(clues)
        self.errors = list(errors)
        self.metadata = dict(metadata or {})
        self.scope = scope or "unknown"
        self.size = size
        self.mirror_of = None
        self.mirror_group = None
        self.mirror_candidate = False

    @property
    def source(self):
        return SourceKind.HIVE

    @property
    def registry(self):
        return self._registry

    def add_clue(self, clue):
        key = (clue.kind.value, clue.normalized, clue.source.value,
               clue.group, clue.locator)
        for existing in self.clues:
            if (existing.kind.value, existing.normalized,
                    existing.source.value, existing.group,
                    existing.locator) == key:
                return existing
        self.clues.append(clue)
        return clue

    def add_mount_note(self, note):
        if isinstance(note, str):
            note = parse_mount_note(note, evidence_id=self.evidence_id)
        if note is None:
            return None
        note.evidence_id = self.evidence_id
        self.mount_notes.append(note)
        for clue in note.clues:
            clue.evidence_id = self.evidence_id
            self.add_clue(clue)
        return note

    def clues_of(self, kind, source=None):
        result = []
        for clue in self.clues:
            if clue.kind != ClueKind(kind):
                continue
            if source is not None and clue.source != SourceKind(source):
                continue
            result.append(clue)
        return result

    @property
    def machine_sid(self):
        return self.metadata.get("machine_sid")

    def to_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "label": self.label,
            "sha256": self.sha256,
            "size": self.size,
            "hive_type": self.hive_type,
            "scope": self.scope,
            "machine_sid": self.machine_sid,
            "mount_notes": [note.to_dict() for note in self.mount_notes],
            "mirror_of": self.mirror_of,
            "mirror_group": self.mirror_group,
            "mirror_candidate": self.mirror_candidate,
            "clues": [clue.to_dict() for clue in self.clues],
            "errors": list(self.errors),
        }

    def __repr__(self):
        return "HiveEvidence(%r, hive_type=%r, clues=%d)" % (
            self.evidence_id, self.hive_type, len(self.clues))


_STANDARD_REG_TYPES = frozenset((
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000A, 0x000B,
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016,
))


def _optional_key(reg, path):
    try:
        return reg.open(path)
    except (RegistryKeyNotFoundException, RegistryValueNotFoundException):
        return None
    except Exception:
        return None


def _optional_value(key, name):
    if key is None:
        return None
    try:
        return key.value(name)
    except (RegistryKeyNotFoundException, RegistryValueNotFoundException):
        return None
    except Exception:
        return None


def _string_value(value):
    if value is None:
        return None
    try:
        return _clean_text(value.value())
    except Exception:
        try:
            return _clean_text(value.raw_data())
        except Exception:
            return None


def _binary_value(value):
    if value is None:
        return None
    try:
        data = value.value()
    except Exception:
        try:
            data = value.raw_data()
        except Exception:
            return None
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, int):
        return struct.pack("<I", data & 0xFFFFFFFF)
    return None


def _rid_from_name_default(values):
    for value in values:
        if value.name() not in ("(default)", ""):
            continue
        try:
            data_type = value.value_type()
        except Exception:
            data_type = None
        if (isinstance(data_type, int) and data_type > 0
                and data_type not in _STANDARD_REG_TYPES
                and data_type <= 0x3FFFFFFF):
            return int(data_type)

        data = _binary_value(value)
        if data:
            candidates = []
            if len(data) >= 8:
                candidates.append(struct.unpack_from("<I", data, 4)[0])
            if len(data) >= 4:
                candidates.append(struct.unpack_from("<I", data, 0)[0])
            for candidate in candidates:
                if 0 < candidate <= 0x3FFFFFFF:
                    return candidate

        try:
            value_data = value.value()
        except Exception:
            value_data = None
        if isinstance(value_data, int) and 0 < value_data <= 0x3FFFFFFF:
            return int(value_data)
    return None


def _sam_machine_sid(reg):
    key = _optional_key(reg, "SAM\\Domains\\Account")
    value = _optional_value(key, "V")
    data = _binary_value(value)
    if not data:
        return None

    candidates = []
    for offset in range(0, len(data) - 8):
        if data[offset] != 1:
            continue
        count = data[offset + 1]
        if count < 1 or count > 15 or offset + 8 + 4 * count > len(data):
            continue
        authority = _int_from_bytes_be(data[offset + 2:offset + 8])
        if authority != 5:
            continue
        try:
            sid = sid_from_binary(data, offset)
        except ValueError:
            continue
        subauthorities = _sid_subauthorities(sid)
        if len(subauthorities) >= 4 and subauthorities[0] == 21:
            candidates.append(sid)
    if not candidates:
        return None
    return candidates[-1]


def _parse_sam_v(data):
    """Decode username/profile fields from a SAM ``V`` value."""
    result = {}
    if not data or len(data) < 0xCC:
        return result
    base = 0xCC
    fields = (
        ("username", 0x0C),
        ("full_name", 0x18),
        ("comment", 0x24),
        ("user_comment", 0x30),
        ("home_directory", 0x48),
        ("home_directory_connect", 0x54),
        ("script_path", 0x60),
        ("profile_path", 0x6C),
        ("workstations", 0x78),
    )
    for name, position in fields:
        if position + 8 > len(data):
            continue
        offset = struct.unpack_from("<I", data, position)[0]
        length = struct.unpack_from("<I", data, position + 4)[0]
        if length == 0 or length > 4096 or length % 2:
            continue
        start = base + offset
        end = start + length
        if start < 0 or start >= len(data) or end > len(data):
            continue
        try:
            text = data[start:end].decode("utf-16le", "replace")
        except Exception:
            continue
        text = text.replace("\x00", "").strip()
        if text and not any(ord(char) < 0x20 for char in text):
            result[name] = text
    return result


def _f_value_rid(data, expected_rid=None):
    if not data:
        return None
    candidates = []
    if len(data) >= 0x34:
        candidates.append(struct.unpack_from("<I", data, 0x30)[0])
    for offset in range(0, max(0, len(data) - 3), 4):
        candidates.append(struct.unpack_from("<I", data, offset)[0])
    if expected_rid is not None:
        for candidate in candidates:
            if candidate == expected_rid:
                return candidate
    for candidate in candidates:
        if 0 < candidate <= 0x3FFFFFFF:
            return candidate
    return None


def _add_clue(evidence, kind, value, locator, confidence, domain=None,
              detail=None, tags=(), group=None):
    if value is None:
        return None
    try:
        clue = EvidenceClue(
            kind=kind,
            value=value,
            source=SourceKind.HIVE,
            evidence_id=evidence.evidence_id,
            locator=locator,
            confidence=confidence,
            domain=domain,
            detail=detail,
            tags=tags,
            group=group,
        )
    except (TypeError, ValueError):
        return None
    return evidence.add_clue(clue)


def _add_profile_path(evidence, path, locator, confidence, group,
                      tags=()):
    path = _clean_text(path)
    if not path:
        return
    derived = username_from_profile_path(path)
    clue_tags = tuple(tags)
    if _is_machine_default_path(path):
        clue_tags += ("machine_default",)
    _add_clue(evidence, ClueKind.PROFILE_PATH, path, locator, confidence,
              detail="profile path", tags=clue_tags, group=group)
    if derived:
        _, username, machine_default = derived
        if machine_default:
            clue_tags += ("machine_default",)
        _add_clue(evidence, ClueKind.USERNAME, username, locator,
                  confidence if confidence != Confidence.HIGH
                  else Confidence.MEDIUM,
                  detail="derived from profile path", tags=clue_tags,
                  group=group)
    elif "machine_default" in clue_tags:
        candidate = _profile_name_from_path(path)
        if candidate:
            _add_clue(evidence, ClueKind.USERNAME, candidate, locator,
                      Confidence.LOW, detail="default profile path",
                      tags=clue_tags, group=group)


def _extract_ntuser(reg, evidence):
    for path, confidence, group_name in (
            ("Volatile Environment", Confidence.HIGH, "ntuser:volatile"),
            ("Environment", Confidence.MEDIUM, "ntuser:environment")):
        key = _optional_key(reg, path)
        if key is None:
            continue
        for value in key.values():
            name = value.name().upper()
            text = _string_value(value)
            locator = "%s:%s" % (path, value.name())
            if name in ("USERNAME", "USER", "LOGON_USER"):
                _add_clue(evidence, ClueKind.USERNAME, text, locator,
                          confidence, group=group_name)
            elif name in ("USERDOMAIN", "DOMAIN", "LOGON_DOMAIN"):
                _add_clue(evidence, ClueKind.DOMAIN, text, locator,
                          confidence, group=group_name)
            elif name in ("USERPROFILE", "HOMEPATH", "APPDATA",
                          "LOCALAPPDATA", "HOMESHARE"):
                _add_profile_path(evidence, text, locator, confidence,
                                  group_name)

    for path, confidence, group_name in (
            ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
             "\\Shell Folders", Confidence.MEDIUM, "ntuser:shell-folders"),
            ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
             "\\User Shell Folders", Confidence.LOW,
             "ntuser:user-shell-folders")):
        key = _optional_key(reg, path)
        if key is None:
            continue
        for value in key.values():
            text = _string_value(value)
            if not text or "\\" not in text and "/" not in text:
                continue
            _add_profile_path(evidence, text,
                              "%s:%s" % (path, value.name()),
                              confidence, group_name)

    key = _optional_key(
        reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
             "\\Logon User Name")
    if key is not None:
        for value in key.values():
            text = _string_value(value)
            if text:
                _add_clue(evidence, ClueKind.USERNAME, text,
                          "Logon User Name:%s" % (value.name(),),
                          Confidence.MEDIUM, group="ntuser:logon-user-name")

    key = _optional_key(
        reg, "Software\\Microsoft\\Protected Storage System Provider")
    if key is not None:
        for subkey in key.subkeys():
            sid = _try_sid(subkey.name())
            if sid:
                _add_clue(evidence, ClueKind.SID, sid,
                          "Protected Storage System Provider\\%s"
                          % (subkey.name(),), Confidence.MEDIUM,
                          group="ntuser:psp:%s" % (sid,))


def _extract_sam(reg, evidence):
    machine_sid = _sam_machine_sid(reg)
    if machine_sid:
        evidence.metadata["machine_sid"] = machine_sid
        _add_clue(evidence, ClueKind.MACHINE_SID, machine_sid,
                  "SAM\\Domains\\Account:V", Confidence.HIGH,
                  detail="machine SID; used only to construct account SIDs",
                  tags=("machine_sid",), group="sam:machine")

    rid_to_name = {}
    names_key = _optional_key(reg, "SAM\\Domains\\Account\\Users\\Names")
    if names_key is not None:
        for subkey in names_key.subkeys():
            username = _clean_text(subkey.name())
            if not username:
                continue
            try:
                _, username = _normalize_name(None, username)
            except ValueError:
                continue
            rid = _rid_from_name_default(subkey.values())
            group = "sam-account:%s" % (rid if rid is not None
                                         else username.casefold(),)
            locator = "SAM\\Domains\\Account\\Users\\Names\\%s" % (
                subkey.name(),)
            _add_clue(evidence, ClueKind.USERNAME, username, locator,
                      Confidence.HIGH, group=group)
            if rid is not None:
                rid_to_name[rid] = username
                _add_clue(evidence, ClueKind.RID, rid, locator,
                          Confidence.MEDIUM, group=group)
                if machine_sid:
                    account_sid = "%s-%d" % (machine_sid, rid)
                    _add_clue(evidence, ClueKind.SID, account_sid, locator,
                              Confidence.HIGH,
                              detail="machine SID + SAM RID", group=group)

    users_key = _optional_key(reg, "SAM\\Domains\\Account\\Users")
    if users_key is None:
        return
    for subkey in users_key.subkeys():
        if subkey.name().casefold() == "names":
            continue
        try:
            rid = int(subkey.name(), 16)
        except (TypeError, ValueError):
            continue
        group = "sam-account:%s" % (rid,)
        locator = "SAM\\Domains\\Account\\Users\\%s" % (subkey.name(),)

        f_value = _optional_value(subkey, "F")
        f_data = _binary_value(f_value)
        f_rid = _f_value_rid(f_data, expected_rid=rid)
        if f_rid is not None:
            _add_clue(evidence, ClueKind.RID, f_rid, locator + ":F",
                      Confidence.MEDIUM, group=group)

        v_value = _optional_value(subkey, "V")
        v_data = _binary_value(v_value)
        parsed = _parse_sam_v(v_data)
        username = parsed.get("username")
        if username:
            _add_clue(evidence, ClueKind.USERNAME, username, locator + ":V",
                      Confidence.HIGH, group=group)
        if parsed.get("profile_path"):
            _add_profile_path(evidence, parsed["profile_path"],
                              locator + ":V", Confidence.HIGH, group,
                              tags=("sam_profile_path",))
        if parsed.get("home_directory"):
            _add_profile_path(evidence, parsed["home_directory"],
                              locator + ":V", Confidence.MEDIUM, group)

        if machine_sid:
            account_sid = "%s-%d" % (machine_sid, rid)
            _add_clue(evidence, ClueKind.SID, account_sid, locator,
                      Confidence.HIGH,
                      detail="machine SID + SAM RID", group=group)

        if rid not in rid_to_name and username:
            rid_to_name[rid] = username

    evidence.metadata["sam_accounts"] = [
        {"rid": rid, "username": username}
        for rid, username in sorted(rid_to_name.items())
    ]


def _extract_software(reg, evidence):
    key = _optional_key(
        reg, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    if key is not None:
        for subkey in key.subkeys():
            sid = _try_sid(subkey.name())
            if not sid:
                continue
            group = "profile:%s" % (sid,)
            locator = "ProfileList\\%s" % (subkey.name(),)
            tags = ("machine_default",) if _is_machine_default_sid(sid) else ()
            _add_clue(evidence, ClueKind.SID, sid, locator,
                      Confidence.HIGH, tags=tags, group=group)

            sid_raw = _optional_value(subkey, "Sid")
            sid_value = _binary_value(sid_raw)
            sid_text = _string_value(sid_raw)
            if not sid_value and sid_text:
                sid_value = sid_text
            if sid_value:
                binary_sid = _try_sid(sid_value)
                if binary_sid:
                    _add_clue(evidence, ClueKind.SID, binary_sid,
                              locator + ":Sid", Confidence.HIGH, group=group)
                    if binary_sid != sid:
                        evidence.metadata.setdefault(
                            "profile_sid_mismatches", []).append({
                                "key_sid": sid,
                                "value_sid": binary_sid,
                                "locator": locator,
                            })

            profile_path = _string_value(
                _optional_value(subkey, "ProfileImagePath"))
            if profile_path:
                path_tags = tuple(tags)
                derived = username_from_profile_path(profile_path)
                if derived and derived[2]:
                    path_tags += ("machine_default",)
                _add_profile_path(evidence, profile_path,
                                  locator + ":ProfileImagePath",
                                  Confidence.HIGH, group, tags=path_tags)

    for path in (
            "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI",
            "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"):
        key = _optional_key(reg, path)
        if key is None:
            continue
        for value in key.values():
            name = value.name().casefold()
            if name not in ("lastloggedonuser", "lastloggedonsamuser",
                            "defaultusername", "defaultuser"):
                continue
            text = _string_value(value)
            if not text:
                continue
            try:
                domain, username = _normalize_name(None, text)
            except ValueError:
                continue
            _add_clue(evidence, ClueKind.USERNAME, username,
                      "%s:%s" % (path, value.name()), Confidence.LOW,
                      domain=domain,
                      tags=("autologon",) if "Default" in value.name()
                      else ("last_logon",),
                      group="logonui:%s" % (path,))
            if domain:
                _add_clue(evidence, ClueKind.DOMAIN, domain,
                          "%s:%s" % (path, value.name()), Confidence.LOW,
                          group="logonui:%s" % (path,))

    key = _optional_key(
        reg, "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"
             "\\SessionData")
    if key is not None:
        for index, subkey in enumerate(key.subkeys()):
            if index >= 128:
                break
            for value in subkey.values():
                name = value.name().casefold()
                text = _string_value(value)
                if not text:
                    continue
                locator = "SessionData\\%s:%s" % (subkey.name(), value.name())
                if name in ("loggedonuser", "loggedonsamuser"):
                    try:
                        domain, username = _normalize_name(None, text)
                    except ValueError:
                        continue
                    _add_clue(evidence, ClueKind.USERNAME, username, locator,
                              Confidence.LOW, domain=domain,
                              tags=("last_logon",),
                              group="logon-session:%s" % (subkey.name(),))
                elif name in ("loggedonusersid", "sid"):
                    sid = _try_sid(text)
                    if sid:
                        _add_clue(evidence, ClueKind.SID, sid, locator,
                                  Confidence.LOW, tags=("last_logon",),
                                  group="logon-session:%s" % (subkey.name(),))


def _extract_security(reg, evidence):
    key = _optional_key(reg, "Policy\\Accounts")
    if key is None:
        return
    for subkey in key.subkeys():
        sid = _try_sid(subkey.name())
        if sid:
            _add_clue(evidence, ClueKind.SID, sid,
                      "Policy\\Accounts\\%s" % (subkey.name(),),
                      Confidence.LOW, tags=("security_policy_account",),
                      group="security:%s" % (sid,))


def _extract_system(reg, evidence):
    select = _optional_key(reg, "Select")
    control_set = None
    if select is not None:
        value = _optional_value(select, "Current")
        try:
            if value is not None:
                control_set = int(value.value())
        except Exception:
            control_set = None
    control_sets = []
    if control_set is not None:
        control_sets.append("ControlSet%03d" % (control_set,))
    control_sets.extend(["ControlSet001", "ControlSet002"])

    for control in control_sets:
        key = _optional_key(
            reg, "%s\\Control\\Session Manager\\Environment" % (control,))
        if key is None:
            continue
        for value in key.values():
            name = value.name().upper()
            text = _string_value(value)
            locator = "%s\\Control\\Session Manager\\Environment:%s" % (
                control, value.name())
            if name in ("USERNAME", "USER"):
                _add_clue(evidence, ClueKind.USERNAME, text, locator,
                          Confidence.LOW, group="system:environment")
            elif name in ("USERPROFILE", "HOMEPATH", "APPDATA"):
                _add_profile_path(evidence, text, locator, Confidence.LOW,
                                  "system:environment")
        break


def _infer_hive_type(reg):
    try:
        hive_type = reg.hive_type()
    except Exception:
        hive_type = HiveType.UNKNOWN
    if hive_type != HiveType.UNKNOWN:
        return hive_type.value

    try:
        root_names = set(subkey.name().casefold()
                         for subkey in reg.root().subkeys())
    except Exception:
        root_names = set()
    if "sam" in root_names:
        return HiveType.SAM.value
    if "software" in root_names:
        return HiveType.NTUSER.value
    if "microsoft" in root_names:
        return HiveType.SOFTWARE.value
    if "controlset001" in root_names or "select" in root_names:
        return HiveType.SYSTEM.value
    if "policy" in root_names:
        return HiveType.SECURITY.value
    return HiveType.UNKNOWN.value


def _infer_scope(reg, hive_type):
    if hive_type in (HiveType.NTUSER.value, HiveType.USRCLASS.value):
        return "user"
    if hive_type in (HiveType.SAM.value, HiveType.SOFTWARE.value,
                     HiveType.SYSTEM.value, HiveType.SECURITY.value,
                     HiveType.DEFAULT.value):
        return "machine"
    try:
        root_names = set(subkey.name().casefold()
                         for subkey in reg.root().subkeys())
    except Exception:
        root_names = set()
    if "software" in root_names:
        return "user"
    if "volatile environment" in root_names or "environment" in root_names:
        return "user"
    if ("sam" in root_names or "policy" in root_names
            or "controlset001" in root_names or "microsoft" in root_names):
        return "machine"
    return "unknown"


def _extract_all(reg, evidence):
    hive_type = evidence.hive_type
    extractors = []
    if hive_type == HiveType.SAM.value:
        extractors.append(("sam", _extract_sam))
    elif hive_type in (HiveType.NTUSER.value, HiveType.USRCLASS.value):
        extractors.append(("ntuser", _extract_ntuser))
    elif hive_type == HiveType.SOFTWARE.value:
        extractors.append(("software", _extract_software))
    elif hive_type == HiveType.SECURITY.value:
        extractors.append(("security", _extract_security))
        extractors.append(("sam", _extract_sam))
    elif hive_type == HiveType.SYSTEM.value:
        extractors.append(("system", _extract_system))
    else:
        extractors.extend((
            ("ntuser", _extract_ntuser),
            ("software", _extract_software),
            ("sam", _extract_sam),
            ("security", _extract_security),
            ("system", _extract_system),
        ))

    # Known paths may still exist in a hive whose internal name is missing or
    # anonymised; try the user and account extractors without requiring a
    # perfect header match.
    if hive_type not in (HiveType.NTUSER.value, HiveType.USRCLASS.value):
        if _optional_key(reg, "Volatile Environment") is not None:
            extractors.append(("ntuser", _extract_ntuser))
    if hive_type != HiveType.SAM.value:
        if _optional_key(reg, "SAM\\Domains\\Account") is not None:
            extractors.append(("sam", _extract_sam))

    seen = set()
    for name, extractor in extractors:
        if name in seen:
            continue
        seen.add(name)
        try:
            extractor(reg, evidence)
        except Exception as exc:
            evidence.errors.append("%s extractor: %s: %s" % (
                name, type(exc).__name__, exc))


def _read_source_bytes(source):
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if isinstance(source, Registry):
        data = getattr(source, "_buf", None)
        if data is None:
            raise ValueError("Registry object does not expose its buffer")
        return bytes(data)
    if hasattr(source, "read"):
        if hasattr(source, "seek"):
            try:
                source.seek(0)
            except Exception:
                pass
        data = source.read()
        if isinstance(data, str):
            data = data.encode("latin-1")
        return bytes(data)
    path = _fspath(source)
    with open(path, "rb") as stream:
        return stream.read()


def _coerce_hive_source(spec, default_id):
    mount_note = None
    label = None
    evidence_id = default_id
    if isinstance(spec, HiveEvidence):
        return spec, None, None
    if isinstance(spec, dict):
        evidence_id = spec.get("evidence_id") or spec.get("id") or default_id
        label = spec.get("label")
        mount_note = spec.get("mount_note", spec.get("mount_notes"))
        if "registry" in spec:
            source = spec["registry"]
        elif "data" in spec:
            source = spec["data"]
        elif "bytes" in spec:
            source = spec["bytes"]
        elif "raw" in spec:
            source = spec["raw"]
        elif "filelike" in spec:
            source = spec["filelike"]
        elif "file" in spec:
            source = spec["file"]
        elif "path" in spec:
            source = spec["path"]
        else:
            raise ValueError("hive specification has no path or data")
        return source, evidence_id, (label, mount_note)
    return spec, evidence_id, (label, mount_note)


def read_hive_evidence(source, evidence_id=None, mount_note=None, label=None):
    """
    Read and analyze one hive without modifying it.

    ``source`` may be a path, bytes, a file-like object, a parsed
    ``Registry`` object, or a specification dictionary.
    """
    if isinstance(source, HiveEvidence):
        if mount_note:
            for note in (mount_note if isinstance(mount_note, (list, tuple))
                         else [mount_note]):
                source.add_mount_note(note)
        return source

    default_id = evidence_id or "H1"
    source, evidence_id, extra = _coerce_hive_source(source, default_id)
    if evidence_id is None:
        evidence_id = default_id
    if extra:
        extra_label, extra_note = extra
        label = label or extra_label
        if mount_note is None:
            mount_note = extra_note

    try:
        raw = _read_source_bytes(source)
    except Exception as exc:
        evidence = HiveEvidence(
            evidence_id=evidence_id, source_path=str(source), label=label,
            errors=["read error: %s: %s" % (type(exc).__name__, exc)],
            scope="unknown")
        if mount_note:
            for note in (mount_note if isinstance(mount_note, (list, tuple))
                         else [mount_note]):
                evidence.add_mount_note(note)
        return evidence

    digest = hashlib.sha256(raw).hexdigest()
    source_path = None
    if isinstance(source, str):
        source_path = source
    elif hasattr(os, "PathLike") and isinstance(source, os.PathLike):
        source_path = _fspath(source)
    elif hasattr(source, "name") and isinstance(getattr(source, "name"), str):
        source_path = source.name

    try:
        reg = Registry(io.BytesIO(raw))
        hive_type = _infer_hive_type(reg)
        scope = _infer_scope(reg, hive_type)
        evidence = HiveEvidence(
            evidence_id=evidence_id,
            source_path=source_path,
            registry=reg,
            sha256=digest,
            hive_type=hive_type,
            label=label,
            scope=scope,
            size=len(raw),
        )
        _extract_all(reg, evidence)
    except Exception as exc:
        evidence = HiveEvidence(
            evidence_id=evidence_id,
            source_path=source_path,
            sha256=digest,
            hive_type="unknown",
            label=label,
            scope="unknown",
            size=len(raw),
            errors=["parse error: %s: %s" % (type(exc).__name__, exc)])

    if mount_note:
        for note in (mount_note if isinstance(mount_note, (list, tuple))
                     else [mount_note]):
            evidence.add_mount_note(note)

    # The export name/path is provenance too.  Parse it conservatively; a
    # generic temporary path yields no clues.
    if not evidence.mount_notes:
        candidate_text = (evidence.label if evidence.explicit_label
                          else source_path or evidence.label)
        if candidate_text:
            note = parse_mount_note(candidate_text,
                                    evidence_id=evidence.evidence_id)
            if note.clues:
                evidence.add_mount_note(note)
    return evidence


def analyze_hive(source, evidence_id=None, mount_note=None, label=None):
    """Alias for :func:`read_hive_evidence`."""
    return read_hive_evidence(source, evidence_id=evidence_id,
                              mount_note=mount_note, label=label)


def extract_hive_clues(source, evidence_id=None, mount_note=None):
    """Return the extracted clue list for one hive."""
    return read_hive_evidence(source, evidence_id=evidence_id,
                              mount_note=mount_note).clues


class Conflict(object):
    """An evidence conflict that must remain visible to the reviewer."""

    def __init__(self, kind, message, subject=None, values=(), sources=(),
                 severity="error"):
        self.kind = kind
        self.message = message
        self.subject = subject
        self.values = list(values)
        self.sources = list(sources)
        self.severity = severity

    def to_dict(self):
        return {
            "kind": self.kind,
            "severity": self.severity,
            "subject": self.subject,
            "message": self.message,
            "values": self.values,
            "sources": self.sources,
        }

    def __repr__(self):
        return "Conflict(%s, %s)" % (self.kind, self.message)


class IdentityHypothesis(object):
    """
    A group of evidence clues believed to describe one account.

    The object may be populated in an unresolved/provisional state.  Inspect
    ``unique`` and ``status`` before treating it as an attribution.
    """

    def __init__(self, identity_id, sid=None, username=None, domain=None,
                 kind="user"):
        self.identity_id = identity_id
        self.sid = sid
        self.username = username
        self.domain = domain
        self.kind = kind
        self.status = ResolutionStatus.UNRESOLVED
        self.unique = False
        self.confidence = Confidence.UNVERIFIED
        self.trusted_match = None
        self.reason = None
        self.evidence_ids = []
        self.clues = []
        self.observed_sids = []
        self.observed_names = []
        self.profile_paths = []
        self.mirror_groups = []
        self.sid_missing_evidence_ids = []
        self.conflicts = []
        self.warnings = []
        self.trusted_records = []

    @property
    def display_name(self):
        return _display_name(self.domain, self.username) if self.username else None

    @property
    def confidence_score(self):
        return self.confidence.score

    @property
    def sources(self):
        return list(self.evidence_ids)

    @property
    def provenance(self):
        return [clue.provenance() for clue in self.clues]

    @property
    def provisional(self):
        return self.status == ResolutionStatus.UNRESOLVED and (
            self.sid is not None or self.username is not None)

    @property
    def is_unique(self):
        return self.unique

    @property
    def resolved(self):
        return self.status == ResolutionStatus.RESOLVED

    def add_clues(self, clues):
        for clue in clues:
            if clue not in self.clues:
                self.clues.append(clue)

    def add_evidence(self, evidence_id):
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def to_dict(self):
        return {
            "identity_id": self.identity_id,
            "kind": self.kind,
            "sid": self.sid,
            "username": self.username,
            "domain": self.domain,
            "display_name": self.display_name,
            "status": self.status.value,
            "unique": self.unique,
            "provisional": self.provisional,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence.score,
            "trusted_match": self.trusted_match,
            "reason": self.reason,
            "evidence_ids": sorted(self.evidence_ids),
            "observed_sids": sorted(self.observed_sids),
            "observed_names": [list(item) for item in self.observed_names],
            "profile_paths": sorted(self.profile_paths),
            "mirror_groups": sorted(self.mirror_groups),
            "sid_missing_evidence_ids": sorted(
                self.sid_missing_evidence_ids),
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "warnings": list(self.warnings),
            "trusted_records": [record.to_dict()
                                for record in self.trusted_records],
            "clues": [clue.to_dict() for clue in self.clues],
        }

    def __repr__(self):
        return "IdentityHypothesis(%r, status=%s, unique=%r)" % (
            self.identity_id, self.status.value, self.unique)


class EvidenceAttribution(object):
    """Per-hive attribution result, with provisional candidates retained."""

    def __init__(self, evidence_id, scope, status, unique=False,
                 identity_id=None, sid=None, username=None, domain=None,
                 confidence=Confidence.UNVERIFIED, candidate_ids=(),
                 reason=None):
        self.evidence_id = evidence_id
        self.scope = scope
        self.status = ResolutionStatus(status)
        self.unique = bool(unique)
        self.identity_id = identity_id if unique else None
        self.sid = sid if unique else None
        self.username = username if unique else None
        self.domain = domain if unique else None
        self.confidence = Confidence(confidence)
        self.candidate_ids = sorted(candidate_ids)
        self.reason = reason

    @property
    def confidence_score(self):
        return self.confidence.score

    def to_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "scope": self.scope,
            "status": self.status.value,
            "unique": self.unique,
            "identity_id": self.identity_id,
            "sid": self.sid,
            "username": self.username,
            "domain": self.domain,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence.score,
            "candidate_ids": list(self.candidate_ids),
            "reason": self.reason,
        }

    def __bool__(self):
        return self.unique

    __nonzero__ = __bool__

    def __repr__(self):
        return "EvidenceAttribution(%r, unique=%r, status=%s)" % (
            self.evidence_id, self.unique, self.status.value)


class _FactGroup(object):
    def __init__(self, group_id, evidence_id, scope):
        self.group_id = group_id
        self.evidence_id = evidence_id
        self.scope = scope
        self.clues = []
        self.sids = set()
        self.hive_sids = set()
        self.mount_sids = set()
        self.names = []
        self.name_keys = set()
        self.profile_paths = set()
        self.domains = set()
        self.tags = set()
        self.sid_missing = False
        self.sid_inferred = False

    def add(self, clue):
        self.clues.append(clue)
        self.tags.update(clue.tags)
        if clue.kind == ClueKind.SID:
            self.sids.add(clue.value)
            if clue.source == SourceKind.HIVE:
                self.hive_sids.add(clue.value)
            elif clue.source == SourceKind.MOUNT_NOTE:
                self.mount_sids.add(clue.value)
        elif clue.kind == ClueKind.USERNAME:
            key = _name_key(clue.domain, clue.value)
            if key not in self.name_keys:
                self.name_keys.add(key)
                self.names.append((clue.domain, clue.value))
        elif clue.kind == ClueKind.PROFILE_PATH:
            self.profile_paths.add(clue.value)
        elif clue.kind == ClueKind.DOMAIN and clue.value:
            self.domains.add(clue.value)

    @property
    def identity_sids(self):
        # Hive-internal SIDs outrank mount annotations for identity keys.
        # A conflicting mount SID is still kept as provenance and reported
        # as a mount conflict, but it must not create a second person.
        return set(self.hive_sids) or set(self.mount_sids)


def _group_facts(evidence):
    facts_by_group = {}
    for clue in evidence.clues:
        if clue.kind == ClueKind.MACHINE_SID:
            continue
        group_id = clue.group or clue.locator
        if evidence.scope == "user":
            group_id = "user:%s" % (evidence.evidence_id,)
        elif evidence.scope == "unknown":
            # If the hive has at most one account's worth of clues, keep the
            # clues together; otherwise respect extraction-local groups.
            group_id = clue.group or clue.locator
        fact = facts_by_group.get(group_id)
        if fact is None:
            fact = _FactGroup(group_id, evidence.evidence_id, evidence.scope)
            facts_by_group[group_id] = fact
        fact.add(clue)

    if evidence.scope == "unknown":
        all_sids = set()
        all_names = set()
        for fact in facts_by_group.values():
            all_sids.update(fact.sids)
            all_names.update(fact.name_keys)
        if len(all_sids) <= 1 and len(all_names) <= 1:
            merged = _FactGroup("unknown:%s" % (evidence.evidence_id,),
                                evidence.evidence_id, evidence.scope)
            for fact in facts_by_group.values():
                for clue in fact.clues:
                    merged.add(clue)
            facts_by_group = {merged.group_id: merged}

    # A hive-level USERDOMAIN applies to the account names extracted from
    # the same hive.  Keep the original clue untouched, but qualify the
    # grouped name so reports and matching use DOMAIN\user.
    for fact in facts_by_group.values():
        if len(fact.domains) == 1:
            domain = list(fact.domains)[0]
            fact.names = [(domain if item_domain is None else item_domain,
                           username)
                          for item_domain, username in fact.names]
            fact.name_keys = set(_name_key(item_domain, username)
                                 for item_domain, username in fact.names)
            # Keep the original separate DOMAIN clue, and also qualify the
            # matching view of hive-sourced names so provenance consumers
            # see the same effective account name.
            for clue in fact.clues:
                if (clue.kind == ClueKind.USERNAME
                        and clue.source == SourceKind.HIVE
                        and clue.domain is None):
                    clue.domain = domain
    return list(facts_by_group.values())


def _fact_has_machine_default(fact):
    if "machine_default" in fact.tags:
        return True
    for domain, username in fact.names:
        if _is_machine_default_name(username):
            return True
    for sid in fact.sids:
        if _is_machine_default_sid(sid):
            return True
    for path in fact.profile_paths:
        derived = username_from_profile_path(path)
        if (derived and derived[2]) or _is_machine_default_path(path):
            return True
    return False


def _build_mirror_groups(evidences):
    groups = []
    by_hash = {}
    for evidence in evidences:
        if evidence.sha256:
            by_hash.setdefault(evidence.sha256, []).append(evidence)
    for digest, items in sorted(by_hash.items()):
        if len(items) < 2:
            continue
        group_id = "mirror:sha256:%s" % (digest[:16],)
        canonical = sorted(items, key=lambda item: item.evidence_id)[0]
        for item in items:
            item.mirror_group = group_id
            if item is not canonical:
                item.mirror_of = canonical.evidence_id
        groups.append({
            "group_id": group_id,
            "kind": "byte_identical",
            "sha256": digest,
            "evidence_ids": sorted(item.evidence_id for item in items),
            "canonical_evidence_id": canonical.evidence_id,
            "confidence": Confidence.HIGH.value,
        })

    # Different bytes may still be copies of the same profile.  This is a
    # weaker signal than a byte-identical mirror, so keep it separate.
    by_identity = {}
    for evidence in evidences:
        sids = sorted(set(clue.value for clue in evidence.clues_of(ClueKind.SID)))
        names = sorted(set(_name_key(clue.domain, clue.value)
                           for clue in evidence.clues_of(ClueKind.USERNAME)))
        if len(sids) == 1 and len(names) == 1:
            by_identity.setdefault((sids[0], names[0]), []).append(evidence)
    for key, items in sorted(by_identity.items()):
        digests = set(item.sha256 for item in items if item.sha256)
        if len(items) < 2 or len(digests) < 2:
            continue
        group_id = "mirror:identity:%s" % (key[0],)
        for item in items:
            if item.mirror_group is None:
                item.mirror_group = group_id
                item.mirror_candidate = True
        groups.append({
            "group_id": group_id,
            "kind": "same_sid_and_name",
            "sid": key[0],
            "name": list(key[1]),
            "evidence_ids": sorted(item.evidence_id for item in items),
            "confidence": Confidence.MEDIUM.value,
        })
    return groups


def _name_candidates_from_fact(fact):
    return list(fact.names)


def _build_clusters(facts, table):
    clusters = {}
    facts_with_sid = []
    facts_without_sid = []

    for fact in facts:
        if fact.identity_sids:
            facts_with_sid.append(fact)
        elif fact.names:
            facts_without_sid.append(fact)

    for fact in facts_with_sid:
        identity_sids = sorted(fact.identity_sids)
        for sid in identity_sids:
            cluster = clusters.get(sid)
            if cluster is None:
                cluster = IdentityHypothesis(
                    identity_id="sid:%s" % (sid,), sid=sid)
                clusters[sid] = cluster
            cluster.add_evidence(fact.evidence_id)
            cluster.add_clues(fact.clues)
            cluster.observed_sids = sorted(set(cluster.observed_sids) | {sid})
            for domain, username in fact.names:
                if (domain, username) not in cluster.observed_names:
                    cluster.observed_names.append((domain, username))
            cluster.profile_paths = sorted(
                set(cluster.profile_paths) | fact.profile_paths)
            if len(identity_sids) > 1:
                cluster.conflicts.append(Conflict(
                    "hive_sid_conflict",
                    "one extraction group contains %d identity SIDs" % (
                        len(identity_sids),),
                    subject=fact.evidence_id,
                    values=identity_sids,
                    sources=[clue.provenance() for clue in fact.clues
                             if clue.kind == ClueKind.SID]))

    # Name-only facts are first linked to an existing SID cluster when the
    # name is unambiguous.  This keeps a SID-less copy of the same profile
    # from appearing as a second person, without making it unique.
    sid_by_name = {}
    for sid, cluster in clusters.items():
        for domain, username in cluster.observed_names:
            sid_by_name.setdefault(_name_key(domain, username), set()).add(sid)

    name_clusters = {}
    for fact in facts_without_sid:
        names = list(fact.names)
        candidate_sids = set()
        for domain, username in names:
            candidate_sids.update(sid_by_name.get(
                _name_key(domain, username), set()))

        if table is not None and names:
            table_sids = set()
            for domain, username in names:
                table_sids.update(table.distinct_sids_for_name(
                    username, domain=domain))
            if len(table_sids) == 1:
                sid = list(table_sids)[0]
                candidate_sids = {sid}
                fact.sid_inferred = True

        if len(candidate_sids) == 1:
            sid = list(candidate_sids)[0]
            cluster = clusters.get(sid)
            if cluster is None:
                cluster = IdentityHypothesis(
                    identity_id="sid:%s" % (sid,), sid=sid)
                clusters[sid] = cluster
                fact.sid_inferred = True
            cluster.add_evidence(fact.evidence_id)
            cluster.add_clues(fact.clues)
            cluster.observed_sids = sorted(
                set(cluster.observed_sids) | {sid})
            for domain, username in names:
                if (domain, username) not in cluster.observed_names:
                    cluster.observed_names.append((domain, username))
            cluster.profile_paths = sorted(
                set(cluster.profile_paths) | fact.profile_paths)
            # A table-derived or mount-note SID is useful for grouping, but
            # it must remain visible when the hive itself supplied no SID.
            if not fact.hive_sids:
                cluster.sid_missing_evidence_ids.append(fact.evidence_id)
            continue

        if names:
            key = _name_key(names[0][0], names[0][1])
            cluster = name_clusters.get(key)
            if cluster is None:
                cluster = IdentityHypothesis(
                    identity_id="name:%s" % (
                        _display_name(names[0][0], names[0][1]),),
                    username=names[0][1], domain=names[0][0])
                name_clusters[key] = cluster
            cluster.add_evidence(fact.evidence_id)
            cluster.add_clues(fact.clues)
            for domain, username in names:
                if (domain, username) not in cluster.observed_names:
                    cluster.observed_names.append((domain, username))
            cluster.profile_paths = sorted(
                set(cluster.profile_paths) | fact.profile_paths)
            if candidate_sids:
                cluster.warnings.append(
                    "name matches %d SID candidates" % (len(candidate_sids),))
        else:
            # No usable name or SID.  The evidence remains in the report but
            # does not become an identity candidate.
            continue

    return list(clusters.values()) + list(name_clusters.values())


def _select_trusted_record(records, names, sid=None):
    if not records:
        return None
    if sid is not None:
        records = [record for record in records if record.sid == sid]
    if not records:
        return None
    if not names:
        return records[0] if len(set(record.name_key
                                     for record in records)) == 1 else None

    name_keys = set(_name_key(domain, username)
                    for domain, username in names)
    exact = [record for record in records if record.name_key in name_keys]
    if exact:
        return exact[0]
    usernames = set(key[1] for key in name_keys)
    if len(usernames) == 1:
        by_user = [record for record in records
                   if record.username.casefold() in usernames]
        if len(set(record.name_key for record in by_user)) == 1:
            return by_user[0]
    return None


def _hive_sids(cluster):
    return sorted(set(clue.value for clue in cluster.clues
                      if (clue.kind == ClueKind.SID
                          and clue.source == SourceKind.HIVE)))


def _hive_names(cluster):
    result = []
    for clue in cluster.clues:
        if clue.kind == ClueKind.USERNAME and clue.source == SourceKind.HIVE:
            item = (clue.domain, clue.value)
            if item not in result:
                result.append(item)
    return result


def _mount_names(cluster):
    result = []
    for clue in cluster.clues:
        if (clue.kind == ClueKind.USERNAME
                and clue.source == SourceKind.MOUNT_NOTE):
            item = (clue.domain, clue.value)
            if item not in result:
                result.append(item)
    return result


def _set_identity_names(cluster, record):
    cluster.domain = record.domain
    cluster.username = record.username
    if cluster.sid is None:
        cluster.sid = record.sid


def _resolve_cluster(cluster, table):
    cluster.observed_sids = sorted(set(cluster.observed_sids))
    if not cluster.observed_names:
        cluster.observed_names = []
    cluster.kind = "user"

    if any("machine_default" in clue.tags for clue in cluster.clues):
        if cluster.username is None and cluster.observed_names:
            cluster.domain, cluster.username = cluster.observed_names[0]
        cluster.kind = "machine_default"
        cluster.status = ResolutionStatus.MACHINE_DEFAULT
        cluster.unique = False
        cluster.confidence = Confidence.UNVERIFIED
        cluster.reason = "machine_default_not_a_user"
        return

    for domain, username in cluster.observed_names:
        if cluster.username is None:
            cluster.domain = domain
            cluster.username = username
            break

    if cluster.observed_sids:
        for sid in cluster.observed_sids:
            if _is_machine_default_sid(sid):
                cluster.kind = "machine_default"
                cluster.status = ResolutionStatus.MACHINE_DEFAULT
                cluster.unique = False
                cluster.confidence = Confidence.UNVERIFIED
                cluster.reason = "machine_default_not_a_user"
                return
    for domain, username in cluster.observed_names:
        if _is_machine_default_name(username):
            cluster.kind = "machine_default"
            cluster.status = ResolutionStatus.MACHINE_DEFAULT
            cluster.unique = False
            cluster.confidence = Confidence.UNVERIFIED
            cluster.reason = "machine_default_not_a_user"
            return

    if table is None or table.is_empty():
        cluster.status = ResolutionStatus.UNRESOLVED
        cluster.unique = False
        cluster.confidence = Confidence.UNVERIFIED
        cluster.reason = "trusted_sid_table_required"
        if cluster.observed_names:
            domain, username = cluster.observed_names[0]
            cluster.domain = cluster.domain or domain
            cluster.username = cluster.username or username
        return

    # ``observed_sids`` may contain a SID inferred from the trusted table
    # during clustering.  Only an actual SID clue makes the SID branch
    # authoritative; otherwise the table is still supplying the SID by name.
    has_sid_clue = any(clue.kind == ClueKind.SID for clue in cluster.clues)
    observed_sids = list(cluster.observed_sids) if has_sid_clue else []
    observed_names = list(cluster.observed_names)
    hive_names = _hive_names(cluster)
    mount_names = _mount_names(cluster)

    sid_records = []
    supported_sids = []
    for sid in observed_sids:
        records = table.records_for_sid(sid)
        if records:
            supported_sids.append(sid)
            sid_records.extend(records)

    if observed_sids and sid_records:
        distinct_supported = sorted(set(supported_sids))
        if len(distinct_supported) > 1:
            cluster.status = ResolutionStatus.CONFLICT
            cluster.unique = False
            cluster.confidence = Confidence.UNVERIFIED
            cluster.reason = "trusted_table_supports_multiple_observed_sids"
            cluster.trusted_records = sid_records
            cluster.conflicts.append(Conflict(
                "trusted_table_supports_multiple_observed_sids",
                "trusted table confirms more than one SID for the same hive group",
                subject=cluster.identity_id,
                values=distinct_supported,
                sources=[clue.provenance() for clue in cluster.clues
                         if clue.kind == ClueKind.SID]))
            return

        sid = distinct_supported[0]
        record = _select_trusted_record(sid_records, observed_names, sid=sid)
        if record is None:
            matching_names = sorted(set(
                _display_name(item.domain, item.username)
                for item in sid_records))
            cluster.status = ResolutionStatus.CONFLICT
            cluster.unique = False
            cluster.confidence = Confidence.UNVERIFIED
            cluster.reason = "trusted_table_disagrees_with_hive_name"
            cluster.trusted_records = sid_records
            cluster.conflicts.append(Conflict(
                "trusted_table_vs_hive_name",
                "trusted SID %s maps to %s, but the hive reports %s" % (
                    sid, ", ".join(matching_names) or "<no name>",
                    ", ".join(_display_name(domain, user)
                              for domain, user in observed_names)
                    or "<no name>"),
                subject=sid,
                values=matching_names + [
                    _display_name(domain, user)
                    for domain, user in observed_names],
                sources=[clue.provenance() for clue in cluster.clues]))
            return

        hive_name_keys = set(_name_key(domain, username)
                             for domain, username in hive_names)
        if hive_name_keys and record.name_key not in hive_name_keys:
            # The table is authoritative, but a contradictory hive name is
            # material and must not be hidden behind a "resolved" label.
            cluster.status = ResolutionStatus.CONFLICT
            cluster.unique = False
            cluster.confidence = Confidence.UNVERIFIED
            cluster.reason = "trusted_table_disagrees_with_hive_name"
            cluster.trusted_records = [record]
            cluster.conflicts.append(Conflict(
                "trusted_table_vs_hive_name",
                "trusted SID %s is %s, but the hive says %s" % (
                    sid, record.display_name,
                    ", ".join(_display_name(domain, user)
                              for domain, user in hive_names)),
                subject=sid,
                values=[record.display_name] + [
                    _display_name(domain, user)
                    for domain, user in hive_names],
                sources=[clue.provenance() for clue in cluster.clues]))
            return

        _set_identity_names(cluster, record)
        cluster.trusted_records = [record]
        cluster.trusted_match = "sid"
        cluster.status = ResolutionStatus.RESOLVED
        cluster.unique = True
        cluster.confidence = Confidence.AUTHORITATIVE
        cluster.reason = "trusted_sid_match"
        if len(observed_sids) > 1:
            for other in observed_sids:
                if other == sid:
                    continue
                cluster.warnings.append(
                    "hive also contains SID %s; trusted table confirms %s"
                    % (other, sid))
        for domain, username in mount_names:
            if _name_key(domain, username) != record.name_key:
                cluster.warnings.append(
                    "mount note name %s differs from trusted name %s" % (
                        _display_name(domain, username), record.display_name))
        return

    if observed_sids and not sid_records:
        # The hive has a SID, but the table does not contain it.  A
        # name-based match that points at a different SID is a hard
        # contradiction, not a silent override.
        name_records = []
        for domain, username in observed_names:
            name_records.extend(table.records_for_name(
                username, domain=domain))
        distinct = sorted(set(record.sid for record in name_records))
        if len(distinct) == 1 and distinct[0] not in observed_sids:
            cluster.status = ResolutionStatus.CONFLICT
            cluster.unique = False
            cluster.confidence = Confidence.UNVERIFIED
            cluster.reason = "trusted_table_disagrees_with_hive_sid"
            cluster.trusted_records = name_records
            cluster.conflicts.append(Conflict(
                "trusted_table_vs_hive_sid",
                "hive reports %s but trusted name mapping reports %s" % (
                    ", ".join(observed_sids), distinct[0]),
                subject=observed_names[0][1] if observed_names else None,
                values=observed_sids + distinct,
                sources=[clue.provenance() for clue in cluster.clues]))
            return
        cluster.status = ResolutionStatus.UNRESOLVED
        cluster.unique = False
        cluster.confidence = Confidence.LOW
        cluster.reason = "observed_sid_not_in_trusted_table"
        return

    # No SID in the evidence.  The table may supply one by name, but only if
    # the name is unambiguous.
    name_records = []
    for domain, username in observed_names:
        name_records.extend(table.records_for_name(username, domain=domain))

    distinct = sorted(set(record.sid for record in name_records))
    if not name_records:
        cluster.status = ResolutionStatus.UNRESOLVED
        cluster.unique = False
        cluster.confidence = Confidence.LOW
        cluster.reason = "no_trusted_mapping"
        return
    if len(distinct) > 1:
        cluster.status = ResolutionStatus.AMBIGUOUS
        cluster.unique = False
        cluster.confidence = Confidence.LOW
        cluster.reason = "trusted_name_ambiguous"
        cluster.trusted_records = name_records
        cluster.conflicts.append(Conflict(
            "trusted_name_ambiguous",
            "name %s maps to %d SIDs in the trusted table" % (
                ", ".join(_display_name(domain, user)
                          for domain, user in observed_names),
                len(distinct)),
            subject=_display_name(*observed_names[0]) if observed_names else None,
            values=distinct,
            sources=[record.to_dict() for record in name_records]))
        return

    record = _select_trusted_record(name_records, observed_names,
                                    sid=distinct[0])
    if record is None:
        cluster.status = ResolutionStatus.AMBIGUOUS
        cluster.unique = False
        cluster.confidence = Confidence.LOW
        cluster.reason = "trusted_name_not_unique"
        cluster.trusted_records = name_records
        return

    _set_identity_names(cluster, record)
    cluster.trusted_records = [record]
    cluster.trusted_match = "name"
    cluster.status = ResolutionStatus.RESOLVED
    cluster.unique = True
    cluster.confidence = Confidence.HIGH
    cluster.reason = "trusted_name_match_sid_inferred"
    cluster.warnings.append(
        "evidence did not contain a SID; SID %s was supplied by the trusted "
        "table" % (record.sid,))


def _resolve_name_cluster_against_sid_cluster(cluster, sid_clusters, table):
    if table is None or table.is_empty() or cluster.sid is not None:
        return cluster
    if len(cluster.observed_names) != 1:
        return cluster
    domain, username = cluster.observed_names[0]
    sids = table.distinct_sids_for_name(username, domain=domain)
    if len(sids) != 1:
        return cluster
    target = sid_clusters.get(sids[0])
    if target is None:
        return cluster
    target.add_clues(cluster.clues)
    for evidence_id in cluster.evidence_ids:
        target.add_evidence(evidence_id)
    for item in cluster.observed_names:
        if item not in target.observed_names:
            target.observed_names.append(item)
    target.profile_paths = sorted(set(target.profile_paths)
                                  | set(cluster.profile_paths))
    target.warnings.extend(cluster.warnings)
    target.conflicts.extend(cluster.conflicts)
    return target


def _best_name(clues, source=None):
    best = None
    for clue in clues:
        if clue.kind != ClueKind.USERNAME:
            continue
        if source is not None and clue.source != SourceKind(source):
            continue
        if best is None or clue.confidence.score > best.confidence.score:
            best = clue
    return (best.domain, best.value) if best else None


def _collect_conflicts(evidences, clusters, table, mirror_groups):
    conflicts = []
    warnings = []

    name_to_sids = {}
    sid_to_names = {}
    for evidence in evidences:
        groups = {}
        for clue in evidence.clues:
            if clue.source != SourceKind.HIVE:
                continue
            if clue.kind not in (ClueKind.USERNAME, ClueKind.SID):
                continue
            groups.setdefault(clue.group, []).append(clue)
            if clue.kind == ClueKind.USERNAME:
                name_to_sids.setdefault(
                    _name_key(clue.domain, clue.value), set())
            else:
                sid_to_names.setdefault(clue.value, set())
        for group_clues in groups.values():
            names = [clue for clue in group_clues
                     if clue.kind == ClueKind.USERNAME]
            sids = [clue for clue in group_clues if clue.kind == ClueKind.SID]
            for name_clue in names:
                key = _name_key(name_clue.domain, name_clue.value)
                for sid_clue in sids:
                    name_to_sids[key].add(sid_clue.value)
                    sid_to_names[sid_clue.value].add(key)

    # Cross-cluster conflicts are what distinguish two same-named exports
    # with different SIDs from a single account.  Only hive-sourced names
    # participate here; a contradictory mount note is reported separately
    # as a provenance warning instead of being promoted to a SID/name
    # conflict.
    for cluster in clusters:
        cluster_sids = set(_hive_sids(cluster))
        if not cluster_sids:
            continue
        cluster_names = _hive_names(cluster)
        for domain, username in cluster_names:
            key = _name_key(domain, username)
            name_to_sids.setdefault(key, set()).update(cluster_sids)
            for sid in cluster_sids:
                sid_to_names.setdefault(sid, set()).add(key)

    for key, sids in sorted(name_to_sids.items()):
        if len(sids) <= 1:
            continue
        sources = []
        for evidence in evidences:
            for clue in evidence.clues:
                if clue.kind == ClueKind.USERNAME and (
                        _name_key(clue.domain, clue.value) == key):
                    sources.append(clue.provenance())
                elif clue.kind == ClueKind.SID and clue.value in sids:
                    sources.append(clue.provenance())
        conflicts.append(Conflict(
            "same_name_sid_conflict",
            "username %s is associated with %d distinct SIDs" % (
                _display_name(key[0] or None, key[1]), len(sids)),
            subject=_display_name(key[0] or None, key[1]),
            values=sorted(sids), sources=sources))

    for sid, names in sorted(sid_to_names.items()):
        if len(names) <= 1:
            continue
        sources = []
        for evidence in evidences:
            for clue in evidence.clues:
                if clue.kind == ClueKind.SID and clue.value == sid:
                    sources.append(clue.provenance())
                elif clue.kind == ClueKind.USERNAME and (
                        _name_key(clue.domain, clue.value) in names):
                    sources.append(clue.provenance())
        conflicts.append(Conflict(
            "same_sid_name_conflict",
            "SID %s is associated with %d distinct usernames" % (
                sid, len(names)),
            subject=sid,
            values=[_display_name(domain or None, username)
                    for domain, username in sorted(names)],
            sources=sources))

    for evidence in evidences:
        hive_names = set(_name_key(clue.domain, clue.value)
                         for clue in evidence.clues
                         if (clue.kind == ClueKind.USERNAME
                             and clue.source == SourceKind.HIVE))
        mount_names = set(_name_key(clue.domain, clue.value)
                          for clue in evidence.clues
                          if (clue.kind == ClueKind.USERNAME
                              and clue.source == SourceKind.MOUNT_NOTE))
        if hive_names and mount_names and not (hive_names & mount_names):
            conflicts.append(Conflict(
                "mount_note_name_conflict",
                "mount note names %s disagree with hive names %s" % (
                    ", ".join(_display_name(domain or None, username)
                              for domain, username in sorted(mount_names)),
                    ", ".join(_display_name(domain or None, username)
                              for domain, username in sorted(hive_names))),
                subject=evidence.evidence_id,
                values=[_display_name(domain or None, username)
                        for domain, username in
                        sorted(hive_names | mount_names)],
                sources=[clue.provenance() for clue in evidence.clues
                         if clue.kind == ClueKind.USERNAME],
                severity="warning"))

        hive_sids = set(clue.value for clue in evidence.clues
                        if (clue.kind == ClueKind.SID
                            and clue.source == SourceKind.HIVE))
        mount_sids = set(clue.value for clue in evidence.clues
                         if (clue.kind == ClueKind.SID
                             and clue.source == SourceKind.MOUNT_NOTE))
        if hive_sids and mount_sids and not (hive_sids & mount_sids):
            conflicts.append(Conflict(
                "mount_note_sid_conflict",
                "mount note SID %s disagrees with hive SID %s" % (
                    ", ".join(sorted(mount_sids)),
                    ", ".join(sorted(hive_sids))),
                subject=evidence.evidence_id,
                values=sorted(hive_sids | mount_sids),
                sources=[clue.provenance() for clue in evidence.clues
                         if clue.kind == ClueKind.SID],
                severity="warning"))

        if not evidence.clues_of(ClueKind.SID) and evidence.clues_of(
                ClueKind.USERNAME):
            warnings.append("%s: no SID clue; unique attribution requires "
                            "the trusted SID table" % (evidence.evidence_id,))

    for group in mirror_groups:
        if group.get("kind") != "byte_identical":
            continue
        evidences_in_group = [evidence for evidence in evidences
                              if evidence.evidence_id
                              in group["evidence_ids"]]
        names = set()
        sids = set()
        for evidence in evidences_in_group:
            names.update(_name_key(clue.domain, clue.value)
                         for clue in evidence.clues
                         if clue.kind == ClueKind.USERNAME)
            sids.update(clue.value for clue in evidence.clues
                        if clue.kind == ClueKind.SID)
        if len(names) > 1 or len(sids) > 1:
            conflicts.append(Conflict(
                "mirror_copy_provenance_conflict",
                "byte-identical copies carry contradictory mount clues",
                subject=group["group_id"],
                values=[_display_name(domain or None, username)
                        for domain, username in sorted(names)]
                + sorted(sids),
                sources=[clue.provenance()
                         for evidence in evidences_in_group
                         for clue in evidence.clues
                         if clue.kind in (ClueKind.USERNAME, ClueKind.SID)],
                severity="warning"))

    for conflict in table.conflicts if table is not None else []:
        conflicts.append(Conflict(
            conflict["kind"],
            "trusted SID table conflict",
            subject=conflict.get("sid") or conflict.get("username"),
            values=conflict.get("sids") or conflict.get("names") or [],
            sources=[{"source": SourceKind.TRUSTED_SID_TABLE.value,
                      "source_row": conflict.get("source_rows")}],
            severity="warning"))

    for cluster in clusters:
        conflicts.extend(cluster.conflicts)
        warnings.extend("%s: %s" % (cluster.identity_id, warning)
                        for warning in cluster.warnings)
        if cluster.kind == "machine_default":
            warnings.append(
                "%s: machine/default account is not a human user attribution"
                % (cluster.identity_id,))

    # Deduplicate deterministic conflict/warning output.
    unique_conflicts = []
    seen_conflicts = set()
    for conflict in conflicts:
        key = (conflict.kind, conflict.subject,
               tuple(conflict.values), conflict.message)
        if key in seen_conflicts:
            continue
        seen_conflicts.add(key)
        unique_conflicts.append(conflict)
    unique_warnings = []
    for warning in warnings:
        if warning not in unique_warnings:
            unique_warnings.append(warning)
    return unique_conflicts, unique_warnings


class _AttributionDict(dict):
    """JSON-friendly attribution that also supports attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class IdentityReport(object):
    """
    Complete read-only result of identity correlation.

    ``unique``/``is_unique`` is the hard forensic gate: it can only be true
    when a trusted SID table is present and confirms the attribution.
    """

    def __init__(self, evidence, identities, attributions, trusted_table,
                 mirror_groups=(), conflicts=(), warnings=()):
        self.evidence = list(evidence)
        self.identities = list(identities)
        self.attributions = list(attributions)
        self.trusted_sid_table = trusted_table
        self.mirror_groups = list(mirror_groups)
        self.conflicts = list(conflicts)
        self.warnings = list(warnings)

    @property
    def trusted_sid_table_present(self):
        return bool(self.trusted_sid_table is not None
                    and self.trusted_sid_table.present)

    @property
    def hives(self):
        return list(self.evidence)

    @property
    def mirrors(self):
        return list(self.mirror_groups)

    @property
    def provisional_identities(self):
        return [identity for identity in self.identities
                if identity.status in (ResolutionStatus.UNRESOLVED,
                                       ResolutionStatus.AMBIGUOUS,
                                       ResolutionStatus.CONFLICT)]

    @property
    def is_unique(self):
        # Hard gate: even a perfect-looking internal match is not a final
        # attribution without the independent SID cross-reference.
        if not self.trusted_sid_table_present:
            return False
        user_attributions = [item for item in self.attributions
                             if item.scope == "user"]
        if not user_attributions:
            return False
        if not all(item.unique for item in user_attributions):
            return False
        identity_ids = set(item.identity_id for item in user_attributions)
        if len(identity_ids) != 1:
            return False
        identity_id = list(identity_ids)[0]
        identity = self.identity_by_id(identity_id)
        return (identity is not None
                and identity.kind == "user"
                and identity.status == ResolutionStatus.RESOLVED
                and identity.unique)

    @property
    def unique(self):
        return self.is_unique

    @property
    def resolved(self):
        return self.is_unique

    @property
    def identity(self):
        if not self.is_unique:
            return None
        for item in self.attributions:
            if item.scope == "user" and item.unique:
                return self.identity_by_id(item.identity_id)
        return None

    @property
    def attribution(self):
        if not self.is_unique:
            return None
        for item in self.attributions:
            if item.scope == "user" and item.unique:
                return _AttributionDict({
                    "evidence_ids": [attribution.evidence_id
                                     for attribution in self.attributions
                                     if attribution.identity_id
                                     == item.identity_id],
                    "identity_id": item.identity_id,
                    "sid": item.sid,
                    "username": item.username,
                    "domain": item.domain,
                    "confidence": item.confidence.value,
                })
        return None

    @property
    def user(self):
        attribution = self.attribution
        return attribution["username"] if attribution else None

    @property
    def sid(self):
        attribution = self.attribution
        return attribution["sid"] if attribution else None

    def identity_by_id(self, identity_id):
        for identity in self.identities:
            if identity.identity_id == identity_id:
                return identity
        return None

    def attribution_for(self, evidence_id):
        for attribution in self.attributions:
            if attribution.evidence_id == evidence_id:
                return attribution
        raise KeyError(evidence_id)

    def resolved_identities(self):
        return [identity for identity in self.identities
                if identity.status == ResolutionStatus.RESOLVED]

    def to_dict(self):
        return {
            "read_only": True,
            "trusted_sid_table": (
                self.trusted_sid_table.to_dict()
                if self.trusted_sid_table is not None else {
                    "present": False,
                    "entry_count": 0,
                    "records": [],
                    "conflicts": [],
                }),
            "trusted_sid_table_required": not self.trusted_sid_table_present,
            "evidence": [item.to_dict() for item in self.evidence],
            "identities": [item.to_dict() for item in self.identities],
            "mirror_groups": list(self.mirror_groups),
            "attributions": [item.to_dict() for item in self.attributions],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "warnings": list(self.warnings),
            "is_unique": self.is_unique,
            "attribution": self.attribution,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True,
                          ensure_ascii=False)

    def __repr__(self):
        return "IdentityReport(evidence=%d, identities=%d, unique=%r)" % (
            len(self.evidence), len(self.identities), self.is_unique)


class IdentityResolver(object):
    """
    Correlate one or more hive occurrences against an optional trusted table.

    The resolver is immutable with respect to evidence: each source is read
    once, hashed, and parsed from an in-memory copy.
    """

    def __init__(self, trusted_sid_table=None, trusted_sid_path=None,
                 sid_table=None, sid_table_path=None):
        source = trusted_sid_table
        if source is None:
            source = trusted_sid_path
        if source is None:
            source = sid_table
        if source is None:
            source = sid_table_path
        if isinstance(source, TrustedSidTable):
            self.trusted_sid_table = source
        else:
            self.trusted_sid_table = load_trusted_sid_table(source)

    def analyze(self, hives, mount_notes=None):
        if hives is None:
            hives = []
        elif (isinstance(hives, (str, bytes, bytearray, dict,
                                 HiveEvidence, Registry))
              or hasattr(hives, "read")
              or (hasattr(os, "PathLike") and isinstance(hives, os.PathLike))):
            hives = [hives]
        else:
            try:
                hives = list(hives)
            except TypeError:
                hives = [hives]

        evidence = []
        specified_ids = set()
        for index, spec in enumerate(hives, 1):
            default_id = "H%d" % (index,)
            supplied_id = None
            if isinstance(spec, HiveEvidence):
                supplied_id = spec.evidence_id
            elif isinstance(spec, dict):
                supplied_id = spec.get("evidence_id") or spec.get("id")
            evidence_id = supplied_id or default_id
            if evidence_id in specified_ids:
                suffix = 2
                candidate = "%s#%d" % (evidence_id, suffix)
                while candidate in specified_ids:
                    suffix += 1
                    candidate = "%s#%d" % (evidence_id, suffix)
                evidence_id = candidate
            specified_ids.add(evidence_id)

            note = None
            if isinstance(mount_notes, dict):
                note = mount_notes.get(supplied_id or evidence_id)
                if note is None:
                    note = mount_notes.get(evidence_id)
                if note is None and isinstance(spec, dict):
                    for key in (spec.get("path"), spec.get("label")):
                        if key is not None:
                            note = mount_notes.get(key)
                            if note is not None:
                                break
                if note is None and isinstance(spec, str):
                    note = mount_notes.get(spec)
            elif isinstance(mount_notes, (list, tuple)):
                if index - 1 < len(mount_notes):
                    note = mount_notes[index - 1]
            elif isinstance(mount_notes, str) and index == 1:
                note = mount_notes

            if isinstance(spec, dict) and note is None:
                note = spec.get("mount_note", spec.get("mount_notes"))
            evidence.append(read_hive_evidence(
                spec, evidence_id=evidence_id, mount_note=note))

        return self.correlate(evidence)

    resolve = analyze

    def correlate(self, evidence):
        evidence = [item if isinstance(item, HiveEvidence)
                    else read_hive_evidence(item)
                    for item in list(evidence)]
        mirror_groups = _build_mirror_groups(evidence)

        facts = []
        for item in evidence:
            facts.extend(_group_facts(item))

        clusters = _build_clusters(facts, self.trusted_sid_table)

        # A name-only cluster can be merged into a SID cluster once the
        # trusted table supplies the missing edge.
        sid_clusters = {cluster.sid: cluster for cluster in clusters
                        if cluster.sid is not None}
        merged = []
        seen = set()
        for cluster in clusters:
            target = _resolve_name_cluster_against_sid_cluster(
                cluster, sid_clusters, self.trusted_sid_table)
            if id(target) in seen:
                continue
            seen.add(id(target))
            merged.append(target)
        clusters = merged

        for cluster in clusters:
            _resolve_cluster(cluster, self.trusted_sid_table)
            for group in mirror_groups:
                if any(evidence_id in group["evidence_ids"]
                       for evidence_id in cluster.evidence_ids):
                    group_id = group["group_id"]
                    if group_id not in cluster.mirror_groups:
                        cluster.mirror_groups.append(group_id)

        # Keep a stable, human-oriented order: users by SID/name, then
        # machine/default accounts.
        clusters.sort(key=lambda item: (
            1 if item.kind == "machine_default" else 0,
            item.sid or "",
            item.display_name or "",
            item.identity_id,
        ))

        cluster_by_evidence = {}
        for cluster in clusters:
            for evidence_id in cluster.evidence_ids:
                cluster_by_evidence.setdefault(evidence_id, []).append(cluster)

        attributions = []
        for evidence_item in evidence:
            related = cluster_by_evidence.get(evidence_item.evidence_id, [])
            if not related:
                attributions.append(EvidenceAttribution(
                    evidence_item.evidence_id, evidence_item.scope,
                    ResolutionStatus.INSUFFICIENT_EVIDENCE,
                    reason="no_identity_clues"))
                continue

            if evidence_item.scope != "user":
                attributions.append(EvidenceAttribution(
                    evidence_item.evidence_id, evidence_item.scope,
                    ResolutionStatus.MACHINE_SCOPE,
                    candidate_ids=[cluster.identity_id
                                   for cluster in related],
                    reason="hive_contains_machine_wide_accounts"))
                continue

            if len(related) > 1:
                attributions.append(EvidenceAttribution(
                    evidence_item.evidence_id, evidence_item.scope,
                    ResolutionStatus.CONFLICT,
                    candidate_ids=[cluster.identity_id
                                   for cluster in related],
                    reason="multiple_sid_candidates"))
                continue

            cluster = related[0]

            if cluster.kind == "machine_default":
                attributions.append(EvidenceAttribution(
                    evidence_item.evidence_id, evidence_item.scope,
                    ResolutionStatus.MACHINE_DEFAULT,
                    candidate_ids=[cluster.identity_id],
                    reason="machine_default_not_a_user"))
                continue

            if cluster.unique and cluster.status == ResolutionStatus.RESOLVED:
                attributions.append(EvidenceAttribution(
                    evidence_item.evidence_id, evidence_item.scope,
                    ResolutionStatus.RESOLVED,
                    unique=True,
                    identity_id=cluster.identity_id,
                    sid=cluster.sid,
                    username=cluster.username,
                    domain=cluster.domain,
                    confidence=cluster.confidence,
                    candidate_ids=[cluster.identity_id],
                    reason=cluster.reason))
            else:
                attributions.append(EvidenceAttribution(
                    evidence_item.evidence_id, evidence_item.scope,
                    cluster.status,
                    candidate_ids=[cluster.identity_id],
                    reason=cluster.reason))

        conflicts, warnings = _collect_conflicts(
            evidence, clusters, self.trusted_sid_table, mirror_groups)
        if not self.trusted_sid_table.present:
            warnings.insert(
                0,
                "no trusted SID table was supplied; every result is "
                "provisional and no unique attribution is permitted")

        return IdentityReport(
            evidence=evidence,
            identities=clusters,
            attributions=attributions,
            trusted_table=self.trusted_sid_table,
            mirror_groups=mirror_groups,
            conflicts=conflicts,
            warnings=warnings)


def correlate_identities(hives, trusted_sid_table=None, mount_notes=None,
                         trusted_sid_path=None, sid_table=None,
                         sid_table_path=None):
    """
    Convenience entry point.

    ``trusted_sid_table`` is the only source allowed to produce a unique
    attribution.  It may be a path, file-like object, list of records, JSON
    object, or a :class:`TrustedSidTable`.
    """
    resolver = IdentityResolver(
        trusted_sid_table=trusted_sid_table,
        trusted_sid_path=trusted_sid_path,
        sid_table=sid_table,
        sid_table_path=sid_table_path)
    return resolver.analyze(hives, mount_notes=mount_notes)


def resolve_identities(hives, trusted_sid_table=None, mount_notes=None,
                       **kwargs):
    return correlate_identities(
        hives, trusted_sid_table=trusted_sid_table,
        mount_notes=mount_notes, **kwargs)


resolve_user_identities = resolve_identities
build_identity_report = correlate_identities


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m Registry.Identity",
        description="Read-only Registry user identity correlation")
    parser.add_argument("hives", nargs="+",
                        help="hive paths (or '-' for stdin is not supported)")
    parser.add_argument("--trusted-sid-table", "--sid-table",
                        dest="trusted_sid_table", default=None,
                        help="independent SID cross-reference (CSV/JSON/text)")
    parser.add_argument("--mount-note", action="append", default=None,
                        help="mount note, applied to hives in order")
    parser.add_argument("--pretty", action="store_true",
                        help="indent JSON output")
    parser.add_argument("--require-unique", action="store_true",
                        help="exit 3 when no unique user attribution exists")
    args = parser.parse_args(argv)

    report = correlate_identities(
        args.hives,
        trusted_sid_table=args.trusted_sid_table,
        mount_notes=args.mount_note)
    print(report.to_json(indent=2 if args.pretty else None))
    if args.require_unique and not report.is_unique:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
