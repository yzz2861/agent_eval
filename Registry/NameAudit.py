#    This file is part of python-registry.
#
#   Name identity auditing for forensic use.
#
#   Two registry keys may be displayed with identical names while their
#   underlying bytes differ (case only, invisible code points, compressed
#   vs. UTF-16 storage, ...).  A naive ``name.lower()`` de-duplication would
#   silently hide one of the persistence artifacts.  This module therefore
#   keeps three deliberately separate views of every name:
#
#     1. the raw identity  - exact bytes as stored on disk;
#     2. the lookup identity - equivalence under a *named* Windows rule;
#     3. the display identity - an escaped, human readable rendering that can
#        never be confused with the bytes used for querying.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import unicode_literals

from enum import Enum


class NameEncoding(Enum):
    """
    The on-disk name encoding used by an NK/VK record.

    Registry names are stored either as single-byte ("compressed", flag bit
    set in the record) or as UTF-16LE strings.
    """
    COMPRESSED = "compressed"
    UTF16 = "utf-16le"


class CollationRule(Enum):
    """
    The equivalence rule applied when Windows resolves a name lookup.

    ``CASE_INSENSITIVE_ASCII`` covers the documented, deterministic behavior
    for ASCII-only names.  Every rule whose result cannot be proven without
    the Windows kernel locale tables is reported as ``UNKNOWN``: python's
    ``str.lower()`` / ``str.casefold()`` must never be presented as the
    Windows behavior.
    """
    CASE_INSENSITIVE_ASCII = "windows-case-insensitive-ascii"
    UNKNOWN = "unknown"


def _is_pure_ascii(text):
    try:
        text.encode("ascii")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return False
    return True


def ascii_lookup_key(text):
    """
    The documented Windows lookup transform for an ASCII-only name:
    upper-case every ASCII letter.  Non-ASCII names have no deterministic
    portable transform and must not be forced through this function.

    @type text: str
    @rtype: str
    """
    if not _is_pure_ascii(text):
        raise ValueError(
            "ascii_lookup_key is only defined for pure ASCII names; "
            "use NameIdentity.collation_rule() to detect this case")
    return text.upper()


def escape_for_display(text):
    """
    Render arbitrary code points (including invisible / control / private use
    characters) as an unambiguous, human readable string.

    The result is a *display* artifact only; it is never fed back into a
    lookup, so escaping cannot change the identity that is queried.

    @type text: str
    @rtype: str
    """
    out = []
    for char in text:
        codepoint = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif 0x20 <= codepoint <= 0x7E:
            out.append(char)
        elif codepoint == 0x7F:
            out.append("\\x7f")
        elif codepoint <= 0xFFFF:
            out.append("\\u%04x" % codepoint)
        else:
            out.append("\\U%08x" % codepoint)
    return "".join(out)


class NameIdentity(object):
    """
    The audited identity of one stored registry key/value name.

    The object is immutable and keeps the exact on-disk bytes alongside the
    decoded text, so two names that look the same in a GUI can still be told
    apart by ``raw_bytes`` / ``codepoints``.
    """
    def __init__(self, raw_bytes, encoding, decoded=None):
        """
        @type raw_bytes: bytes
        @param raw_bytes: the exact name bytes stored in the record
        @type encoding: NameEncoding
        @type decoded: optional str, decoded by the record's own codec
        """
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raise TypeError("raw_bytes must be a byte string")
        self._raw_bytes = bytes(raw_bytes)
        self._encoding = NameEncoding(encoding)
        if decoded is None:
            decoded = self._decode()
        self._text = decoded

    def _decode(self):
        if self._encoding == NameEncoding.COMPRESSED:
            # windows-1252 is the codec used by NKRecord/VKRecord for the
            # single-byte ("compressed") name flag.
            return self._raw_bytes.decode("windows-1252")
        return self._raw_bytes.decode("utf-16le")

    def raw_bytes(self):
        """Exact name bytes as found on disk (never normalized)."""
        return self._raw_bytes

    def encoding(self):
        """The on-disk encoding of this name."""
        return self._encoding

    def text(self):
        """The decoded name, identical to the legacy ``name()`` result."""
        return self._text

    def codepoints(self):
        """
        Tuple of Unicode code points (integers).  This makes invisible
        differences such as a trailing NUL or zero-width characters explicit.
        """
        return tuple(ord(char) for char in self._text)

    def codepoint_sequence(self):
        """
        Human readable list of ``U+XXXX`` tokens, one per code point.
        """
        return tuple("U+%04X" % point for point in self.codepoints())

    def collation_rule(self):
        """
        The rule under which Windows lookup equivalence is known.

        Pure ASCII names get the deterministic ASCII rule; every name that
        contains non-ASCII code points is reported as unknown because the
        exact kernel/locale behavior cannot be reproduced here.
        """
        if _is_pure_ascii(self._text):
            return CollationRule.CASE_INSENSITIVE_ASCII
        return CollationRule.UNKNOWN

    def lookup_key(self):
        """
        The canonical key used for Windows-style equivalence.

        Returns ``None`` (rather than guessing via ``casefold``) when the
        collation rule is unknown.
        """
        if self.collation_rule() == CollationRule.CASE_INSENSITIVE_ASCII:
            return ascii_lookup_key(self._text)
        return None

    def display_name(self):
        """
        Escaped rendering suitable for forensic tooling.  Purely cosmetic:
        this value must never be used as a lookup identity.
        """
        return escape_for_display(self._text)

    def equivalent_to(self, other):
        """
        Whether two stored names are equivalent under a *known* Windows rule.

        Returns ``False`` for distinct raw identities whose rule is unknown,
        instead of collapsing them with a Python-only transform.
        """
        if not isinstance(other, NameIdentity):
            return False
        rule = self.collation_rule()
        if rule != other.collation_rule():
            return False
        if rule == CollationRule.UNKNOWN:
            return False
        return self.lookup_key() == other.lookup_key()

    def __eq__(self, other):
        if not isinstance(other, NameIdentity):
            return NotImplemented
        return (self._raw_bytes == other._raw_bytes
                and self._encoding == other._encoding)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self._encoding, self._raw_bytes))

    def __repr__(self):
        return ("NameIdentity(encoding=%s, raw=%r, display=%r)"
                % (self._encoding.value, self._raw_bytes, self.display_name()))


def make_name_identity(raw_bytes, compressed):
    """
    Build a NameIdentity from record fields.

    @type raw_bytes: bytes
    @param compressed: True when the record's ASCII/compressed name flag is set
    @rtype: NameIdentity
    """
    encoding = NameEncoding.COMPRESSED if compressed else NameEncoding.UTF16
    return NameIdentity(raw_bytes, encoding)


class LookupOutcome(Enum):
    """
    Result of an explicit name lookup against a set of stored candidates.
    """
    MATCH = "match"
    AMBIGUOUS = "ambiguous"
    NOT_FOUND = "not-found"
    UNKNOWN_RULE = "unknown-rule"


class NameCandidate(object):
    """
    One stored name participating in a lookup, together with the location at
    which it was found (typically the absolute offset of the NK/VK cell).
    """
    def __init__(self, identity, offset, record=None):
        self._identity = identity
        self._offset = offset
        self._record = record

    def identity(self):
        return self._identity

    def offset(self):
        return self._offset

    def record(self):
        return self._record

    def __repr__(self):
        return "NameCandidate(offset=0x%x, identity=%r)" % (
            self._offset, self._identity)


class LookupResult(object):
    """
    Explicit outcome of a name lookup.

    A lookup never silently picks one of several equivalent candidates: when
    more than one stored name matches the requested identity, every candidate
    and its offset are returned and the outcome is ``AMBIGUOUS``.
    """
    def __init__(self, query, outcome, candidates, rule, reason=None):
        self._query = query
        self._outcome = LookupOutcome(outcome)
        self._candidates = tuple(candidates)
        self._rule = CollationRule(rule)
        self._reason = reason

    def query(self):
        """The requested name as a str (the query input is never mutated)."""
        return self._query

    def outcome(self):
        return self._outcome

    def is_match(self):
        return self._outcome == LookupOutcome.MATCH

    def is_ambiguous(self):
        return self._outcome == LookupOutcome.AMBIGUOUS

    def candidates(self):
        """All matching NameCandidate objects (zero, one or many)."""
        return self._candidates

    def offsets(self):
        """Absolute offsets of every matching candidate."""
        return tuple(candidate.offset() for candidate in self._candidates)

    def collation_rule(self):
        return self._rule

    def reason(self):
        return self._reason

    def single_candidate(self):
        """
        Return the unique candidate, or raise ValueError when there is not
        exactly one match.
        """
        if len(self._candidates) != 1:
            raise ValueError(
                "lookup for %r is %s with %d candidates"
                % (self._query, self._outcome.value, len(self._candidates)))
        return self._candidates[0]

    def __repr__(self):
        return ("LookupResult(query=%r, outcome=%s, rule=%s, offsets=%s)"
                % (self._query, self._outcome.value, self._rule.value,
                   ["0x%x" % offset for offset in self.offsets()]))


def query_identity(query, candidates):
    """
    Resolve a requested name against stored NameCandidate objects using the
    explicitly named Windows equivalence rules.

    - identical bytes always match (the raw identity);
    - ASCII names additionally match case-insensitively under the
      documented Windows ASCII rule;
    - non-ASCII names only match on exact code-point identity, and the rule
      is reported as unknown rather than approximated;
    - several equivalent candidates yield AMBIGUOUS with every offset.

    @type query: str
    @param query: the name requested by the caller (treated as read-only)
    @type candidates: iterable of NameCandidate
    @rtype: LookupResult
    """
    if not isinstance(query, str):
        raise TypeError("query must be a str")

    query_ascii = _is_pure_ascii(query)
    query_lookup = ascii_lookup_key(query) if query_ascii else None

    exact = []
    equivalent = []
    unknown_rule_involved = not query_ascii

    for candidate in candidates:
        identity = candidate.identity()
        expected_bytes = _encode_query(identity.encoding(), query)
        # Exact raw identity: same code points AND same on-disk bytes.
        if expected_bytes is not None and identity.raw_bytes() == expected_bytes:
            exact.append(candidate)
        elif query_ascii and identity.collation_rule() == \
                CollationRule.CASE_INSENSITIVE_ASCII \
                and identity.lookup_key() == query_lookup:
            equivalent.append(candidate)
        if identity.collation_rule() == CollationRule.UNKNOWN:
            unknown_rule_involved = True

    matches = []
    seen = set()
    for candidate in exact + equivalent:
        if candidate.offset() not in seen:
            seen.add(candidate.offset())
            matches.append(candidate)

    rule = (CollationRule.CASE_INSENSITIVE_ASCII
            if query_ascii else CollationRule.UNKNOWN)

    if not matches:
        if unknown_rule_involved:
            return LookupResult(
                query, LookupOutcome.UNKNOWN_RULE, [], rule,
                "non-ASCII name: Windows collation cannot be reproduced; "
                "only exact code-point identity is supported")
        return LookupResult(query, LookupOutcome.NOT_FOUND, [], rule)

    if len(matches) > 1:
        return LookupResult(query, LookupOutcome.AMBIGUOUS, matches, rule,
                            "%d distinct stored names are equivalent under "
                            "the %s rule" % (len(matches), rule.value))
    return LookupResult(query, LookupOutcome.MATCH, matches, rule)


def _encode_query(encoding, query):
    """Re-encode a query text with a candidate's record codec."""
    if encoding == NameEncoding.COMPRESSED:
        try:
            return query.encode("windows-1252")
        except UnicodeEncodeError:
            return None
    return query.encode("utf-16le")
