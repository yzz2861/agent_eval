"""
provenance.py

Source-mapping for the oletools extraction backend.

Every fragment derived from a sample (container members, decoded or
de-obfuscated content, concatenated streams) carries a provenance map that
links each derived byte/character back to:

* the identity of the container member it came from (name + occurrence
  index, so two nested objects with the same name stay distinct),
* the byte range(s) in the *original* sample bytes,
* the chain of decoding steps that produced the derived content.

Positions that cannot be mapped back exactly (many-to-one transforms such
as compression, approximate transforms such as base64, or concatenation of
several sources) are expressed as *sets* of source ranges and/or flagged as
uncertain.  A single offset is never fabricated when the mapping is not
exact.

IOC values extracted through this API are kept exactly as matched in the
derived text; only their provenance is added.

This module is offline and has no third-party dependencies.

Part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

import base64
import binascii
import codecs
import re
import zlib
from typing import NamedTuple


# === DATA MODEL ==============================================================

class MemberRef(NamedTuple):
    """Identity of one member inside its parent container.

    ``occurrence`` is the 0-based index of this member among siblings that
    share the same name, so two nested objects with identical names are
    never merged into a single piece of evidence.
    """
    name: str
    occurrence: int = 0


class DecodingStep(NamedTuple):
    """One transformation applied between the original bytes and a derived
    fragment (e.g. 'hex-decode', 'zlib-decompress')."""
    name: str
    detail: str = ''


class SourceRange(NamedTuple):
    """A byte range in the original sample, with the member path (from the
    root of the sample down to the member holding these bytes) and the
    decoding steps applied afterwards."""
    path: tuple          # tuple of MemberRef, root first
    start: int           # offset in the original sample bytes
    end: int
    steps: tuple = ()    # tuple of DecodingStep

    def __str__(self):
        loc = '/'.join(
            '%s[%d]' % (m.name, m.occurrence) for m in self.path
        ) or '<root>'
        return '%s:%d-%d' % (loc, self.start, self.end)


class Provenance(object):
    """Result of mapping a derived range back to the original sample.

    ``ranges`` is a *set* of SourceRange: several ranges appear whenever the
    derived fragment was assembled from several places (concatenation) or
    when the exact position cannot be reversed (the whole possible envelope
    is reported).  ``uncertain`` is True whenever any part of the mapping is
    approximate; in that case the ranges are a conservative envelope, not
    exact offsets.
    """
    __slots__ = ('origin', 'ranges', 'uncertain')

    def __init__(self, origin, ranges, uncertain=False):
        self.origin = origin
        self.ranges = tuple(ranges)
        self.uncertain = bool(uncertain)

    def describe(self):
        """Human-readable rendering for reports."""
        lines = []
        for r in self.ranges:
            path = '/'.join(
                '%s[%d]' % (m.name, m.occurrence) for m in r.path
            ) or '<root>'
            steps = ' -> '.join(
                s.name + ('(%s)' % s.detail if s.detail else '')
                for s in r.steps) or 'none'
            approx = ' (approximate)' if self.uncertain else ''
            lines.append('%s bytes %d-%d%s in %s, decoding: %s'
                         % (self.origin, r.start, r.end, approx, path, steps))
        return '\n'.join(lines)


class _Segment(object):
    """Maps a range of a derived buffer to its source range(s).

    exact + positions is None: linear mapping, source offset =
        sources[0].start + stride * (derived_pos - dstart); sources has
        exactly one entry.
    exact + positions: explicit original offset per derived position
        (len(positions) == dend - dstart + 1); sources holds the envelope.
    not exact: sources is the conservative envelope (one or more ranges);
        any lookup returns all of them and flags uncertainty.
    """
    __slots__ = ('dstart', 'dend', 'sources', 'exact', 'stride', 'positions')

    def __init__(self, dstart, dend, sources, exact=True, stride=1,
                 positions=None):
        self.dstart = dstart
        self.dend = dend
        self.sources = tuple(sources)
        self.exact = exact
        self.stride = stride
        self.positions = positions

    def src_span(self, start, end):
        """Exact source span for derived [start, end) inside this segment."""
        if self.positions is not None:
            return (self.positions[start - self.dstart],
                    self.positions[end - self.dstart])
        src = self.sources[0]
        return (src.start + self.stride * (start - self.dstart),
                src.start + self.stride * (end - self.dstart))


def _merge_ranges(ranges):
    """De-duplicate and merge adjacent ranges that share path and steps."""
    unique = sorted(set(ranges),
                    key=lambda r: (r.path, r.steps, r.start, r.end))
    merged = []
    for r in unique:
        if merged and merged[-1].path == r.path and \
                merged[-1].steps == r.steps and r.start <= merged[-1].end:
            last = merged[-1]
            merged[-1] = SourceRange(last.path, last.start,
                                     max(last.end, r.end), last.steps)
        else:
            merged.append(r)
    return merged


# === PROVENANCE MAP ==========================================================

class ProvenanceMap(object):
    """Provenance of one derived buffer (bytes or text).

    Offsets are plain integer positions, so the same class tracks byte
    buffers and decoded text.
    """

    def __init__(self, origin, length, segments):
        self.origin = origin
        self.length = length
        self._segments = tuple(segments)

    @classmethod
    def for_data(cls, data, origin='<memory>'):
        """Provenance of the original sample itself (identity mapping)."""
        rng = SourceRange((), 0, len(data), ())
        return cls(origin, len(data), [_Segment(0, len(data), (rng,))])

    # -- structural operations ----------------------------------------------

    def slice(self, start, end):
        """Provenance of the sub-range [start, end) of this buffer."""
        if not 0 <= start <= end <= self.length:
            raise ValueError('slice out of bounds: %d-%d' % (start, end))
        segs = []
        for seg in self._segments:
            ds, de = max(seg.dstart, start), min(seg.dend, end)
            if ds >= de:
                continue
            if seg.exact:
                if seg.positions is not None:
                    pos = seg.positions[ds - seg.dstart: de - seg.dstart + 1]
                    src = seg.sources[0]
                    env = SourceRange(src.path, pos[0], pos[-1], src.steps)
                    segs.append(_Segment(ds - start, de - start, (env,),
                                         True, 1, tuple(pos)))
                else:
                    s0, s1 = seg.src_span(ds, de)
                    src = seg.sources[0]
                    rng = SourceRange(src.path, s0, s1, src.steps)
                    segs.append(_Segment(ds - start, de - start, (rng,),
                                         True, seg.stride))
            else:
                # conservative: keep the whole envelope
                segs.append(_Segment(ds - start, de - start, seg.sources,
                                     False))
        return ProvenanceMap(self.origin, end - start, segs)

    def member(self, name, start, end, occurrence=0):
        """Provenance of a container member stored at [start, end).

        Appends a MemberRef to the path of every source range so nested
        membership stays visible, and same-named members stay distinct via
        ``occurrence``.
        """
        sub = self.slice(start, end)
        ref = MemberRef(name, occurrence)
        segs = []
        for seg in sub._segments:
            sources = tuple(
                SourceRange(s.path + (ref,), s.start, s.end, s.steps)
                for s in seg.sources)
            segs.append(_Segment(seg.dstart, seg.dend, sources, seg.exact,
                                 seg.stride, seg.positions))
        return ProvenanceMap(self.origin, sub.length, segs)

    @staticmethod
    def concat(parts):
        """Provenance of the concatenation of several derived buffers.

        Each part keeps its own source ranges and decoding steps, so a
        fragment assembled from several places maps back to a *set* of
        ranges.
        """
        parts = list(parts)
        if not parts:
            raise ValueError('concat needs at least one part')
        origin = parts[0].origin
        segs = []
        offset = 0
        for part in parts:
            if part.origin != origin:
                raise ValueError('cannot concat provenance from different '
                                 'origins: %r vs %r' % (origin, part.origin))
            for seg in part._segments:
                segs.append(_Segment(seg.dstart + offset, seg.dend + offset,
                                     seg.sources, seg.exact, seg.stride,
                                     seg.positions))
            offset += part.length
        return ProvenanceMap(origin, offset, segs)

    # -- transforms ----------------------------------------------------------

    def transform(self, step, out_length, input_span=None):
        """Provenance after applying a decoding step.

        ``step`` is a DecodingStep (or a plain name).  ``input_span``, when
        given, maps one output position p to the input span (a, b, exact)
        it was produced from.  When ``input_span`` is None the transform is
        not reversible (e.g. decompression): the whole output maps to the
        union of all input source ranges and is flagged uncertain.
        """
        if isinstance(step, str):
            step = DecodingStep(step)

        def add_step(rng):
            return SourceRange(rng.path, rng.start, rng.end,
                               rng.steps + (step,))

        if input_span is None:
            sources = []
            seen = set()
            for seg in self._segments:
                for s in seg.sources:
                    ns = add_step(s)
                    if ns not in seen:
                        seen.add(ns)
                        sources.append(ns)
            return ProvenanceMap(self.origin, out_length,
                                 [_Segment(0, out_length, tuple(sources),
                                           False)])

        def map_position(p):
            """-> (exact, tuple of SourceRange without the new step)."""
            a, b, ex = input_span(p)
            covering = [seg for seg in self._segments
                        if seg.dstart <= a and b <= seg.dend]
            if len(covering) == 1 and covering[0].exact:
                seg = covering[0]
                s0, s1 = seg.src_span(a, b)
                src = seg.sources[0]
                return bool(ex), (SourceRange(src.path, s0, s1, src.steps),)
            prov = self.lookup(a, b)
            if prov.uncertain or len(prov.ranges) != 1:
                return False, tuple(prov.ranges)
            return bool(ex), tuple(prov.ranges)

        new_segments = []
        run = None  # [exact, spans(list of (s,e)), sources(list), env_end]

        def flush(dend):
            if run is None:
                return
            exact, spans, sources, _env_end, count, _ps = run
            dstart = dend - count
            if exact:
                positions = [s for s, _e in spans] + [spans[-1][1]]
                src0 = sources[0]
                n = len(spans)
                widths = [positions[i + 1] - positions[i]
                          for i in range(n)]
                uniform = all(w == widths[0] for w in widths) and all(
                    positions[i + 1] - positions[i] ==
                    positions[1] - positions[0]
                    for i in range(n))
                env = SourceRange(src0.path, positions[0], positions[-1],
                                  src0.steps)
                if uniform and n > 0:
                    new_segments.append(_Segment(
                        dstart, dend, (env,), True, widths[0]))
                else:
                    new_segments.append(_Segment(
                        dstart, dend, (env,), True, 1, tuple(positions)))
            else:
                new_segments.append(_Segment(dstart, dend, tuple(sources),
                                             False))

        out_pos = 0
        for p in range(out_length):
            exact_p, sources_p = map_position(p)
            sources_p = tuple(add_step(s) for s in sources_p)
            if exact_p:
                s0 = sources_p[0].start
                s1 = sources_p[0].end
                path_steps = (sources_p[0].path, sources_p[0].steps)
            else:
                s0 = min(s.start for s in sources_p)
                s1 = max(s.end for s in sources_p)
                path_steps = (tuple(s.path for s in sources_p),
                              tuple(s.steps for s in sources_p))
            if run is not None:
                same = run[0] == exact_p
                if same and exact_p:
                    same = (run[5] == path_steps and run[3] == s0)
                elif same:
                    same = (run[5] == path_steps and s0 <= run[3])
                if not same:
                    flush(out_pos)
                    run = None
            if run is None:
                # [exact, spans, sources, env_end, count, path_steps]
                run = [exact_p, [], [], 0, 0, path_steps]
            if exact_p:
                run[1].append((s0, s1))
                if not run[2]:
                    run[2].append(sources_p[0])
            else:
                for s in sources_p:
                    if s not in run[2]:
                        run[2].append(s)
            run[3] = max(run[3], s1) if run[4] else s1
            run[4] += 1
            out_pos += 1
        flush(out_length)
        return ProvenanceMap(self.origin, out_length, new_segments)

    # -- lookup ---------------------------------------------------------------

    def lookup(self, start, end):
        """Map derived range [start, end) back to original source ranges."""
        if not 0 <= start <= end <= self.length:
            raise ValueError('lookup out of bounds: %d-%d' % (start, end))
        ranges = []
        uncertain = False
        for seg in self._segments:
            ds, de = max(seg.dstart, start), min(seg.dend, end)
            if ds >= de:
                continue
            if seg.exact:
                s0, s1 = seg.src_span(ds, de)
                src = seg.sources[0]
                ranges.append(SourceRange(src.path, s0, s1, src.steps))
            else:
                ranges.extend(seg.sources)
                uncertain = True
        ranges = _merge_ranges(ranges)
        return Provenance(self.origin, ranges, uncertain)


# === READY-MADE TRANSFORMS ===================================================
# Each helper takes (data, provenance-map) and returns
# (new-data, new-provenance-map), recording one DecodingStep.

def apply_transform(data, prov, step, func, input_span=None):
    """Generic helper: apply ``func`` to data and record the decoding step.

    ``input_span`` maps one output position to the input span (a, b, exact)
    it came from; pass None for non-reversible transforms.
    """
    out = func(data)
    if isinstance(step, str):
        step = DecodingStep(step)
    return out, prov.transform(step, len(out), input_span)


def hex_decode(data, prov):
    """Hex-decode; exactly reversible (2 input chars per output byte)."""
    compact = re.sub(rb'\s+', b'', bytes(data))
    out = binascii.unhexlify(compact)
    # positions in `compact`; if whitespace was removed the mapping to the
    # original buffer is no longer exact, so only claim exactness when the
    # input was already compact.
    if len(compact) == len(data):
        span = lambda p: (2 * p, 2 * p + 2, True)
    else:
        span = None
    return out, prov.transform(DecodingStep('hex-decode'), len(out), span)


def base64_decode(data, prov):
    """Base64-decode; 3 output bytes share a 4-char quantum, so the reverse
    mapping is approximate (conservative envelope, flagged uncertain)."""
    out = base64.b64decode(bytes(data))
    n = len(data)

    def span(p):
        a = (p // 3) * 4
        return a, min(a + 4, n), False

    return out, prov.transform(DecodingStep('base64-decode'), len(out), span)


def xor_decode(data, prov, key):
    """XOR with a single-byte key; exactly reversible (1:1)."""
    out = bytes(b ^ key for b in bytes(data))
    span = lambda p: (p, p + 1, True)
    return out, prov.transform(
        DecodingStep('xor-decode', 'key=0x%02x' % key), len(out), span)


def zlib_decompress(data, prov):
    """zlib-decompress; not position-reversible, the whole output maps to
    the whole compressed input and is flagged uncertain."""
    out = zlib.decompress(bytes(data))
    return out, prov.transform(DecodingStep('zlib-decompress'), len(out),
                               None)


def decode_text(data, prov, encoding='utf-8', errors='strict'):
    """Decode bytes to text, tracking the byte span of every character.

    Exact for strict decoding; with a forgiving error handler the mapping
    is flagged uncertain since characters may not correspond to input
    bytes one-to-one.
    """
    decoder = codecs.getincrementaldecoder(encoding)(errors=errors)
    char_byte_end = []   # char index -> end offset in input bytes
    parts = []
    raw = bytes(data)
    for i in range(len(raw)):
        chunk = decoder.decode(raw[i:i + 1])
        for _ch in chunk:
            char_byte_end.append(i + 1)
            parts.append(_ch)
    tail = decoder.decode(b'', True)
    for _ch in tail:
        char_byte_end.append(len(raw))
        parts.append(_ch)
    text = ''.join(parts)
    exact = (errors == 'strict')
    starts = [0] + char_byte_end[:-1]

    def span(p):
        return starts[p], char_byte_end[p], exact

    return text, prov.transform(
        DecodingStep('text-decode', encoding), len(text),
        span if text else (lambda p: (0, 0, exact)))


# === IOC EXTRACTION ==========================================================

# Simple, dependency-free IOC patterns.  Values are reported exactly as
# matched; no normalization (no defanging, no case folding) is applied.
IOC_PATTERNS = (
    ('URL', re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)),
    ('email', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
                         r'\b')),
    ('IPv4', re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('domain', re.compile(r'\b(?:[A-Za-z0-9-]+\.)+'
                          r'(?:com|net|org|info|biz|io|ru|cn|top|xyz)\b')),
)


class IOCEntry(NamedTuple):
    """One IOC match: the value exactly as found, where it was found in the
    derived text, and its provenance back to the original sample."""
    ioc_type: str
    value: str
    start: int           # offset in the derived text
    end: int
    provenance: Provenance


def find_iocs(text, prov, patterns=None):
    """Find IOCs in derived ``text`` and attach provenance to each match.

    Matches of later patterns that fall entirely inside an already
    reported span (e.g. a domain inside a URL) are skipped to avoid
    duplicate evidence.
    """
    if patterns is None:
        patterns = IOC_PATTERNS
    entries = []
    taken = []
    for ioc_type, regex in patterns:
        for match in regex.finditer(text):
            s, e = match.span()
            if any(s >= ts and e <= te for ts, te in taken):
                continue
            taken.append((s, e))
            entries.append(IOCEntry(ioc_type, match.group(0), s, e,
                                    prov.lookup(s, e)))
    entries.sort(key=lambda entry: (entry.start, entry.end))
    return entries


class IOCGroup(NamedTuple):
    """Display aggregation of identical IOC values; every individual entry
    (with its full provenance) is preserved."""
    ioc_type: str
    value: str
    entries: tuple

    @property
    def provenances(self):
        return tuple(entry.provenance for entry in self.entries)


def aggregate_iocs(entries):
    """Group IOC entries by (type, value) for display.

    Aggregation never merges provenance: each entry keeps its own complete
    source mapping, so identical IOCs found in distinct members (including
    same-named nested objects) remain distinguishable.
    """
    groups = {}
    order = []
    for entry in entries:
        key = (entry.ioc_type, entry.value)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(entry)
    return [IOCGroup(t, v, tuple(groups[(t, v)])) for t, v in order]


# === MINIMAL CONTAINER FORMAT (for tests and small tools) ====================
# Layout: magic b'SMC1', 1 byte member count, then per member:
# 1 byte name length, name (ascii), 4 bytes little-endian data length, data.
# Members may themselves be SMC1 blobs, giving nested containers.

SIMPLE_CONTAINER_MAGIC = b'SMC1'


class ContainerMember(NamedTuple):
    """Location of one member's data inside its container's byte buffer."""
    name: str
    occurrence: int      # index among same-named siblings
    start: int
    end: int


def read_simple_container(data, offset=0):
    """Parse an SMC1 blob, returning the list of ContainerMember."""
    data = bytes(data)
    if data[offset:offset + 4] != SIMPLE_CONTAINER_MAGIC:
        raise ValueError('not an SMC1 container at offset %d' % offset)
    count = data[offset + 4]
    pos = offset + 5
    members = []
    seen = {}
    for _ in range(count):
        name_len = data[pos]
        pos += 1
        name = data[pos:pos + name_len].decode('ascii')
        pos += name_len
        size = int.from_bytes(data[pos:pos + 4], 'little')
        pos += 4
        occurrence = seen.get(name, 0)
        seen[name] = occurrence + 1
        members.append(ContainerMember(name, occurrence, pos, pos + size))
        pos += size
    return members


def build_simple_container(members):
    """Build an SMC1 blob from a list of (name, data-bytes) pairs."""
    out = bytearray(SIMPLE_CONTAINER_MAGIC)
    out.append(len(members))
    for name, data in members:
        encoded = name.encode('ascii')
        out.append(len(encoded))
        out += encoded
        out += len(data).to_bytes(4, 'little')
        out += data
    return bytes(out)
