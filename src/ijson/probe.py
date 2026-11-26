'''
Budgeted probing of JSON streams for the presence of managed fields.

This module implements a *probe completion condition* on top of the regular
ijson interfaces, meant for callers (e.g. archive security reviews) that may
only read a bounded number of bytes from a stream while confirming whether
certain managed fields appear in it.

The main entry point is 'probe'. It scans a JSON source for one or more
prefixes (using the same prefix syntax as 'ijson.items') and reports, for
each of them, one of three conclusions:

- 'ProbeStatus.FOUND': the prefix was observed in the stream.
- 'ProbeStatus.EXCLUDED': the stream was consumed to its natural end
  (EOF) within the read budget and the prefix never appeared, so it is
  confirmed absent from the full range.
- 'ProbeStatus.PENDING': the read budget was exhausted before the stream
  ended, so the prefix may still appear in the unread remainder and no
  conclusion is available.

Conclusions are independent of the read chunk size ('buf_size'): the
incremental parser reassembles tokens that span chunk boundaries, so a
field split across two reads is still detected, and an EXCLUDED verdict
only requires that EOF was observed within the budget.
'''

import enum

from ijson import common
from ijson.adapters import from_iter


class ProbeStatus(enum.Enum):
    '''
    Possible conclusions of probing a single prefix.
    '''
    #: The prefix was observed in the stream.
    FOUND = 'found'
    #: The stream ended naturally within the read budget and the prefix
    #: never appeared; it is confirmed absent from the full range.
    EXCLUDED = 'excluded'
    #: The read budget was exhausted before the stream ended; the prefix
    #: may appear in the unread remainder, so the conclusion stays pending.
    PENDING = 'pending'
    #: The prefix was not part of the probe selection and therefore was
    #: not checked at all.
    UNCHECKED = 'unchecked'


class _BudgetedReader:
    '''
    File-like wrapper around a source that enforces a read budget.

    Reads pass through until 'max_bytes' units (bytes for binary streams)
    have been consumed; further reads then report an empty result while
    'budget_exhausted' records that the end of data was artificial, so a
    budget cut is never mistaken for the natural end of the stream
    ('eof_reached' is only set by a genuine empty read from the source).
    Short reads from unbuffered sources are accounted by the amount
    actually returned.
    '''

    def __init__(self, source, max_bytes):
        self._source = source
        self._remaining = max_bytes
        self.bytes_read = 0
        self.eof_reached = False
        self.budget_exhausted = False

    def read(self, n=-1):
        if n == 0:
            return self._source.read(0)
        if self._remaining is not None:
            if self._remaining <= 0:
                self.budget_exhausted = True
                return self._source.read(0)
            if n is None or n < 0 or n > self._remaining:
                n = self._remaining
        data = self._source.read(n)
        self.bytes_read += len(data)
        if self._remaining is not None:
            self._remaining -= len(data)
        if not data:
            self.eof_reached = True
        return data


class FieldProbe:
    '''
    Conclusion for a single probed prefix.

    Attributes:

    - 'prefix': the probed prefix, in 'ijson.items' syntax.
    - 'status': a 'ProbeStatus' value.
    - 'occurrences': how many values were observed at the prefix (i.e.
      how many times 'ijson.items' would yield it) before probing
      stopped.
    - 'event': the (event, value) pair of the first match, if any.
    - 'bytes_read': units read from the source when the first match
      occurred (only meaningful for FOUND).
    - 'reason': human-readable explanation of the conclusion.
    '''

    def __init__(self, prefix):
        self.prefix = prefix
        self.status = ProbeStatus.PENDING
        self.occurrences = 0
        self.event = None
        self.bytes_read = 0
        self.reason = ''

    def _record_match(self, event, value, bytes_read):
        if event in ('map_key', 'end_map', 'end_array'):
            # Structural events about the surroundings of the prefix, not
            # values found at it.
            return
        if self.occurrences == 0:
            self.status = ProbeStatus.FOUND
            self.event = (event, value)
            self.bytes_read = bytes_read
        self.occurrences += 1

    def __repr__(self):
        return 'FieldProbe(%r, %s)' % (self.prefix, self.status.value)


class ProbeResult:
    '''
    Outcome of a 'probe' call.

    Attributes:

    - 'probes': tuple of 'FieldProbe', one per requested prefix.
    - 'bytes_read': total units read from the source.
    - 'ended_naturally': True if the stream reached EOF within the budget.
    - 'budget_exhausted': True if reading stopped because the budget ran
      out before the stream ended.
    - 'budget': the read budget that was enforced (None for unlimited).
    - 'buf_size': the read chunk size that was used.
    '''

    def __init__(self, probes, reader, budget, buf_size):
        self.probes = tuple(probes)
        self.bytes_read = reader.bytes_read
        self.ended_naturally = reader.eof_reached
        self.budget_exhausted = reader.budget_exhausted
        self.budget = budget
        self.buf_size = buf_size
        self._by_prefix = dict((p.prefix, p) for p in self.probes)

    @property
    def complete(self):
        # True if no prefix was left with a PENDING conclusion.
        return all(p.status is not ProbeStatus.PENDING for p in self.probes)

    @property
    def prefixes(self):
        return tuple(p.prefix for p in self.probes)

    def __iter__(self):
        return iter(self.probes)

    def __getitem__(self, prefix):
        return self._by_prefix[prefix]

    def status_of(self, prefix):
        '''
        Conclusion for 'prefix'; UNCHECKED if it was not in the selection.
        '''
        field_probe = self._by_prefix.get(prefix)
        if field_probe is None:
            return ProbeStatus.UNCHECKED
        return field_probe.status

    def explain(self, prefix=None):
        '''
        Human-readable explanation of the conclusions.

        With 'prefix=None' (the default) a summary covering every probed
        prefix and the overall reading outcome is returned. Otherwise the
        explanation for a single prefix is returned, including the case of
        prefixes that fell outside the probed selection.
        '''
        if prefix is not None:
            field_probe = self._by_prefix.get(prefix)
            if field_probe is None:
                return (
                    'prefix %r was not part of the probe selection %s; it '
                    'falls outside the checked scope, so it was not '
                    'inspected (unchecked)' % (prefix, self.prefixes)
                )
            return field_probe.reason
        lines = [p.reason for p in self.probes]
        if self.ended_naturally:
            lines.append(
                'the stream was read to its natural end (EOF) after %d '
                'units; absences are confirmed for the full range'
                % self.bytes_read
            )
        elif self.budget_exhausted:
            lines.append(
                'reading stopped when the budget of %r units was exhausted '
                'after %d units, before the stream ended; conclusions for '
                'unmatched prefixes stay pending'
                % (self.budget, self.bytes_read)
            )
        else:
            lines.append(
                'reading stopped early after %d units because every '
                'selected prefix was found' % self.bytes_read
            )
        return chr(10).join(lines)

    def __repr__(self):
        return 'ProbeResult(%s)' % ', '.join(
            '%r: %s' % (p.prefix, p.status.value) for p in self.probes
        )


def _finalize(probes, reader, budget):
    for field_probe in probes:
        if field_probe.status is ProbeStatus.FOUND:
            field_probe.reason = (
                'prefix %r was observed (%d occurrence(s), first as event '
                '%r after reading %d units); the incremental parser '
                'reassembles tokens that span read chunks, so the match '
                'holds for any buf_size' % (
                    field_probe.prefix, field_probe.occurrences,
                    field_probe.event[0], field_probe.bytes_read,
                )
            )
        elif reader.eof_reached:
            field_probe.status = ProbeStatus.EXCLUDED
            field_probe.reason = (
                'prefix %r was not seen after reading the stream to its '
                'natural end (EOF) within the budget (%d units read); it '
                'is confirmed absent from the full range, regardless of '
                'the read chunk size' % (field_probe.prefix, reader.bytes_read)
            )
        else:
            field_probe.status = ProbeStatus.PENDING
            field_probe.reason = (
                'the read budget of %r units was exhausted after %d units, '
                'before the stream ended; prefix %r may still appear in '
                'the unread remainder, so the conclusion stays pending' % (
                    budget, reader.bytes_read, field_probe.prefix,
                )
            )


def probe(source, *prefixes, max_bytes=None, buf_size=64 * 1024,
          backend=None, **config):
    '''
    Probe 'source' for the presence of 'prefixes' within a read budget.

    'source' may be anything the synchronous 'ijson.parse' accepts: a
    file-like object (including unbuffered raw streams, which may return
    short reads), a bytes/str object, or an iterable of bytes/str chunks.
    Prefixes use the same syntax as 'ijson.items' (e.g. 'docs.item.meta')
    and several of them are checked in a single pass, either as separate
    arguments or as a single list/tuple.

    'max_bytes' caps how many units are read from the source; None (the
    default) means no limit. A prefix is reported EXCLUDED only when the
    natural end of the stream was observed within the budget; if the
    budget runs out first, the conclusion stays PENDING. Note that a
    budget exactly equal to the stream length cannot confirm EOF and
    therefore still yields PENDING for absent prefixes.

    'buf_size' only controls the read chunk size and never changes the
    conclusions. 'backend' defaults to the top-level 'ijson' module; any
    ijson backend module may be passed instead. Additional keyword
    arguments ('config') are forwarded to 'ijson.parse'.

    Returns a 'ProbeResult'.
    '''
    if len(prefixes) == 1 and isinstance(prefixes[0], (list, tuple, set, frozenset)):
        prefixes = tuple(prefixes[0])
    if not prefixes:
        raise ValueError('probe() requires at least one prefix')
    if backend is None:
        import ijson
        backend = ijson
    source = common._get_source(source)
    if common.is_async_file(source):
        raise ValueError('probe() does not support asynchronous sources')
    if not common.is_file(source):
        if common.is_iterable(source):
            source = from_iter(source)
        else:
            raise ValueError('Unknown source type: %r' % type(source))
    reader = _BudgetedReader(source, max_bytes)
    probes = []
    by_prefix = {}
    for prefix in prefixes:
        if prefix not in by_prefix:
            field_probe = FieldProbe(prefix)
            probes.append(field_probe)
            by_prefix[prefix] = field_probe
    events = backend.parse(reader, buf_size=buf_size, **config)
    try:
        for prefix, event, value in events:
            field_probe = by_prefix.get(prefix)
            if field_probe is not None:
                field_probe._record_match(event, value, reader.bytes_read)
                if all(p.status is ProbeStatus.FOUND for p in probes):
                    break
    except common.IncompleteJSONError:
        if not reader.budget_exhausted:
            raise
    finally:
        events.close()
    _finalize(probes, reader, max_bytes)
    return ProbeResult(probes, reader, max_bytes, buf_size)
