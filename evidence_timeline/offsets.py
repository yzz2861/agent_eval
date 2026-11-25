"""Exact byte-range location inside a DER blob.

Time-stamp commitments are only explainable if we can name the real bytes a
message imprint was calculated over. The analyzer works with sub-encodings
(signature content, nested record DER, whole record DER) and needs every
occurrence of those bytes located in the supplied blob. DER is deterministic,
so offsets reported here correspond exactly to what was originally parsed.
"""

from __future__ import unicode_literals

from .model import ByteRange


class ByteOffsetIndex(object):
    """Locate raw sub-encodings as absolute ``[start, end)`` byte ranges."""

    def __init__(self, blob):
        self.blob = blob

    def locate(self, needle, record_id=None):
        """Return every byte range whose contents equal ``needle``."""

        if not needle:
            return []
        ranges = []
        search_from = 0
        while True:
            start = self.blob.find(needle, search_from)
            if start < 0:
                break
            ranges.append(ByteRange(
                record_id=record_id or '',
                start=start,
                end=start + len(needle),
            ))
            search_from = start + 1
        return ranges
