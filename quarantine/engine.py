# -*- coding: utf-8 -*-

"""Header-only scanning engine built on top of ``filetype``.

The engine works on plain local bytes (paths, bytes/bytearray or file-like
objects are accepted through ``filetype.utils.get_bytes``) and replays the
current rule registry in the same order ``filetype.match`` uses.
"""

from __future__ import absolute_import

import base64

from filetype.utils import get_bytes

from .rules import RULES


class ScanResult(object):
    """Outcome of scanning one attachment header.

    Attributes:
        attachment_id: identifier copied from the caller input.
        header_length: number of header bytes actually available (<= 8192).
        matched_rule: first matching :class:`~quarantine.rules.Rule` or None.
        matching_rules: every rule whose matcher accepts the header, in
            registry order. When more than one rule matches the result is
            order-sensitive: only the first one is advertised by filetype.
        sufficient: True when the header carries enough bytes for the
            winning rule's signature check.
    """

    def __init__(self, attachment_id, header_length, matched_rule,
                 matching_rules, sufficient):
        self.attachment_id = attachment_id
        self.header_length = header_length
        self.matched_rule = matched_rule
        self.matching_rules = matching_rules
        self.sufficient = sufficient

    @property
    def format(self):
        return self.matched_rule.extension if self.matched_rule else None

    @property
    def mime(self):
        return self.matched_rule.mime if self.matched_rule else None

    @property
    def rule_id(self):
        return self.matched_rule.rule_id if self.matched_rule else None

    def to_dict(self):
        return {
            'attachment_id': self.attachment_id,
            'header_length': self.header_length,
            'format': self.format,
            'mime': self.mime,
            'rule_id': self.rule_id,
            'matching_rule_ids': [rule.rule_id for rule in self.matching_rules],
            'evidence_sufficient': self.sufficient,
        }


def scan_buffer(attachment_id, buf):
    """Scan a bytes/bytearray header and return a :class:`ScanResult`.

    Only the first 8192 bytes are inspected, matching filetype's own header
    limit; passing a truncated capture therefore keeps the original byte
    length visible through ``header_length`` instead of being padded.
    """
    header = get_bytes(buf)
    matching = [rule for rule in RULES if rule.match(header)]
    winner = matching[0] if matching else None
    sufficient = winner is not None and len(header) >= winner.min_bytes
    return ScanResult(
        attachment_id=attachment_id,
        header_length=len(header),
        matched_rule=winner,
        matching_rules=matching,
        sufficient=sufficient,
    )


def scan_path(attachment_id, path):
    """Scan a local file path without reading the whole attachment."""
    with open(path, 'rb') as fp:
        header = get_bytes(fp)
    return scan_buffer(attachment_id, header)


def rescan(attachment):
    """Rescan one attachment record from the caller-provided history.

    The record may carry either a local ``path`` or an inline ``bytes``
    capture (bytes/bytearray or base64 string). Records without any header
    material are returned as an unresolvable :class:`ScanResult`.
    """
    attachment_id = attachment['attachment_id']
    if attachment.get('path'):
        return scan_path(attachment_id, attachment['path'])
    raw = attachment.get('bytes')
    if raw is None and attachment.get('bytes_base64'):
        raw = base64.b64decode(attachment['bytes_base64'])
    if raw is None:
        return ScanResult(attachment_id, 0, None, [], False)
    return scan_buffer(attachment_id, raw)


def evaluate(attachments):
    """Rescan a list of attachment records, keyed by ``attachment_id``."""
    results = {}
    for attachment in attachments:
        result = rescan(attachment)
        results[result.attachment_id] = result
    return results
