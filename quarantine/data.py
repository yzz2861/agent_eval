# -*- coding: utf-8 -*-

"""Small caller-provided history set used to demonstrate the workflow.

The data set deliberately mixes:

* real local fixture bytes (via ``path``), and
* inline header captures (via ``bytes``), including truncated captures.

Every history record names the rule id that was signed off before the
weekend rule refresh. Rule ids missing from the current registry represent
rules retired by the update.
"""

from __future__ import absolute_import

import os
import struct


FIXTURE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'tests', 'fixtures',
)


def _fixture(name):
    return os.path.join(FIXTURE_DIR, name)


def _skippable_with_payload():
    """Skippable frame whose first bytes cannot satisfy the frame rule."""
    regular_frame = open(_fixture('sample.zst'), 'rb').read()[:8]
    payload = b'USERDATA'
    return (struct.pack('<II', 0x184D2A50, len(payload))
            + payload + regular_frame)


def _truncated_capture():
    """Recognizable magic cut below the gateway evidence floor (4 bytes)."""
    return open(_fixture('sample.jpg'), 'rb').read()[:3]


# Attachments the gateway still holds in quarantine and can rescan locally.
ATTACHMENTS = [
    {
        'attachment_id': 'ATT-001',
        'filename': 'photo-banner.jpg',
        'path': _fixture('sample.jpg'),
    },
    {
        # Acceptance case: format name stays "zst" but the old approval only
        # covered the regular frame rule; this capture matches the skippable
        # frame rule added/refreshed over the weekend.
        'attachment_id': 'ATT-002',
        'filename': 'telemetry-bundle.zst',
        'bytes': _skippable_with_payload(),
    },
    {
        'attachment_id': 'ATT-003',
        'filename': 'contract-2003.doc',
        'path': _fixture('sample_1.doc'),
    },
    {
        'attachment_id': 'ATT-004',
        'filename': 'quarterly-report.docx',
        'path': _fixture('sample.docx'),
    },
    {
        'attachment_id': 'ATT-005',
        'filename': 'assets-package.zip',
        'path': _fixture('sample.zip'),
    },
    {
        # Truncated capture: the JPEG SOI rule fires on 3 bytes but the
        # gateway requires a 4-byte signature block, so evidence is rejected.
        'attachment_id': 'ATT-006',
        'filename': 'partial-upload.jpg',
        'bytes': _truncated_capture(),
    },
    {
        # Format drift: previously approved as DOC, now scans as DOCX.
        'attachment_id': 'ATT-007',
        'filename': 'renamed-contract.docx',
        'path': _fixture('sample_1.docx'),
    },
    {
        # Policy difference: RTF is blocked under the legacy allowlist and
        # admitted under the updated one.
        'attachment_id': 'ATT-008',
        'filename': 'notes.rtf',
        'bytes': b'{\\rtf1\\ansi\\deff0 example notes}',
    },
    {
        # Old approval names a rule that no longer exists in the registry.
        'attachment_id': 'ATT-009',
        'filename': 'archive.tar',
        'path': _fixture('sample.tar'),
    },
    {
        # Stable, unchanged attachment: should stay cleared under both policies.
        'attachment_id': 'ATT-010',
        'filename': 'logo.png',
        'path': _fixture('sample.png'),
    },
]


# Previous gateway decisions (the small historical result set).
HISTORY = {
    'ATT-001': {
        'approved_format': 'jpg',
        'approved_rule_id': 'jpg',
        'decision': 'released',
    },
    'ATT-002': {
        'approved_format': 'zst',
        'approved_rule_id': 'zst.frame',
        'decision': 'released',
    },
    'ATT-003': {
        'approved_format': 'doc',
        'approved_rule_id': 'doc.worddoc-stream',
        'decision': 'released',
    },
    'ATT-004': {
        'approved_format': 'docx',
        'approved_rule_id': 'docx',
        'decision': 'released',
    },
    'ATT-005': {
        'approved_format': 'zip',
        'approved_rule_id': 'zip.local-header',
        'decision': 'released',
    },
    'ATT-006': {
        'approved_format': 'jpg',
        'approved_rule_id': 'jpg',
        'decision': 'released',
    },
    'ATT-007': {
        'approved_format': 'doc',
        'approved_rule_id': 'doc.root-entry',
        'decision': 'released',
    },
    'ATT-008': {
        'approved_format': 'rtf',
        'approved_rule_id': 'rtf',
        'decision': 'held-pending-policy',
    },
    'ATT-009': {
        'approved_format': 'tar',
        # Retired by the weekend rule refresh (replaced upstream, id removed).
        'approved_rule_id': 'tar.legacy-ustar',
        'decision': 'released',
    },
    'ATT-010': {
        'approved_format': 'png',
        'approved_rule_id': 'png',
        'decision': 'released',
    },
}
