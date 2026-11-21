# coding: utf-8
"""
Offline audit support for RFC 3161 time-stamp tokens carried inside CMS.

The package turns the raw asn1crypto parse tree into reviewable provenance
records for offline exhibit inventories. Every association between a receipt
and an exhibit is derived solely from local bytes:

* the digest algorithm declared by the TSTInfo message imprint,
* the message-imprint digest bytes declared by the receipt,
* the nesting path that locates the receipt inside its carrier file.

Displayed times (TSTInfo genTime) are recorded for reference only and are
never used to decide that two exhibits or two receipts are the same.

Signature authenticity is never evaluated here. Callers that performed their
own verification may attach the verdict through ``build_inventory()`` or the
``--verdicts`` option; otherwise the receipt stays marked ``unprovided``.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

from .inventory import build_inventory
from .matching import apply_signature_verdicts
from .receipts import ReceiptParseError, parse_receipt_file

__all__ = [
    'build_inventory',
    'apply_signature_verdicts',
    'parse_receipt_file',
    'ReceiptParseError',
]
