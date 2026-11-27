msoffcrypto.custody module
==========================

.. automodule:: msoffcrypto.custody
   :members:
   :undoc-members:
   :show-inheritance:

The custody reviewer consumes caller-supplied handover events and optional
signature/receipt records.  It observes each artifact through the public
``OfficeFile(...).is_encrypted()`` entry point, compares the SHA-256 digest of
the delivered bytes with the event's evidence digest, and checks the event
time against its declared window.  A repeated delivery token is recorded as a
duplicate delivery and is excluded from the protection-state sequence and from
before/after links when the observed bytes and protection state are identical.

Ambiguous links retain all possible interpretations.  Each interpretation is
marked ``supported``, ``possible``, or ``excluded``; the report also lists the
provided receipts that cover the link and the required receipt fields that
would settle an unresolved reading.
