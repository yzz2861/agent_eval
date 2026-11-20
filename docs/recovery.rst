Offline recovery checks
=======================

.. automodule:: jks.recovery
   :members:
   :show-inheritance:

The check accepts a purpose, the entry categories that may be used, and
public matching material (certificate DER/PEM, public keys, fingerprints,
aliases, or mappings/lists of those).  Matching entries are reported in
priority order.  Certificate entries never acquire a private-key
capability merely because their chain is complete.

Both the ``recovery`` and ``security`` role views expose the missing
capabilities and next actions.  No private key, secret key or password is
read or rendered.
