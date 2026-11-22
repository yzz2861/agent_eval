Trust impact preview
====================

:mod:`jks.trust_impact` answers a narrow, read-only question: when a batch of
Java trust material is merged into one image, which applications gain public
certificate trust?

The preview reads only ``TrustedCertEntry`` objects.  It loads JKS/JCEKS images
with ``try_decrypt_keys=False`` and never calls ``decrypt()``.  Private-key and
secret-key entries are counted as ignored, not inspected.  Certificate identity
is the SHA-256 digest of the DER certificate; an alias is only a label.

Selection contracts
-------------------

Callers describe each application with a selection contract.  A contract can be
a :class:`~jks.trust_impact.SelectionContract`, a dictionary, an alias string,
a list of aliases, or the string ``all``::

  contracts = {
      "reporting": {
          "selection": "all",
          "baseline": {"certificates": [shared_sha256]},
      },
      "billing": {
          "aliases": ["billing-root"],
          "baseline": {"aliases": ["billing-root"],
                         "certificates": [billing_sha256]},
      },
  }

  preview = jks.preview_trust_impact(contracts, "merged-truststore.jks")
  print(preview.to_json())

``mode``/``selection`` is one of:

``all``
  The legacy application accepts every public certificate in the image.
``aliases``
  The application selects named aliases (``aliases``/``alias``).
``none``
  The application trusts no public entries.
``unknown``
  Explicitly unknown; it is never silently converted to ``all``.

The prior selection record is supplied with ``baseline``, ``previous``,
``record`` or ``selection_record``.  Use ``{"certificates": [...]}`` when the
real certificate identities are known.  ``{"aliases": [...]}`` is retained as
alias-only evidence; alias names alone do not establish certificate identity.
An omitted record and an explicitly empty record are different: the former is
reported as ``missing_selection_record`` and leaves ``expanded`` as ``None``;
the latter is a known zero-trust record.  A caller can also supply a
``baseline_image=`` or put a ``records=`` mapping beside the contracts.

Explicit outcomes
-----------------

* A requested alias that is absent is returned in ``missing_aliases`` with
  status ``missing_aliases``; other aliases in the same contract are still
  evaluated.
* An alias that points at a private or secret entry is returned in
  ``non_public_aliases``; its protected material is not read or used as a
  certificate chain.
* Duplicate public certificates are grouped by SHA-256.  Reports keep both
  ``trusted_entry_count`` (entry/alias objects) and
  ``trusted_certificate_count`` (distinct certificate identities), plus
  ``duplicate_certificates`` groups.  A duplicate copy does not widen
  cryptographic trust a second time, but the additional alias object is still
  visible.
* ``expanded`` is only asserted when certificate identity can be compared.
  ``transition`` calls out the important case where an application moves from
  one local authorization to multiple trusted certificate objects:
  ``local_authorization_to_multiple_trust_objects``.

Shared-certificate example
--------------------------

:func:`jks.shared_certificate_example` builds an in-memory target with one
shared certificate under two aliases plus a newly merged partner certificate.
The ``default-store`` application has a real prior record containing only the
shared certificate.  Its computed transition is
``local_authorization_to_multiple_trust_objects``, the shared certificate shows
up as a duplicate group, and the partner certificate is the single added
identity.

Run it with::

  python -c "import jks; print(jks.run_shared_certificate_example())"
