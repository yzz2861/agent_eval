Certificate de-duplication preflight
=====================================

.. py:module:: jks.cert_dedup

Several Java keystores may carry copies of the same public certificate.
A migration can keep one shared certificate object and store only references
from each entry, but archive queries still need to rebuild the exact public
chain that belonged to every entry.

The preflight checker reads pyjks records directly:

* ``PrivateKeyEntry.cert_chain`` is an ordered list of
  ``(certificate_type, certificate_data)`` tuples;
* ``TrustedCertEntry.cert`` is a one-slot public chain;
* entries such as ``SecretKeyEntry`` have no public chain and are reported
  separately.

Two independent checks are performed:

``objects``
    Every distinct certificate object used by a visible chain must still be
    present in the shared certificate store.

``slots``
    Every entry must keep positional references.  A set of certificate IDs is
    not sufficient: it proves object existence, but it does not prove order or
    the number of occurrences of a certificate in a chain.  Reports include a
    fingerprint for the expected and actual object at each position.

Python API
----------

::

    import jks
    from jks.cert_dedup import DedupPlan, preflight_certificate_dedup

    store = jks.KeyStore.load("keystore.jks", "changeit")
    private_key = store.private_keys["mykey"]

    objects = {}
    refs = []
    for position, cert_record in enumerate(private_key.cert_chain):
        object_id = "cert-%d" % position
        objects[object_id] = cert_record
        refs.append(object_id)

    plan = DedupPlan(certificates=objects, chains={"mykey": refs})
    report = preflight_certificate_dedup(store, plan)

    print(report.objects_ok)
    print(report.slots_ok)
    print(report.unreadable_entries)

``report.ok`` is true only when both ``objects_ok`` and ``slots_ok`` are true.
Entries without a readable public chain do not make the preflight fail; they
are listed in ``report.unreadable_entries`` so they can be handled separately.

JSON and command line
---------------------

Certificate material in JSON can be a plain UTF-8 string, a ``base64:`` or
``hex:`` prefixed string, or an object with ``cert`` and ``encoding`` fields.
Synthetic material may therefore be as small as ``"synthetic-public-a"``.

Visible chains::

    {
      "entries": {
        "alpha": {
          "cert_chain": [
            {"type": "X.509", "cert": "synthetic-public-a"},
            {"type": "X.509", "cert": "synthetic-public-b"}
          ]
        }
      }
    }

De-duplication plan::

    {
      "certificates": {
        "pub-a": {"type": "X.509", "cert": "synthetic-public-a"},
        "pub-b": {"type": "X.509", "cert": "synthetic-public-b"}
      },
      "chains": {
        "alpha": ["pub-a", "pub-b"]
      }
    }

Run::

    python -m jks.cert_dedup --chains chains.json --plan plan.json
    python -m jks.cert_dedup --chains chains.json --plan plan.json --json
    python -m jks.cert_dedup --demo

An unordered certificate set can be supplied for an entry, for example
``{"alpha": {"pub-a", "pub-b"}}`` or ``{"set": ["pub-a", "pub-b"]}``.  The
object check can still pass, but slot recovery fails because a set carries no
positional evidence.  Repeated occurrences are reported separately with their
expected positions and the positions that were lost.

The repository also provides ``tools/dedup_preflight.py`` and
``tools/cert_dedup_preflight.py`` as command-line wrappers.
