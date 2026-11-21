Offline migration forensics
==========================

The `jks.migration` module inspects one or more keystore snapshots
without contacting a CA, a JVM, or any other online service.  It is meant for
decommissioning work: proving which entry in a newer keystore is the same
certificate as an entry in an older one, and finding entries whose alias stayed
the same while the certificate was actually replaced.

Certificate identity
--------------------

An identity is the SHA-256 digest of the DER encoded certificate.  Aliases are
reported as labels and history, never as identity.  Consequently:

* the same certificate under a new alias is reported as a rename, and
* the same alias with different certificate material is reported as a
  certificate rotation.

A rename record has `identity_preserved` set to True.  A rotation record
has `identity_preserved` set to False and lists the caller supplied
high-risk purposes it affects in `affected_high_risk_usages`.  The two kinds
of change are always emitted as independent records.

Usage inventory
---------------

Callers describe what each entry is for.  Several shapes are accepted, for
example::

    usages = {
        'tls-server': {
            'aliases': ['legacy-web', 'web'],
            'risk': 'high',
        },
        'internal-metrics': {
            'aliases': ['web'],
            'risk': 'low',
        },
    }

If the whole inventory is unlabelled, every purpose is treated
conservatively as high-risk.  Once any purpose carries an explicit risk
label, unlabelled purposes are non-critical.  Use `risk: high` or
`high_risk: True` for critical purposes and `risk: low` or `high_risk: False`
for the rest.  An alias-to-purposes mapping such as
{'legacy-web': ['tls-server']} is also accepted.

Keystore sources
----------------

Sources are ordered from the oldest hand-off to the newest.  Each source may be
a path, raw bytes, a loaded pyjks keystore, or a dictionary::

    sources = [
        {'name': 'old', 'path': 'old.jks', 'password': 'changeit'},
        {'name': 'new', 'path': 'new.jks', 'password': 'changeit'},
    ]
    report = jks.inspect_migration(sources, usages)

Damaged and unverifiable files
------------------------------

JKS and JCEKS files whose signature cannot be verified, or whose tail is
truncated, are parsed on a best-effort basis.  Only complete entries are used.
The report records the problem in `warnings` and sets `incomplete` to
True while still returning every certificate hand-off that could be
confirmed.  A failing source never discards results from the other sources.

Private key handling
--------------------

Key entries are loaded with `try_decrypt_keys=False`.  Private keys and
secret keys are never decrypted and no private key bytes, store passwords, or
entry passwords are copied into the report.  Only public certificate material,
its fingerprints, and public certificate metadata are reported.

Report fields
-------------

identities
    Mapping from certificate SHA-256 fingerprint to aliases, sources, public
    certificate metadata, purposes, and high-risk purposes.

observations
    One public-certificate observation per recovered entry.

handoffs
    Confirmed observations that carry a certificate identity.

renames
    Alias changes that preserve a certificate identity.

rotations
    Certificate replacements, including affected high-risk purposes.

changes
    Renames and rotations in migration order.

unresolved
    Entries or usage records that could not be tied to public certificate
    material.

warnings and errors
    Non-fatal salvage notes and source loading failures.
