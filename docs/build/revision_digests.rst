.. _revision_digests:

===========================
Revision Digest Verification
===========================

Alembic normally tracks which revisions have been applied to a database
by revision identifier only.  If a migration file that was already applied
is edited afterwards - without changing its revision id - the change is
invisible to the version table and to commands such as ``alembic history``.

Revision digest verification is an **opt-in** mechanism that closes this
gap.  When enabled, Alembic records a content digest and a graph signature
for every revision as it is successfully applied, and verifies the whole
applied history before subsequent migrations run.

Enabling verification
======================

Set the following option in the ``[alembic]`` section of the configuration
file (or pass ``verify_revision_digests=True`` to
:meth:`.EnvironmentContext.configure` in ``env.py``)::

    [alembic]
    verify_revision_digests = true

The name of the table used to store digests defaults to
``alembic_revision_digests`` and may be changed with the
``revision_digest_table`` option.

Establishing the baseline
=========================

Verification can only check revisions for which a digest has been
recorded.  When the feature is enabled on a database that already has
migrations applied, Alembic does **not** implicitly trust the current
files and does not create the digest table on its own; instead, commands
that run migrations fail with an error until a baseline is established
explicitly::

    alembic baseline

This records the current revision files as the trusted baseline for all
revisions currently applied to the database.  Run it again whenever an
intentional change to an already-applied revision file should be accepted.

On a brand new database there is nothing to trust yet, so the first
``alembic upgrade`` simply records digests as revisions are applied.

What is checked
===============

Before migrations run, every revision applied to the database is verified.
The verification scope is the full ancestor graph of all current database
heads, expanded along ``down_revision`` as well as ``depends_on`` edges,
including merge revisions and branched histories - not just the linear
``down_revision`` chain.  The check is purely static: no migration script
is executed in order to determine whether a revision changed.

Problems are reported in three separate categories:

  * **Revision files missing** - a revision that is recorded as applied
    no longer has a script file.
  * **Revision content changed** - the file exists but its bytes no
    longer match the recorded digest.
  * **Revision graph structure changed** - a revision's ``down_revision``
    or ``depends_on`` entries differ from the recorded signature, or the
    set of revisions that are ancestors of the database heads no longer
    matches the recorded baseline (for example a revision was inserted
    into or removed from the applied lineage).

If any problem is found, the migration is aborted before anything runs and
the database is left unchanged.  A newly added, legitimate revision is not
affected by this check and upgrades as usual; only changes to *already
applied* revisions are blocked.  The standalone ``alembic verify`` command
runs the same check on demand.

Digest computation contract
===========================

The content digest of a revision is defined as::

    "sha256:" + hexdigest(SHA256(<raw bytes of the revision script file>))

The file is read in binary mode and hashed byte for byte, exactly as stored
on disk.  No newline translation is performed (CRLF and LF line endings
produce different digests) and no text decoding or encoding detection is
applied.  The digest therefore depends only on the file contents and does
not drift between machines, platforms, or Python versions.

The graph signature is a canonical JSON document of the revision's sorted
``down_revision`` and resolved ``depends_on`` identifiers, which is equally
machine independent.

Notes and limitations
=====================

  * Verification and recording apply to **online** migrations only;
    offline (``--sql``) generation does not consult or modify the digest
    table.
  * ``alembic stamp`` records digests for the revisions it marks as
    applied, computed from the files present at stamp time.
  * Downgrades remove the digest rows of revisions that are no longer
    applied.
