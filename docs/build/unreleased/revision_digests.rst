.. change::
    :tags: feature, commands

    Added optional revision digest verification.  When enabled via the
    ``verify_revision_digests`` configuration option, Alembic records a
    content digest and revision graph signature for every revision as it
    is applied, and verifies the applied history - expanded along the
    ancestor graph of all current heads, including merges and
    ``depends_on`` dependencies - before subsequent migrations run.
    Missing revision files, changed revision contents, and revision
    graph structure changes are reported as separate categories.  The
    new ``alembic baseline`` command explicitly establishes the trusted
    baseline for databases that already have migrations applied, and the
    new ``alembic verify`` command runs the check on demand.
