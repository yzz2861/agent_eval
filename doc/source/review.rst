Review Mode
===========

Security sign-off is typically performed against a SARIF or JSON report
long after the scan ran. By that time a build tool may have replaced the
source tree, so the reviewer cannot tell which exact file contents and
which exact rule material produced each finding.

The optional review mode attaches reproducible material identifiers to
every result. The identifiers are content based and require no running
service, so a report can be re-checked later against the workspace that
produced it.

Material identifiers
-------------------

Each result carries two pieces of material inside a ``review`` block:

* ``file_material`` identifies the exact bytes that were parsed and handed
  to the rules. It records a SHA-256 ``content_digest``, the byte length
  and a workspace-relative ``logical_path``.
* ``rule_material`` identifies the rule that produced the finding. It
  records the plugin source digest together with the resolved plugin
  configuration digest that was actually passed to the rule.

Because the location is a logical, workspace-relative path and every other
identifier is a content hash, moving the whole working directory does not
invalidate a result.

Running a review scan
---------------------

Enable review mode with ``--review``. The JSON and SARIF formatters then
include the material identifiers on each result and a top-level ``review``
summary block.

.. code-block:: console

    bandit --review -r src -f json -o report.json

Re-verifying a report
---------------------

Re-check an existing review report against the current workspace with
``--verify-report``. The targets name the candidate workspace roots used
to resolve the logical paths. No new scan is performed.

.. code-block:: console

    bandit --verify-report report.json src -f json -o verify.json

Each result is classified as:

* ``reproducible`` - the file content and the rule material both match;
* ``not_reproducible`` at the ``file`` layer - the file cannot be located,
  read, its content digest differs, or the finding location is absent;
* ``not_reproducible`` at the ``rule`` layer - the plugin declaration is
  missing or changed, or the resolved plugin configuration digest differs.

A missing plugin declaration or configuration material is always reported
as not reproducible at the rule layer rather than being guessed at. The
command exits non-zero when any result is not reproducible.

Workspace changes during a scan
-------------------------------

Review mode snapshots each file immediately before parsing it and re-checks
the on-disk content immediately afterwards. Findings from a file whose
contents changed, or that disappeared, while it was being scanned are
withheld from the published results and listed in the review summary
together with the reason (``file changed during scan`` or
``file deleted during scan``). Only findings whose file material still
matches the bytes on disk are published.

A worked demonstration that produces three reproducible findings and shows
the move, file-layer and rule-layer outcomes is available at
``examples/review/demo_review.py``.
