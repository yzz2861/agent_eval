\
# Offline TUF Receipt Comparator

An offline comparator that answers a narrow upgrade-review question for a
Python TUF repository: when a batch of historical delegation/allocation rules
is removed, which existing repair-acceptance receipts can still be
re-verified, and which require a brand new receipt?

The comparator never touches the network. It loads three local inputs and
re-runs the real python-tuf verification workflow against each of them.

## Inputs

1. **Historical metadata** (`--old-metadata`): the TUF metadata that was
   trusted when the receipts were issued (`root.json`, `timestamp.json`,
   `snapshot.json`, `targets.json` and one JSON file per delegated role).
2. **Candidate metadata** (`--candidate-metadata`): the proposed metadata
   after the historical rules are deleted.
3. **Receipts and retained evidence** (`--receipts`, `--evidence`): the
   historical acceptance records plus the actual target bytes still kept on
   disk.

A receipt pins a target path, the accepted content hashes/length, its
issuance time (used as the verification reference time so later metadata
expiry does not disturb historical re-verification) and the delegation path
that was walked when it was issued.

## What is actually verified

For every receipt the comparator:

1. Re-verifies the full `root -> timestamp -> snapshot -> targets` chain in
   both bundles using `tuf.ngclient` `TrustedMetadataSet`, so signature,
   hash, length and version checks are exactly those a real TUF client runs.
2. Reconstructs the delegation path with the same pre-order depth-first walk
   as `ngclient.Updater`, including delegation order and terminating roles.
3. Confirms the candidate still resolves the **same target path** and that
   its recorded hashes match the receipt. Re-ordered roles or bumped metadata
   versions are fine as long as the same download content is still reachable
   through a valid path.
4. Re-hashes the retained evidence bytes against the candidate target info.

Targets that never had a receipt are never reported as a risk. They are only
counted as `targets_without_receipt_ignored` to make the audit boundary
explicit.
\

## Verdict codes

| Code | Meaning | Action |
| --- | --- | --- |
| `reverifiable` | Candidate path resolves and retained evidence re-hashes. | Keep the existing receipt. |
| `path_broken` | No delegated role serves the target path any more. | Re-issue the receipt. |
| `delegated_role_removed` | A role on the path is referenced but its metadata is gone. | Re-issue the receipt. |
| `content_drifted` | Path resolves but candidate hashes differ from the receipt. | Re-issue the receipt. |
| `metadata_untrusted` | A metadata chain fails signature/hash/version verification. | Fix the bundle, then re-issue. |
| `not_historically_valid` | The receipt cannot be reproduced even against old metadata. | Investigate before re-issuing. |
| `evidence_missing` | No retained target bytes are available for the receipt. | Restore evidence or re-issue. |
| `evidence_mismatch` | Retained bytes do not match the recorded hashes. | Restore evidence or re-issue. |

Only `reverifiable` means the historical conclusion still holds. The report
splits outcomes into `re_verifiable` and `blocked` accordingly.

## Usage

Run the comparator against any offline metadata and evidence directories:

```bash
python -m offline_receipt_compare.cli \
  --old-metadata path/to/old_metadata \
  --candidate-metadata path/to/candidate_metadata \
  --receipts path/to/receipts \
  --evidence path/to/evidence \
  --output report.json
```

## Worked examples

The two example fixtures are generated under `../examples_store`:

```bash
python -m offline_receipt_compare.build_examples
```

- `scenario_a_reverifiable`: the candidate renames/re-orders the delegated
  role and bumps metadata versions, but the same firmware content is still
  reachable and the retained evidence hashes correctly. Verdict:
  `reverifiable`. An additional target without a receipt is counted as
  ignored, not as a risk.
- `scenario_b_reissue_required`: the candidate drops the delegated role that
  carried the target, so no trusted path resolves it even though the evidence
  bytes are still on disk. Verdict: `path_broken`, requiring a fresh receipt.

## Tests

```bash
python -m unittest tests.test_offline_receipt_compare \
  tests.test_offline_receipt_examples
```

The tests build fresh in-memory repositories with `FixtureRepository`, so they
do not depend on the checked-in example fixtures and run fully offline.
