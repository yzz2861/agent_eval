# Offline Review Sampling

`detect_secrets.sampling` turns a baseline into a reproducible manual-review
sampling plan. It addresses a specific reporting problem: a security lead can
only review a small fraction of findings each week, but aggregate "human
coverage" can look healthy while an entire source queue is never looked at.

## Core rules

* **One finding, one slot.** A finding is a distinct
  `(filename, line_number, hashed_secret)` location. When several plugins
  flag the same location they are merged into a single finding. Plugin
  multiplicity is recorded (`detector_types`, `plugin_hit_count`) but never
  increases sampling weight, so noisy overlaps cannot hoard review slots.
* **Stratified by queue and detector.** Every finding belongs to exactly one
  `(source_queue, primary_detector)` stratum. The primary detector is the
  lexicographically smallest detector that fired, so stratum assignment is
  independent of plugin execution order.
* **Fixed-seed, no global randomness.** Ranks are `SHA-256(seed || finding_id)`
  in `randomness.py`, never the `random` module. The same baseline, seed,
  budget and allocation settings produce byte-identical plans on any machine.
* **Reviews are external inputs.** Human review annotations are loaded from a
  separate file; the sampler can never mark a finding reviewed on its own.

## Allocation modes

* `even` (default): round-robin across strata, giving every queue a fair offer
  of a review slot.
* `proportional`: largest-remainder allocation by stratum population. This
  intentionally mirrors volume-based distribution, where a small queue can
  receive few or zero slots.
* `--queue-caps`: an optional JSON map of queue -> maximum sample slots, which
  reproduces operational staffing limits. Unused cap is not redistributed, so
  a starved queue stays visible instead of being hidden by other queues.

A stratum whose sample fraction is below `--under-review-threshold`
(default `0.1`) is flagged `under_reviewed`, independently for every stratum.
The aggregate report also counts how many strata are under-reviewed, so a
small queue with almost no sample is surfaced even when total coverage looks
good.

## Inputs

* `baseline`: a standard detect-secrets baseline JSON (top-level `results`),
  or an export with a top-level `findings` list. Export entries may carry an
  explicit `source_queue` field.
* queue map (`--queue-map`): JSON object mapping filename prefixes to source
  queues. The longest matching prefix wins; unmatched files go to
  `unclassified`.
* reviews (`--reviewed`): a JSON list of finding ids, or a JSON object whose
  keys are finding ids.

## Commands

Build a plan and print the coverage/uncertainty table:

```
python -m detect_secrets.sampling.cli plan baseline.json \
    --seed 20261123 --budget 40 \
    --queue-map queues.json --reviewed reviewed.json \
    --allocation-mode proportional --queue-caps caps.json \
    --under-review-threshold 0.1
```

Write the full replayable plan (allocation, selection and report) as JSON:

```
python -m detect_secrets.sampling.cli plan baseline.json \
    --seed 20261123 --budget 40 --queue-map queues.json \
    --output plan.json
```

Let compliance verify whether a specific exception was missed. Re-running with
the same seed recomputes the identical inclusion decision; exit code `1` means
the finding was drawn into the sample but has no review annotation:

```
python -m detect_secrets.sampling.cli verify baseline.json \
    --finding-id "legacy/old.py:1:hash-l1" \
    --seed 20261123 --budget 40 --queue-map queues.json \
    --reviewed reviewed.json
```

## Report fields

Each stratum row reports population size, sample size, sample fraction,
human-reviewed count, human coverage, remaining unreviewed count, a Wilson 95%
interval for the in-sample review rate, and the `under_reviewed` flag. The
aggregate block reports totals plus `strata_under_reviewed`, so residual
uncertainty is shown per queue rather than averaged away.
