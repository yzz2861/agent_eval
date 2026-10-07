# News

## Unreleased

### Improvement

  * Added `DRb::DRbBatch`, an explicit batch builder for remote calls.
    Later calls in a batch may refer to the results of earlier calls
    through restricted slot placeholders, and the whole batch is
    submitted and executed in a single round trip.  Calls that depend
    on a failed call are reported as skipped (keeping the original
    error) while independent branches still run.  Batches are not
    transactional: nothing is rolled back or replayed after a failure.

## 2.2.3 - 2025-05-21

### Improvement

  * Added support for "Changelog" link in RubyGems.org page.
    * GH-30
    * Patch by Mark Young

  * Dropped `ObjectSpace._id2ref` dependency because
    `ObjectSpace._id2ref` is deprecated. `Drb::WeakIdConv` is
    meaningless by this. So it's deprecated. Use the default ID
    converter instead.
    * GH-35
    * https://bugs.ruby-lang.org/issues/15711

### Fixes

  * SSL: Fixed wrong certificate version.
    * GH-29

### Thanks

  * Mark Young
