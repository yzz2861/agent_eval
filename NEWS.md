# News

## Unreleased

### New features

  * Added the opt-in `:exception_envelope` DRb configuration. When
    enabled on both ends, remote exceptions are sent as controlled
    metadata and raised locally as `DRb::RemoteFailure`, without
    invoking custom Marshal hooks on the original exception.

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
