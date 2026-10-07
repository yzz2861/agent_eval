# News

## Unreleased

### Feature

  * Added optional capability proxies (DRb.publish,
    DRb::CapabilityGrant, DRb::DRbCapabilityObject).  A server can publish
    an object with a declared allow-list of methods and per-method return
    policies; clients can derive strictly weaker capabilities and
    capabilities can be revoked independently.  Authorization state is
    kept and enforced server side, send/public_send and similar indirect
    entries cannot bypass the allow-list, and respond_to? reflects only
    the permitted interface.  The feature reuses the existing dRuby
    transport and is explicitly not a defense against untrusted Marshal
    payloads.

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
