# News

## Unreleased

### Improvements

  * Added instance-level type profiles (`XMLRPC::TypeProfile`). A client or
    server instance can now be configured with an explicit profile
    (e.g. `XMLRPC::TypeProfile.standard` or `XMLRPC::TypeProfile.extended`)
    that both its encoder and parser use, instead of changing the global
    `XMLRPC::Config` constants.

    The extended profile enables the `<nil/>`, `<i8>` (64-bit integers) and
    `<bigdecimal>` (exact decimals via `BigDecimal`, never routed through
    `Float`) extension types. Integers are tagged by range and peer
    capability: out-of-range values are rejected instead of being squeezed
    into `<i4>`. Unknown extension tags are rejected or kept as a controlled
    `XMLRPC::UnknownValue` depending on the profile's `unknown_extension`
    policy. Errors for values nested in arrays/structs carry the value path
    (e.g. `params[0]["key"][2]`).

## 0.3.4

### Improvements

  * GH-40: Added accessor methods to `XMLRPC::Config`.
    * Patch by Herwin Weststrate

  * Added REXML dependency.
    * Patch by Herwin Weststrate

  * GH-55: Added support for Nokogiri.
    * Patch by Herwin Weststrate

  * GH-56: Added support for Rack.
    * Patch by Herwin Weststrate

  * GH-59: Dropped support for mod_ruby.
    * Patch by Herwin Weststrate

  * GH-63: Added support for libxml_ruby 6.0.0 or later.
    * Patch by Herwin Weststrate

### Fixes

  * GH-42 GH-43: Fixed a bug that IPv6 address host isn't used.
    * Patch by Herwin Weststrate

### Thanks

  * Herwin Weststrate

## 0.3.3

### Improvements

  * GH-36: Stopped to unmarshal all classes. Classes that include
    `XMLRPC::Marshallable` are only allowed.

    [Patch by ooooooo-q]
    [Found by ooooooo-q and plenumlab separately]

### Thanks

  * ooooooo-q
  * plenumlab

## 0.3.2

### Improvements

  * Added support for Ruby 3.0.
    [GitHub#27][Reported by Herwin Weststrate]

### Thanks

  * Herwin Weststrate

## 0.3.1

### Improvements

  * Added support for comparing `XMLRPC::Base64`.
    [GitHub#14][Patch by Herwin Weststrate]

  * Added support for `application/xml` as `Content-Type`.
    [GitHub#24][Reported by Reiermeyer]

  * Added `XMLRPC::Server#port`.
    [GitHub#17][Reported by Harald Sitter]
    [GitHub#18][Patch by Herwin Weststrate]

### Fixes

  * Fixed a bug that unexpected exception is raised on no data.
    [GitHub#25][Patch by Herwin Weststrate]

### Thanks

  * Herwin Weststrate

  * Reiermeyer

  * Harald Sitter
