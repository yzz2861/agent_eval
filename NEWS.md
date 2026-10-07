# News

## Unreleased

### Improvements

  * Added instance-level type profiles (`XMLRPC::TypeProfile`) for
    clients and servers. `set_type_profile` gives the encoder and the
    parser of one instance the same explicit configuration, without
    mutating the global `XMLRPC::Config` constants. Predefined profiles:
    `XMLRPC::TypeProfile::STANDARD` and `XMLRPC::TypeProfile::EXTENDED`
    (i8, nil and decimal extensions).

  * Integers are encoded as `i4` or `i8` depending on their range and
    the profile's capabilities; out-of-range integers are never stuffed
    into `i4`.

  * Added exact decimal values (`XMLRPC::Decimal`) via the `decimal`
    extension tag; they are never converted through `Float`.

  * Unknown extension tags are rejected or kept as controlled
    `XMLRPC::UnknownValue` values, depending on the profile. They are
    never instantiated as arbitrary Ruby classes.

  * Encoding and parsing errors in nested arrays/structs now report the
    path of the offending value, e.g. `$["key"][2]`.

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
