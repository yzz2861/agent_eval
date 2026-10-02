# Releases

## Unreleased

  - Add an optional `:audience` identifier to `Rack::Session::Cookie`. When set (e.g. to an application's mount path), the audience is included in the authenticated encryption purpose, so cookies cannot be replayed between applications that share secrets or cookie names.
  - Add `:legacy_cookies_until` (a `Time`) as an explicit, time-limited opt-in for accepting audience-less legacy cookies. Accepted legacy cookies are decoded and automatically re-issued in the new audience-bound format; after the given time they are rejected.
  - Parse every cookie sent under the session cookie name and apply a deterministic rule: a request with exactly one distinct valid value uses it (regardless of position), while a request containing more than one distinct valid value is rejected instead of relying on cookie ordering.

## v2.1.2

  - [CVE-2026-39324](https://github.com/advisories/GHSA-33qg-7wpp-89cq) Don't fall back to unencrypted coder if encryptors are present.

## v2.1.1

  - Prevent `Rack::Session::Pool` from recreating deleted sessions [CVE-2025-46336](https://github.com/rack/rack-session/security/advisories/GHSA-9j94-67jr-4cqj).

## v2.1.0

  - Improved compatibility with Ruby 3.3+ and Rack 3+.
  - Add support for cookie option `partitioned`.
  - Introduce `assume_ssl` option to allow secure session cookies through insecure proxy.

## v2.0.0

  - Initial migration of code from Rack 2, for Rack 3 release.

## v1.0.2

  - Fix missing `rack/session.rb` file.

## v1.0.1

  - Pin to `rack < 3`.

## v1.0.0

  - Empty shim release for Rack 2.
