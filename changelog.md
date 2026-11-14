# changelog

## 0.11.2

 - Added an injectable HTTP fetch policy for CRL and OCSP retrieval:
   `certvalidator.http_policy.FetchPolicy` restricts URLs to explicit
   scheme/host/port allowlists, rejects loopback and link-local addresses
   (including DNS results, re-checked on every redirect hop), refuses
   cross-origin redirects, and caps response size and request timeout
 - `crl_client.fetch()`, `crl_client.fetch_certs()` and
   `ocsp_client.fetch()` now accept `http_policy` and `fetcher` keyword
   parameters, also passable via `crl_fetch_params`/`ocsp_fetch_params`
 - Policy rejections raise `certvalidator.errors.CRLFetchError` or
   `certvalidator.errors.OCSPFetchError`, subclasses of
   `CRLValidationIndeterminateError`/`OCSPValidationIndeterminateError`
   with a machine-readable `reason` attribute; logs and error messages
   contain only the URL origin, never a full URL or request body

## 0.11.1

 - Updated [asn1crypto](https://github.com/wbond/asn1crypto) dependency to
   `0.18.1`, [oscrypto](https://github.com/wbond/oscrypto) dependency to
   `0.16.1`.

## 0.11.0

 - Updated for compatibility with oscrypto 0.16.0

## 0.10.0

 - Backwards compability break: the `require_revocation_checks` parameter was
   removed and a new keyword parameter, `revocation_mode`, was added to
   `ValidationContext()`. Validation may now be in a `soft-fail` (default),
   `hard-fail`, or `require` mode. See the documentation for information about
   the behavior of each mode.
 - Added certificate signature hash algorithm checks, with a default blacklist
   of `md2` and `md5`
 - Trust roots no longer need to be self-signed, allowing for cross-signed roots
 - Keys with no `key_usage` extension are now permitted to sign CRLs
 - An OCSP or CRL check may fail and not result in an error if the other is
   successful
 - Exceptions for expired or not-yet-valid certificates now include full date
   and time
 - Self-signed certificates now have a unique exception message instead of a
   generic message indicating the issuer could not be found in the trust roots
 - `crl_client` can now handle CRLs that are PEM-encoded
 - Fixed encoding of URLs in Python 2 when fetching CRLs and OCSP responses
 - Corrected an error when trying to check the signature of a certificate to
   determine if it is self-signed or not
 - Fixed a bug with duplicate HTTP headers during OCSP requests on Python 3
 - Fixed an exception that would be thrown if a signature not using RSA, DSA or
   ECDSA is found

## 0.9.1

 - Fixed a bug with whitelisting certificates on Python 3.2

## 0.9.0

 - Initial release
