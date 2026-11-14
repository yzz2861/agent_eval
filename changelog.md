# changelog

## 0.12.0

 - Fixed a security issue where a validation path could be anchored at a
   certificate that is not one of the caller's trust roots when cross-signed
   or same-subject-name root certificates were present. Path building and
   path validation are now bound to the exact trust roots provided, and a
   single validation will never switch to a different root chain.
 - Validation paths are now explicitly prioritized - shorter paths and paths
   anchored at earlier-specified trust roots are preferred, and validation
   backtracks through candidate paths in that order.
 - Issuer lookup within a validation path now only considers certificates
   located before the certificate in the path, uses the authority key
   identifier and authority issuer/serial number to disambiguate duplicate
   subject names, and raises a stable error when the issuer is ambiguous.
 - Path building now detects certificate loops (including cross-signed
   loops) and paths exceeding the maximum length of 8 certificates, raising
   a stable `PathBuildingError` for each case.

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
