# Changes

## 1.6.0

* Added the `build_tls_channel_bindings()` entry point and `TLSChannelBinding` class which normalize IPv4/IPv6 endpoints and the binding type, validate the certificate digest length and serialize the GSS-API length-prefixed structure before the NTLMv2 MD5 is calculated
* Added `ChannelBindingPolicy` with explicit `local`, `proxy` and `none` trust modes to distinguish locally observed bindings from those injected by a reverse proxy that terminates TLS; the default policy remains local only
* Added `NtlmContext.channel_binding_hash` for a trusted, pre-computed 16-byte channel binding hash with strict length validation; it is mutually exclusive with `cbt_data`
* Split channel binding failures into `ChannelBindingStructureError`, `ChannelBindingDigestError` and `ChannelBindingPolicyError` in `ntlm_auth.exceptions`; error messages never contain certificate or application-data material
* Endpoint and binding normalization guarantees identical binding bytes for IPv6 case differences, packed/text IP literals, TLS 1.2 vs TLS 1.3 and certificate chain changes that keep the same leaf digest
* Existing `GssChannelBindingsStruct` and `server_certificate_hash` callers keep producing byte identical channel binding hashes

## 1.5.0 (Jun 16, 2020)

* Added the `mic_present` property to the `NtlmContext` class to determine if a MIC has been added to the authentication message.
* Added the `sign` and `verify` function to the `NtlmContext` to sign data and verify signatures.
* Added the `reset_rc4_state` function to the `NtlmContext` to allow a caller to reset the incoming and outgoing RC4 cipher.
* Added the `NTLMSSP_NEGOTIATE_UNICODE` flag to the negotiate message to ensure the challenge and authentication message's text fields can be unicode encoded

## 1.4.0 (Aug 19, 2019)

* Added the `session_key` attribute to the `NtlmContext` class so the session key can be accessed in downstream libraries

## 1.3.0 (Apr 9, 2019)

* Added optional dependency for `cryptography` for faster RC4 cipher calls
* Removed the deprecation warning for Ntlm, this is still advised not to use but there's no major harm keep it in place for older hosts
* Add CI test for Python 3.7 and 3.8

## 1.2.0 (Jun 7, 2018)

* Deprecated ntlm_auth.ntlm.Ntlm in favour of ntlm_auth.ntlm.NtlmContext
* This is because `Ntlm` is heavily geared towards HTTP auth which is not always the case, `NtlmContext` makes things more generic
* Updated docs and tests to reflect this
* Dropped support for Python 3.3

## 1.1.0 (Mar 7, 2018)

* Removed DES code as the license was found to be incorrect from the source
* Added new DES code not based on the original
* Fixed up some deprecation warnings
* Changed tests from running unittest to py.test
* Changed licence from GPL to MIT as code is not all my own

## 1.0.6 (Oct 16, 2017)

* More changes to packaging to better handle copyright and licensing

## 1.0.5 (Jun 22, 2017)

* Added support for password hashes when using NTLMv1 authentication
* Better handling of servers that fully conform to the NTLM spec, will check before trying to get the Version field in a challenge message instead of just failing.

## 1.0.2-1.0.4

* Various changes to get Python packaging to work with ordereddict no code changes

## 1.0.1 (Aug 29, 2016)

Major fork from python-ntlm3 which is no longer in active maintenance. Features added since that latest release there;

* Added support for Python 3.5
* Almost complete rewrite of how python-ntlm3 handled authentication to support newer features
* Added support for NTLMv2 auth and fixed up some older auth methods
* Moved code to separate classes to help cleanup the code
* Added support for channel_bindings (CBT) when supplying a certificate hash
* Added support for MIC data for authenticate messages
* Support for signing and sealing of messages
* More comments on each methods relating back to the MS-NLMP document pack on NTLM authentication for easier maintenance
* Created target_info.py to handle AV_PAIRS and putting it in the target info
* Renaming of some variables to match more closely with the Microsoft documentation, makes it easier to understand what is happening
* Rewriting of tests to accommodate these new changes and to cover the new cases
