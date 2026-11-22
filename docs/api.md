# *certvalidator* API Documentation

### `CertificateValidator()` class

> ##### constructor
>
> > ```python
> > def __init__(self, end_entity_cert, intermediate_certs=None, validation_context=None):
> >     """
> >     :param end_entity_cert:
> >         An asn1crypto.x509.Certificate object or a byte string of the DER or
> >         PEM-encoded X.509 end-entity certificate to validate
> >
> >     :param intermediate_certs:
> >         None or a list of asn1crypto.x509.Certificate objects or a byte
> >         string of a DER or PEM-encoded X.509 certificate. Used in
> >         constructing certificate paths for validation.
> >
> >     :param validation_context:
> >         A certvalidator.context.ValidationContext() object that controls
> >         validation options
> >     """
> > ```
>
> ##### `.validate_tls()` method
>
> > ```python
> > def validate_tls(self, hostname):
> >     """
> >     :param hostname:
> >         A unicode string of the TLS server hostname
> >
> >     :raises:
> >         certvalidator.errors.PathValidationError - when an error occurs validating the path
> >         certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
> >         certvalidator.errors.InvalidCertificateError - when the certificate is not valid for TLS or the hostname
> >
> >     :return:
> >         A certvalidator.path.ValidationPath object of the validated
> >         certificate validation path
> >     """
> > ```
> >
> > Validates the certificate path, that the certificate is valid for
> > the hostname provided and that the certificate is valid for the purpose
> > of a TLS connection.
>
> ##### `.validate_usage()` method
>
> > ```python
> > def validate_usage(self, key_usage, extended_key_usage=None, extended_optional=False):
> >     """
> >     :param key_usage:
> >         A set of unicode strings of the required key usage purposes. Valid
> >         values include:
> >
> >          - "digital_signature"
> >          - "non_repudiation"
> >          - "key_encipherment"
> >          - "data_encipherment"
> >          - "key_agreement"
> >          - "key_cert_sign"
> >          - "crl_sign"
> >          - "encipher_only"
> >          - "decipher_only"
> >
> >     :param extended_key_usage:
> >         A set of unicode strings of the required extended key usage
> >         purposes. These must be either dotted number OIDs, or one of the
> >         following extended key usage purposes:
> >
> >          - "server_auth"
> >          - "client_auth"
> >          - "code_signing"
> >          - "email_protection"
> >          - "ipsec_end_system"
> >          - "ipsec_tunnel"
> >          - "ipsec_user"
> >          - "time_stamping"
> >          - "ocsp_signing"
> >          - "wireless_access_points"
> >
> >         An example of a dotted number OID:
> >
> >          - "1.3.6.1.5.5.7.3.1"
> >
> >     :param extended_optional:
> >         A bool - if the extended_key_usage extension may be ommited and still
> >         considered valid
> >
> >     :raises:
> >         certvalidator.errors.PathValidationError - when an error occurs validating the path
> >         certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
> >         certvalidator.errors.InvalidCertificateError - when the certificate is not valid for the usages specified
> >
> >     :return:
> >         A certvalidator.path.ValidationPath object of the validated
> >         certificate validation path
> >     """
> > ```
> >
> > Validates the certificate path and that the certificate is valid for
> > the key usage and extended key usage purposes specified.

### `ValidationContext()` class

> ##### constructor
>
> > ```python
> > def __init__(self, trust_roots=None, extra_trust_roots=None, other_certs=None,
> >              whitelisted_certs=None, moment=None, allow_fetching=False, crls=None,
> >              crl_fetch_params=None, ocsps=None, ocsp_fetch_params=None,
> >              revocation_mode="soft-fail", weak_hash_algos=None):
> >     """
> >     :param trust_roots:
> >         If the operating system's trust list should not be used, instead
> >         pass a list of byte strings containing DER or PEM-encoded X.509
> >         certificates, or asn1crypto.x509.Certificate objects. These
> >         certificates will be used as the trust roots for the path being
> >         built.
> >
> >     :param extra_trust_roots:
> >         If the operating system's trust list should be used, but augmented
> >         with one or more extra certificates. This should be a list of byte
> >         strings containing DER or PEM-encoded X.509 certificates, or
> >         asn1crypto.x509.Certificate objects.
> >
> >     :param other_certs:
> >         A list of byte strings containing DER or PEM-encoded X.509
> >         certificates, or a list of asn1crypto.x509.Certificate objects.
> >         These other certs are usually provided by the service/item being
> >         validated. In TLS, these would be intermediate chain certs.
> >
> >     :param whitelisted_certs:
> >         None or a list of byte strings or unicode strings of the SHA-1
> >         fingerprint of one or more certificates. The fingerprint is a hex
> >         encoding of the SHA-1 byte string, optionally separated into pairs
> >         by spaces or colons. These whilelisted certificates will not be
> >         checked for validity dates. If one of the certificates is an
> >         end-entity certificate in a certificate path, any TLS hostname
> >         mismatches, key usage errors or extended key usage errors will also
> >         be ignored.
> >
> >     :param moment:
> >         If certificate validation should be performed based on a date and
> >         time other than right now. A datetime.datetime object with a tzinfo
> >         value. If this parameter is specified, then the only way to check
> >         OCSP and CRL responses is to pass them via the crls and ocsps
> >         parameters. Can not be combined with allow_fetching=True.
> >
> >     :param crls:
> >         None or a list/tuple of asn1crypto.crl.CertificateList objects of
> >         pre-fetched/cached CRLs to be utilized during validation of paths
> >
> >     :param crl_fetch_params:
> >         None or a dict of keyword args to pass to
> >         certvalidator.crl_client.fetch() when fetching CRLs or associated
> >         certificates. Only applicable when allow_fetching=True.
> >
> >     :param ocsps:
> >         None or a list/tuple of asn1crypto.ocsp.OCSPResponse objects of
> >         pre-fetched/cached OCSP responses to be utilized during validation
> >         of paths
> >
> >     :param ocsp_fetch_params:
> >         None or a dict of keyword args to pass to
> >         certvalidator.ocsp_client.fetch() when fetching OSCP responses.
> >         Only applicable when allow_fetching=True.
> >
> >     :param allow_fetching:
> >         A bool - if HTTP requests should be made to fetch CRLs and OCSP
> >         responses. If this is True and certificates contain the location of
> >         a CRL or OCSP responder, an HTTP request will be made to obtain
> >         information for revocation checking.
> >
> >     :param revocation_mode:
> >         A unicode string of the revocation mode to use: "soft-fail" (the
> >         default), "hard-fail" or "require". In "soft-fail" mode, any sort of
> >         error in fetching or locating revocation information is ignored. In
> >         "hard-fail" mode, if a certificate has a known CRL or OCSP and it
> >         can not be checked, it is considered a revocation failure. In
> >         "require" mode, every certificate in the certificate path must have
> >         a CRL or OCSP.
> >
> >     :param weak_hash_algos:
> >         A set of unicode strings of hash algorithms that should be
> >         considered weak. Valid options include: "md2", "md5", "sha1"
> >     """
> > ```
>
> ##### `.crls` attribute
>
> > A list of all cached asn1crypto.crl.CertificateList objects
>
> ##### `.ocsps` attribute
>
> > A list of all cached asn1crypto.ocsp.OCSPResponse objects
>
> ##### `.new_revocation_certs` attribute
>
> > A list of newly-fetched asn1crypto.x509.Certificate objects that were
> > obtained from OCSP responses and CRLs

### `plan_revocation_evidence()` function

> Creates an offline plan for gathering revocation evidence for a batch of
> certificates. The plan is based on the certificates already validated in
> the validation context, the certificates and time periods covered by
> cached CRLs and OCSP responses, and a disclosure policy controlling which
> certificate identities may be disclosed to which issuing services. No
> network requests are made.
>
> > ```python
> > def plan_revocation_evidence(validation_context, certs, moment=None, disclosure_policy=None):
> >     """
> >     :param validation_context:
> >         A certvalidator.context.ValidationContext object containing the
> >         validated certificates and cached CRLs and OCSP responses
> >
> >     :param certs:
> >         A list of asn1crypto.x509.Certificate objects to plan revocation
> >         evidence gathering for
> >
> >     :param moment:
> >         None or a datetime.datetime object with a tzinfo value to plan
> >         for. If None, the moment of the validation context is used.
> >
> >     :param disclosure_policy:
> >         None or a dict with keys being unicode strings of service URLs
> >         (OCSP responder or CRL distribution point URLs), and values being
> >         lists of certificate identities that may be disclosed to that
> >         service. Each identity may be an asn1crypto.x509.Certificate
> >         object, or the SHA-1 fingerprint of the certificate as a byte
> >         string or unicode string of hex characters, optionally separated
> >         into pairs by spaces or colons. If None, no certificate identity
> >         may be disclosed to any service.
> >
> >     :return:
> >         A certvalidator.revocation_plan.RevocationEvidencePlan object
> >     """
> > ```

### `RevocationEvidencePlan()` class

> ##### `.moment` attribute
>
> > A datetime.datetime object the plan was created for
>
> ##### `.covered` attribute
>
> > A list of asn1crypto.x509.Certificate objects that require no query -
> > either already validated in the validation context, or covered by a
> > cached CRL or OCSP response for the plan moment
>
> ##### `.to_fetch` attribute
>
> > A list of tuples of (asn1crypto.x509.Certificate, list of unicode
> > strings) - certificates that require a query, along with the service
> > URLs the disclosure policy permits the certificate identity to be
> > disclosed to
>
> ##### `.suspended` attribute
>
> > A list of asn1crypto.x509.Certificate objects that require a query but
> > currently have no permitted channel
