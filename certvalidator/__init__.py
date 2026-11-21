# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import pem
from asn1crypto.x509 import Certificate

from .context import ValidationContext
from .errors import ValidationError, PathBuildingError, InvalidCertificateError
from .joint import (
    JointValidationResult,
    UsageRequirement,
    validate_joint_usage,
    validate_joint_usages,
)
from .validate import validate_path, validate_tls_hostname, validate_usage
from .version import __version__, __version_info__
from ._errors import pretty_message
from ._types import type_name, str_cls, byte_cls


__all__ = [
    '__version__',
    '__version_info__',
    'CertificateValidator',
    'JointValidationResult',
    'UsageRequirement',
    'ValidationContext',
    'validate_joint_usage',
    'validate_joint_usages',
]


class CertificateValidator():

    # A certvalidator.context.ValidationContext object
    _context = None

    # An asn1crypto.x509.Certificate object
    _certificate = None

    # A certvalidator.path.ValidationPath object - only set once validated
    _path = None

    def __init__(self, end_entity_cert, intermediate_certs=None, validation_context=None):
        """
        :param end_entity_cert:
            An asn1crypto.x509.Certificate object or a byte string of the DER or
            PEM-encoded X.509 end-entity certificate to validate

        :param intermediate_certs:
            None or a list of asn1crypto.x509.Certificate objects or a byte
            string of a DER or PEM-encoded X.509 certificate. Used in
            constructing certificate paths for validation.

        :param validation_context:
            A certvalidator.context.ValidationContext() object that controls
            validation options
        """

        if not isinstance(end_entity_cert, Certificate):
            if not isinstance(end_entity_cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    end_entity_cert must be a byte string or an instance of
                    asn1crypto.x509.Certificate, not %s
                    ''',
                    type_name(end_entity_cert)
                ))
            if pem.detect(end_entity_cert):
                _, _, end_entity_cert = pem.unarmor(end_entity_cert)
            end_entity_cert = Certificate.load(end_entity_cert)

        if validation_context is None:
            validation_context = ValidationContext()

        if not isinstance(validation_context, ValidationContext):
            raise TypeError(pretty_message(
                '''
                validation_context must be an instance of
                certvalidator.context.ValidationContext, not %s
                ''',
                type_name(validation_context)
            ))

        if intermediate_certs is not None:
            certificate_registry = validation_context.certificate_registry
            for intermediate_cert in intermediate_certs:
                certificate_registry.add_other_cert(intermediate_cert)

        self._context = validation_context
        self._certificate = end_entity_cert

    def _validate_path(self):
        """
        Builds possible certificate paths and validates them until a valid one
        is found, or all fail.

        :raises:
            certvalidator.errors.PathValidationError - when an error occurs validating the path
            certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
        """

        if self._path is not None:
            return

        exceptions = []

        if self._certificate.hash_algo in self._context.weak_hash_algos:
            raise InvalidCertificateError(pretty_message(
                '''
                The X.509 certificate provided has a signature using the weak
                hash algorithm %s
                ''',
                self._certificate.hash_algo
            ))

        try:
            paths = self._context.certificate_registry.build_paths(self._certificate)
        except (PathBuildingError):
            if self._certificate.self_signed in set(['yes', 'maybe']):
                raise InvalidCertificateError(pretty_message(
                    '''
                    The X.509 certificate provided is self-signed - "%s"
                    ''',
                    self._certificate.subject.human_friendly
                ))
            raise

        for candidate_path in paths:
            try:
                validate_path(self._context, candidate_path)
                self._path = candidate_path
                return
            except (ValidationError) as e:
                exceptions.append(e)

        if len(exceptions) == 1:
            raise exceptions[0]

        non_signature_exception = None
        for exception in exceptions:
            if 'signature' not in str_cls(exception):
                non_signature_exception = exception

        if non_signature_exception:
            raise non_signature_exception

        raise exceptions[0]

    def validate_usage(self, key_usage, extended_key_usage=None, extended_optional=False):
        """
        Validates the certificate path and that the certificate is valid for
        the key usage and extended key usage purposes specified.

        :param key_usage:
            A set of unicode strings of the required key usage purposes. Valid
            values include:

             - "digital_signature"
             - "non_repudiation"
             - "key_encipherment"
             - "data_encipherment"
             - "key_agreement"
             - "key_cert_sign"
             - "crl_sign"
             - "encipher_only"
             - "decipher_only"

        :param extended_key_usage:
            A set of unicode strings of the required extended key usage
            purposes. These must be either dotted number OIDs, or one of the
            following extended key usage purposes:

             - "server_auth"
             - "client_auth"
             - "code_signing"
             - "email_protection"
             - "ipsec_end_system"
             - "ipsec_tunnel"
             - "ipsec_user"
             - "time_stamping"
             - "ocsp_signing"
             - "wireless_access_points"

            An example of a dotted number OID:

             - "1.3.6.1.5.5.7.3.1"

        :param extended_optional:
            A bool - if the extended_key_usage extension may be ommited and still
            considered valid

        :raises:
            certvalidator.errors.PathValidationError - when an error occurs validating the path
            certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
            certvalidator.errors.InvalidCertificateError - when the certificate is not valid for the usages specified

        :return:
            A certvalidator.path.ValidationPath object of the validated
            certificate validation path
        """

        self._validate_path()
        validate_usage(
            self._context,
            self._certificate,
            key_usage,
            extended_key_usage,
            extended_optional
        )
        return self._path

    def validate_tls(self, hostname):
        """
        Validates the certificate path, that the certificate is valid for
        the hostname provided and that the certificate is valid for the purpose
        of a TLS connection.

        :param hostname:
            A unicode string of the TLS server hostname

        :raises:
            certvalidator.errors.PathValidationError - when an error occurs validating the path
            certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
            certvalidator.errors.InvalidCertificateError - when the certificate is not valid for TLS or the hostname

        :return:
            A certvalidator.path.ValidationPath object of the validated
            certificate validation path
        """

        self._validate_path()
        validate_tls_hostname(self._context, self._certificate, hostname)
        return self._path

    def validate_joint_usage(self, usages, end_entity_certs=None, require_offline=True,
                             include_trust_anchor=False, identity=None):
        """
        Validates a group of usages and selects one complete path per usage so
        that no intermediate authorization subject is shared between usages.

        Each usage is still validated with the normal path and usage
        validation logic. When a usage has more than one valid path, every
        path is retained and the combination search only fails if all path
        combinations conflict.

        :param usages:
            A list/tuple of usage requirements. Each item may be a
            certvalidator.joint.UsageRequirement object, a dict, or a
            (key_usage, extended_key_usage, extended_optional) sequence. A
            dict may include "name", "key_usage", "extended_key_usage",
            "extended_optional" and "end_entity_cert"/"end_entity_certs"
            keys. A dict mapping usage names to requirement values is also
            accepted.

        :param end_entity_certs:
            None, or a certificate/byte string/list of certificates that may
            serve as the end-entity certificate for every usage without an
            explicit end_entity_certs value. When None, the certificate passed
            to the constructor is used.

        :param require_offline:
            A bool - if the validation context must have fetching disabled

        :param include_trust_anchor:
            A bool - if trust anchors also count as intermediate authorization
            subjects. Defaults to False.

        :param identity:
            None or a callable that accepts an
            asn1crypto.x509.Certificate object and returns a hashable
            authorization-subject identifier. By default a certificate is
            identified by its subject and public key, so cross-signed copies
            of the same intermediate count as one subject.

        :raises:
            certvalidator.errors.PathValidationError - when one of the usages
            can not be validated at all, using the normal validator error

            certvalidator.errors.IndependentResponsibilityError - when every
            individual usage validates, but no path combination satisfies the
            independence constraint

        :return:
            A certvalidator.joint.JointValidationResult object
        """

        return validate_joint_usage(
            self._context,
            self._certificate,
            usages,
            end_entity_certs=end_entity_certs,
            require_offline=require_offline,
            include_trust_anchor=include_trust_anchor,
            identity=identity
        )

    def validate_joint_usages(self, usages, end_entity_certs=None, require_offline=True,
                              include_trust_anchor=False, identity=None):
        """
        Alias for validate_joint_usage()
        """

        return self.validate_joint_usage(
            usages,
            end_entity_certs=end_entity_certs,
            require_offline=require_offline,
            include_trust_anchor=include_trust_anchor,
            identity=identity
        )
