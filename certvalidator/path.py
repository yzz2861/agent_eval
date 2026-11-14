# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import pem, x509

from ._errors import pretty_message
from ._types import byte_cls, type_name
from .errors import DuplicateCertificateError


class ValidationPath():
    """
    Represents a path going towards an end-entity certificate
    """

    # A list of asn1crypto.x509.Certificate objects, starting with a trust root
    # and chaining to an end-entity certificate
    _certs = None

    # A set of asn1crypto.x509.Certificate.issuer_serial byte strings of
    # certificates that are already in ._certs
    _cert_hashes = None

    def __init__(self, end_entity_cert=None):
        """
        :param end_entity_cert:
            An asn1crypto.x509.Certificate object for the end-entity certificate
        """

        self._certs = []
        self._cert_hashes = set()
        if end_entity_cert:
            self.prepend(end_entity_cert)

    @property
    def first(self):
        """
        Returns the current beginning of the path - for a path to be complete,
        this certificate should be a trust root

        :return:
            The first asn1crypto.x509.Certificate object in the path
        """

        return self._certs[0]

    def find_issuer(self, cert):
        """
        Return the issuer of the cert specified, as defined by this path

        :param cert:
            An asn1crypto.x509.Certificate object to get the issuer of

        :raises:
            LookupError - when the issuer of the certificate could not be found

        :return:
            An asn1crypto.x509.Certificate object of the issuer
        """

        return self._certs[self._locate_issuer(cert)]

    def _locate_issuer(self, cert):
        """
        Determines the index of the issuer of a certificate within this path.
        When the path contains multiple certificates with the same subject
        name (such as with cross-signed or renewed roots), the authority key
        identifier and the authority key identifier issuer/serial number are
        used to disambiguate. Only certificates located before the certificate
        in the path are considered, preventing a path from being anchored to
        a different trust root than the one the path was built to.

        :param cert:
            An asn1crypto.x509.Certificate object to locate the issuer of

        :raises:
            LookupError - when the issuer could not be found, or multiple
                          issuers match and the choice is ambiguous

        :return:
            An integer index into the path
        """

        # If the cert is part of the path, its issuer must come before it -
        # this prevents a cross-signed certificate later in the path from
        # being mistaken for the issuer
        entries = self._certs
        for index, entry in enumerate(self._certs):
            if entry.issuer_serial == cert.issuer_serial:
                entries = self._certs[:index]
                break

        matches = []
        for index, entry in enumerate(entries):
            if entry.subject != cert.issuer:
                continue
            # Info from the authority key identifier extension is used to
            # eliminate options when multiple certificates share a subject
            # name, such as with cross-signing or duplicate roots
            if cert.authority_key_identifier and entry.key_identifier:
                if cert.authority_key_identifier != entry.key_identifier:
                    continue
            matches.append(index)

        if not matches:
            raise LookupError('Unable to find the issuer of the certificate specified')

        if len(matches) > 1 and cert.authority_issuer_serial:
            serial_matches = [
                index for index in matches
                if entries[index].issuer_serial == cert.authority_issuer_serial
            ]
            if len(serial_matches) == 1:
                return serial_matches[0]

        if len(matches) > 1:
            raise LookupError(pretty_message(
                '''
                Unable to determine the issuer of the certificate specified -
                the path contains multiple certificates named "%s", and the
                certificate does not contain enough information to
                disambiguate them
                ''',
                cert.issuer.human_friendly
            ))

        return matches[0]

    def truncate_to(self, cert):
        """
        Remove all certificates in the path after the cert specified

        :param cert:
            An asn1crypto.x509.Certificate object to find

        :raises:
            LookupError - when the certificate could not be found

        :return:
            The current ValidationPath object, for chaining
        """

        cert_index = None
        for index, entry in enumerate(self):
            if entry.issuer_serial == cert.issuer_serial:
                cert_index = index
                break

        if cert_index is None:
            raise LookupError('Unable to find the certificate specified')

        while len(self) > cert_index + 1:
            self.pop()

        return self

    def truncate_to_issuer(self, cert):
        """
        Remove all certificates in the path after the issuer of the cert
        specified, as defined by this path

        :param cert:
            An asn1crypto.x509.Certificate object to find the issuer of

        :raises:
            LookupError - when the issuer of the certificate could not be found

        :return:
            The current ValidationPath object, for chaining
        """

        issuer_index = self._locate_issuer(cert)

        while len(self) > issuer_index + 1:
            self.pop()

        return self

    def copy(self):
        """
        Creates a copy of this path

        :return:
            A ValidationPath object
        """

        copy = self.__class__()
        copy._certs = self._certs[:]
        copy._cert_hashes = self._cert_hashes.copy()
        return copy

    def pop(self):
        """
        Removes the last certificate from the path

        :return:
            The current ValidationPath object, for chaining
        """

        last_cert = self._certs.pop()
        self._cert_hashes.remove(last_cert.issuer_serial)

        return self

    def append(self, cert):
        """
        Appends a cert to the path. This should be a cert issued by the last
        cert in the path.

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            The current ValidationPath object, for chaining
        """

        if not isinstance(cert, x509.Certificate):
            if not isinstance(cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    cert must be a byte string or an
                    asn1crypto.x509.Certificate object, not %s
                    ''',
                    type_name(cert)
                ))
            if pem.detect(cert):
                _, _, cert = pem.unarmor(cert)
            cert = x509.Certificate.load(cert)

        if cert.issuer_serial in self._cert_hashes:
            raise DuplicateCertificateError()

        self._cert_hashes.add(cert.issuer_serial)
        self._certs.append(cert)

        return self

    def prepend(self, cert):
        """
        Prepends a cert to the path. This should be the issuer of the previously
        prepended cert.

        :param cert:
            An asn1crypto.x509.Certificate object or a byte string

        :return:
            The current ValidationPath object, for chaining
        """

        if not isinstance(cert, x509.Certificate):
            if not isinstance(cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    cert must be a byte string or an
                    asn1crypto.x509.Certificate object, not %s
                    ''',
                    type_name(cert)
                ))
            if pem.detect(cert):
                _, _, cert = pem.unarmor(cert)
            cert = x509.Certificate.load(cert)

        if cert.issuer_serial in self._cert_hashes:
            raise DuplicateCertificateError()

        self._cert_hashes.add(cert.issuer_serial)
        self._certs.insert(0, cert)

        return self

    def __len__(self):
        return len(self._certs)

    def __getitem__(self, key):
        return self._certs[key]

    def __iter__(self):
        return iter(self._certs)

    def __eq__(self, other):
        return self._certs == other._certs
