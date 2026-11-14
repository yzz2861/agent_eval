# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import pem, x509
from oscrypto import trust_list

from ._errors import pretty_message
from ._types import byte_cls, type_name
from .errors import PathBuildingError, DuplicateCertificateError
from .path import ValidationPath


class CertificateRegistry():
    """
    Contains certificate lists used to build validation paths
    """

    # The maximum number of certificates allowed in a validation path. This
    # prevents pathological or malicious certificate sets from causing
    # excessive path building work.
    MAX_PATH_LENGTH = 8

    # A dict with keys being asn1crypto.x509.Certificate.Name.hashable byte
    # string. Each value is a list of asn1crypto.x509.Certificate objects.
    _subject_map = None

    # A dict with keys being asn1crypto.x509.Certificate.key_identifier byte
    # string. Each value is an asn1crypto.x509.Certificate object.
    _key_identifier_map = None

    # A dict with keys being asn1crypto.x509.Certificate.signature byte string.
    # Each value is a bool - if the certificate is a CA cert.
    _ca_lookup = None

    # A list of asn1crypto.x509.Certificate objects that are trust roots, in
    # the order they were provided
    _trust_roots = None

    # A set of asn1crypto.x509.Certificate.signature byte strings of the
    # trust roots - used to bind path building and validation to the exact
    # certificates the caller decided to trust. The signature bytes are used
    # as the identity since they are unique per certificate and, unlike
    # .sha256, do not require dumping the certificate, which can alter the
    # lazy-parsed state of BER-encoded certificates.
    _trust_root_lookup = None

    def __init__(self, trust_roots=None, extra_trust_roots=None, other_certs=None):
        """
        :param trust_roots:
            If the operating system's trust list should not be used, instead
            pass a list of byte strings containing DER or PEM-encoded X.509
            certificates, or asn1crypto.x509.Certificate objects. These
            certificates will be used as the trust roots for the path being
            built.

        :param extra_trust_roots:
            If the operating system's trust list should be used, but augmented
            with one or more extra certificates. This should be a list of byte
            strings containing DER or PEM-encoded X.509 certificates, or
            asn1crypto.x509.Certificate objects.

        :param other_certs:
            A list of byte strings containing DER or PEM-encoded X.509
            certificates, or a list of asn1crypto.x509.Certificate objects.
            These other certs are usually provided by the service/item being
            validated. In SSL, these would be intermediate chain certs.
        """

        if trust_roots is not None and not isinstance(trust_roots, list):
            raise TypeError(pretty_message(
                '''
                trust_roots must be a list of byte strings or
                asn1crypto.x509.Certificate objects, not %s
                ''',
                type_name(trust_roots)
            ))

        if extra_trust_roots is not None and not isinstance(extra_trust_roots, list):
            raise TypeError(pretty_message(
                '''
                extra_trust_roots must be a list of byte strings or
                asn1crypto.x509.Certificate objects, not %s
                ''',
                type_name(extra_trust_roots)
            ))

        if other_certs is not None and not isinstance(other_certs, list):
            raise TypeError(pretty_message(
                '''
                other_certs must be a list of byte strings or
                asn1crypto.x509.Certificate objects, not %s
                ''',
                type_name(other_certs)
            ))

        if other_certs is None:
            other_certs = []
        else:
            other_certs = self._validate_unarmor(other_certs, 'other_certs')

        if trust_roots is None:
            trust_roots = [e[0] for e in trust_list.get_list()]
        else:
            trust_roots = self._validate_unarmor(trust_roots, 'trust_roots')

        if extra_trust_roots is not None:
            trust_roots.extend(self._validate_unarmor(extra_trust_roots, 'extra_trust_roots'))

        self._subject_map = {}
        self._key_identifier_map = {}
        self._ca_lookup = {}
        self._trust_roots = []
        self._trust_root_lookup = set()

        for trust_root in trust_roots:
            hashable = trust_root.subject.hashable
            if hashable not in self._subject_map:
                self._subject_map[hashable] = []
            self._subject_map[hashable].append(trust_root)
            if trust_root.key_identifier:
                self._key_identifier_map[trust_root.key_identifier] = trust_root
            self._ca_lookup[trust_root.signature] = True
            self._trust_roots.append(trust_root)
            self._trust_root_lookup.add(trust_root.signature)

        for other_cert in other_certs:
            hashable = other_cert.subject.hashable
            if hashable not in self._subject_map:
                self._subject_map[hashable] = []
            self._subject_map[hashable].append(other_cert)
            if other_cert.key_identifier:
                self._key_identifier_map[other_cert.key_identifier] = other_cert

    def _validate_unarmor(self, certs, var_name):
        """
        Takes a list of byte strings or asn1crypto.x509.Certificates objects,
        validates and loads them while unarmoring any PEM-encoded contents

        :param certs:
            A list of byte strings or asn1crypto.x509.Certificate objects

        :param var_name:
            A unicode variable name to use in any TypeError exceptions

        :return:
            A list of asn1crypto.x509.Certificate objects
        """

        output = []
        for cert in certs:
            if isinstance(cert, x509.Certificate):
                output.append(cert)
            else:
                if not isinstance(cert, byte_cls):
                    raise TypeError(pretty_message(
                        '''
                        %s must contain only byte strings or
                        asn1crypto.x509.Certificate objects, not %s
                        ''',
                        var_name,
                        type_name(cert)
                    ))
                if pem.detect(cert):
                    _, _, cert = pem.unarmor(cert)
                output.append(x509.Certificate.load(cert))
        return output

    def is_ca(self, cert):
        """
        Checks if a certificate is in the list of CA certs in this registry

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A boolean - if the certificate is in the CA list
        """

        return self._ca_lookup.get(cert.signature, False)

    def is_trust_root(self, cert):
        """
        Checks if a certificate is one of the trust roots in this registry.
        Unlike is_ca(), this matches the exact certificate, so a cross-signed
        or same-name copy of a trust root that was supplied as an untrusted
        certificate will not be accepted.

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A boolean - if the certificate is one of the trust roots
        """

        return cert.signature in self._trust_root_lookup

    def add_other_cert(self, cert):
        """
        Allows adding an "other" cert that is obtained from doing revocation
        check via OCSP or CRL, or some other method

        :param cert:
            An asn1crypto.x509.Certificate object or a byte string of a DER or
            PEM-encoded certificate

        :return:
            A boolean indicating if the certificate was added - will return
            False if the certificate was already present
        """

        if not isinstance(cert, x509.Certificate):
            if not isinstance(cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    cert must be a byte string or an instance of
                    asn1crypto.x509.Certificate, not %s
                    ''',
                    type_name(cert)
                ))
            if pem.detect(cert):
                _, _, cert = pem.unarmor(cert)
            cert = x509.Certificate.load(cert)

        hashable = cert.subject.hashable
        if hashable not in self._subject_map:
            self._subject_map[hashable] = []

        # Don't add the cert if we already have it
        else:
            serial_number = cert.serial_number
            for existing_cert in self._subject_map[hashable]:
                if existing_cert.serial_number == serial_number:
                    return False

        self._subject_map[hashable].append(cert)
        if cert.key_identifier:
            self._key_identifier_map[cert.key_identifier] = cert
        else:
            self._key_identifier_map[cert.public_key.sha1] = cert

        return True

    def retrieve_by_key_identifier(self, key_identifier):
        """
        Retrieves a cert via its key identifier

        :param key_identifier:
            A byte string of the key identifier

        :return:
            None or an asn1crypto.x509.Certificate object
        """

        if not isinstance(key_identifier, byte_cls):
            raise TypeError(pretty_message(
                '''
                key_identifier must be a byte string, not %s
                ''',
                type_name(key_identifier)
            ))

        return self._key_identifier_map.get(key_identifier)

    def retrieve_by_name(self, name, first_certificate=None):
        """
        Retrieves a list certs via their subject name

        :param name:
            An asn1crypto.x509.Name object

        :param first_certificate:
            An asn1crypto.x509.Certificate object that if found, should be
            placed first in the result list

        :return:
            A list of asn1crypto.x509.Certificate objects
        """

        if not isinstance(name, x509.Name):
            raise TypeError(pretty_message(
                '''
                name must be an instance of asn1crypto.x509.Name, not %s
                ''',
                type_name(name)
            ))

        if first_certificate and not isinstance(first_certificate, x509.Certificate):
            raise TypeError(pretty_message(
                '''
                first_certificate must be an instance of
                asn1crypto.x509.Certificate, not %s
                ''',
                type_name(first_certificate)
            ))

        hashable = name.hashable

        if hashable not in self._subject_map:
            return []

        certs = self._subject_map[hashable]
        first = None
        output = []
        for cert in certs:
            if first_certificate and first_certificate.sha256 == cert.sha256:
                first = cert
            else:
                output.append(cert)
        if first:
            output.insert(0, first)
        return output

    def build_paths(self, end_entity_cert):
        """
        Builds a list of ValidationPath objects from a certificate in the
        operating system trust store to the end-entity certificate

        :param end_entity_cert:
            A byte string of a DER or PEM-encoded X.509 certificate, or an
            instance of asn1crypto.x509.Certificate

        :return:
            A list of certvalidator.path.ValidationPath objects that represent
            the possible paths from the end-entity certificate to one of the CA
            certs.
        """

        if not isinstance(end_entity_cert, byte_cls) and not isinstance(end_entity_cert, x509.Certificate):
            raise TypeError(pretty_message(
                '''
                end_entity_cert must be a byte string or an instance of
                asn1crypto.x509.Certificate, not %s
                ''',
                type_name(end_entity_cert)
            ))

        if isinstance(end_entity_cert, byte_cls):
            if pem.detect(end_entity_cert):
                _, _, end_entity_cert = pem.unarmor(end_entity_cert)
            end_entity_cert = x509.Certificate.load(end_entity_cert)

        path = ValidationPath(end_entity_cert)
        paths = []
        failed_paths = []

        self._walk_issuers(path, paths, failed_paths)

        if len(paths) == 0:
            cert_name = end_entity_cert.subject.human_friendly
            reasons = set(reason for _, reason in failed_paths)

            if 'length' in reasons and 'no_issuer' not in reasons:
                raise PathBuildingError(pretty_message(
                    '''
                    Unable to build a validation path for the certificate "%s"
                    - the path exceeds the maximum length of %s certificates
                    ''',
                    cert_name,
                    self.MAX_PATH_LENGTH
                ))

            if 'no_issuer' not in reasons:
                raise PathBuildingError(pretty_message(
                    '''
                    Unable to build a validation path for the certificate "%s"
                    - a certificate loop was detected
                    ''',
                    cert_name
                ))

            # Pick the deepest failed path with a missing issuer so the error
            # message points at the issuer that is actually missing
            no_issuer_failures = [fp for fp in failed_paths if fp[1] == 'no_issuer']
            no_issuer_failures.sort(
                key=lambda fp: (0 - len(fp[0]), fp[0].first.issuer.human_friendly)
            )
            missing_issuer_name = no_issuer_failures[0][0].first.issuer.human_friendly
            raise PathBuildingError(pretty_message(
                '''
                Unable to build a validation path for the certificate "%s" - no
                issuer matching "%s" was found
                ''',
                cert_name,
                missing_issuer_name
            ))

        # Order the paths so that the most preferred path is first - shorter
        # paths are preferred over cross-signed detours, and paths anchored
        # at trust roots specified earlier by the caller come first
        paths.sort(key=self._path_priority)

        return paths

    def _path_priority(self, path):
        """
        Determines the sort priority of a validation path. Paths that reach a
        trust root in fewer hops are preferred, and amongst paths of equal
        length, the trust roots are preferred in the order they were provided
        by the caller.

        :param path:
            A certvalidator.path.ValidationPath object

        :return:
            A tuple that can be used to sort paths by preference
        """

        anchor = path.first
        trust_index = len(self._trust_roots)
        for index, trust_root in enumerate(self._trust_roots):
            if trust_root.signature == anchor.signature:
                trust_index = index
                break
        return (len(path), trust_index)

    def _walk_issuers(self, path, paths, failed_paths):
        """
        Recursively looks through the list of known certificates for the issuer
        of the certificate specified, stopping once the certificate in question
        is one contained within the CA certs list

        :param path:
            A ValidationPath object representing the current traversal of
            possible paths

        :param paths:
            A list of completed ValidationPath objects. This is mutated as
            results are found.

        :param failed_paths:
            A list of tuples, each containing a certvalidator.path.ValidationPath
            object that failed before reaching a trust root, and a unicode
            string of the reason - one of "no_issuer", "loop" or "length"
        """

        # A path is only complete once it is anchored at one of the exact
        # trust roots - a cross-signed or same-name certificate supplied as
        # an untrusted certificate must not terminate a path
        if path.first.signature in self._trust_root_lookup:
            paths.append(path)
            return

        if len(path) >= self.MAX_PATH_LENGTH:
            failed_paths.append((path, 'length'))
            return

        # Track the subject name and key of every certificate already in the
        # path so that cross-signed loops (certificates with the same key and
        # subject, but signed by different CAs) are detected and rejected
        seen_keys = set()
        for path_cert in path:
            seen_keys.add((
                path_cert.subject.hashable,
                path_cert.key_identifier or path_cert.public_key.sha1
            ))

        new_branches = 0
        loop_detected = False
        for issuer in self._possible_issuers(path.first):
            issuer_key = (
                issuer.subject.hashable,
                issuer.key_identifier or issuer.public_key.sha1
            )
            if issuer_key in seen_keys:
                loop_detected = True
                continue
            try:
                self._walk_issuers(path.copy().prepend(issuer), paths, failed_paths)
                new_branches += 1
            except (DuplicateCertificateError):
                loop_detected = True

        if not new_branches:
            reason = 'loop' if loop_detected else 'no_issuer'
            failed_paths.append((path, reason))

    def _possible_issuers(self, cert):
        """
        Returns a generator that will list all possible issuers for the cert

        :param cert:
            An asn1crypto.x509.Certificate object to find the issuer of
        """

        issuer_hashable = cert.issuer.hashable
        if issuer_hashable not in self._subject_map:
            return

        candidates = self._subject_map[issuer_hashable]

        # Trust roots are preferred since they terminate a path, keeping the
        # path anchored as directly as possible. The sort is stable, so the
        # order certificates were added to the registry is otherwise kept.
        candidates = sorted(
            candidates,
            key=lambda candidate: 0 if candidate.signature in self._trust_root_lookup else 1
        )

        for issuer in candidates:
            # Info from the authority key identifier extension can be used to
            # eliminate possible options when multiple keys with the same
            # subject exist, such as during a transition, or with cross-signing.
            if cert.authority_key_identifier and issuer.key_identifier:
                if cert.authority_key_identifier != issuer.key_identifier:
                    continue
            elif cert.authority_issuer_serial:
                if cert.authority_issuer_serial != issuer.issuer_serial:
                    continue

            yield issuer
