# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Support for creating and validating SSH signatures"""


import binascii
import time

from hashlib import sha256, sha512
from pathlib import PurePath
from typing import List, Optional, Sequence, Tuple, Union, cast

from .misc import BytesOrFilePath, FilePath, OptionsParser
from .misc import open_file, read_file, match_base64, wrap_base64, parse_time
from .packet import String, UInt32, PacketDecodeError, SSHPacket
from .pattern import WildcardPatternList
from .public_key import KeyImportError, KeyPairListArg
from .public_key import SSHKey, SSHOpenSSHCertificate
from .public_key import decode_ssh_public_key, decode_ssh_certificate
from .public_key import import_public_key, load_keypairs


_SSHSIG_MAGIC = b'SSHSIG'
_SSHSIG_VERSION = 1

SSHAllowedSignersArg = Union[bytes, str, Sequence[str], 'SSHAllowedSigners']

_hashes = {b'sha256': sha256, b'sha512': sha512}


class SSHSIGError(ValueError):
    """SSHSIG validation error

       This is the base class for all errors raised while validating
       an SSHSIG signature. It is a subclass of :exc:`ValueError`.

    """


class SSHSIGParseError(SSHSIGError):
    """SSHSIG parsing error

       This exception is raised when an SSHSIG signature cannot be
       parsed, including malformed armored data, an invalid magic or
       version, an unparseable public key, an invalid namespace or
       hash algorithm, or a truncated signature blob.

    """


class SSHSIGSignatureError(SSHSIGError):
    """SSHSIG cryptographic signature error

       This exception is raised when an SSHSIG signature is well-formed
       but the cryptographic signature does not verify against the
       data being validated.

    """


class SSHSIGPolicyError(SSHSIGError):
    """SSHSIG policy rejection error

       This exception is raised when a cryptographically valid SSHSIG
       signature is rejected by the active :class:`SSHSIGPolicy`,
       including namespace, principal, hash algorithm, or validity
       period mismatches.

    """


class SSHSIGPolicy:
    """Explicit validation policy for SSHSIG signatures

       This class holds the policy used by :func:`validate_sshsig` to
       decide whether a cryptographically valid signature may be trusted.
       Every check is enabled by default and must be explicitly disabled
       by the caller; no check is skipped implicitly.

       The namespace, principal, hash algorithm, validity period, and
       signed data are all bound together by this policy so that a
       signature cannot be replayed across namespaces or principals.

       :param check_namespace: (optional)
           Whether the namespace embedded in the signature must match
           the `namespace` argument, defaulting to `True`.
       :param check_principal: (optional)
           Whether the principal argument must be a non-empty string
           and match an entry in the allowed signers list, defaulting
           to `True`.
       :param check_hash_algorithm: (optional)
           Whether the hash algorithm embedded in the signature must
           be one of the `allowed_hashes`, defaulting to `True`.
       :param check_validity: (optional)
           Whether the ``valid-after`` and ``valid-before`` options on
           the matching allowed signers entry and the validity period
           of any signing certificate are enforced, defaulting to
           `True`.
       :param check_signed_data: (optional)
           Whether the cryptographic signature over the signed data is
           verified, defaulting to `True`.
       :param namespace: (optional)
           The namespace the signature is expected to be bound to,
           defaulting to ``'file'``.
       :param allowed_hashes: (optional)
           The hash algorithm names accepted by this policy, defaulting
           to ``('sha256', 'sha512')``.

    """

    def __init__(self, *, check_namespace: bool = True,
                 check_principal: bool = True,
                 check_hash_algorithm: bool = True,
                 check_validity: bool = True,
                 check_signed_data: bool = True,
                 namespace: str = 'file',
                 allowed_hashes: Sequence[str] = ('sha256', 'sha512')):
        self.check_namespace = check_namespace
        self.check_principal = check_principal
        self.check_hash_algorithm = check_hash_algorithm
        self.check_validity = check_validity
        self.check_signed_data = check_signed_data
        self.namespace = namespace
        self.allowed_hashes = tuple(
            hash_name.encode('utf-8') for hash_name in allowed_hashes)


class SSHAllowedSignersEntry(OptionsParser):
    """An entry in an SSH allowed_senders list"""

    def __init__(self, line: str):
        super().__init__()

        try:
            principals, line = line.split(None, 1)
        except ValueError:
            raise ValueError('Missing public key in allowed_signers') from None

        self.principals = WildcardPatternList(principals)

        try:
            self.key = import_public_key(line)
            return
        except KeyImportError:
            pass

        line = self._parse_options(line)
        self.key = import_public_key(line)

    def _set_pattern(self, option: str, value: str) -> None:
        """Set an option with a wildcard pattern value"""

        self.options[option] = WildcardPatternList(value)

    def _set_time(self, option: str, value: str) -> None:
        """Set an option with a time value"""

        self.options[option] = parse_time(value)

    _handlers = {
        'namespaces':   _set_pattern,
        'valid-after':  _set_time,
        'valid-before': _set_time
    }

    def match_options(self, principal: str, namespace: str,
                      check_principal: bool = True,
                      check_validity: bool = True):
        """Match options in entry"""

        if check_principal and not self.principals.matches(principal):
            return False

        namespaces = cast(Optional[WildcardPatternList],
                          self.options.get('namespaces'))

        if namespaces is not None and not namespaces.matches(namespace):
            return False

        if check_validity:
            now = time.time()

            valid_after = cast(Optional[int], self.options.get('valid-after'))
            if valid_after is not None and now < valid_after:
                return False

            valid_before = cast(Optional[int],
                                self.options.get('valid-before'))
            if valid_before is not None and now >= valid_before:
                return False

        return True


class SSHAllowedSigners:
    """An OpenSSH-compatible allowed signers list"""

    def __init__(self, allowed_signers: Optional[str] = None):
        self._key_entries: List[SSHAllowedSignersEntry] = []
        self._cert_entries: List[SSHAllowedSignersEntry] = []

        if allowed_signers:
            self.load(allowed_signers)

    def load(self, allowed_signers: str) -> None:
        """Load allowed signers data into this object"""

        for line in allowed_signers.splitlines():
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            try:
                entry = SSHAllowedSignersEntry(line)
            except KeyImportError:
                continue

            if 'cert-authority' in entry.options:
                self._cert_entries.append(entry)
            else:
                self._key_entries.append(entry)

        if not self._key_entries and not self._cert_entries:
            raise ValueError('No valid entries found in '
                             'allowed_signers')

    def validate(self, key: SSHKey, principal: str, namespace: str,
                 ca: bool = False, check_principal: bool = True,
                 check_validity: bool = True) -> bool:
        """Return whether a public key or CA is valid for SSHSIG signing"""

        for entry in self._cert_entries if ca else self._key_entries:
            if entry.key == key and entry.match_options(
                    principal, namespace, check_principal,
                    check_validity):
                return True

        return False


def _signed_data(data: BytesOrFilePath, is_hashed: bool,
                 hash_name: bytes, namespace: str) -> bytes:
    """Return the data to be signed/verified"""

    try:
        hash_alg = _hashes[hash_name]
    except KeyError:
        raise ValueError('Unsupported hash algorithm') from None

    if not namespace:
        raise ValueError('Namespace must be a non-empty string')

    if isinstance(data, (PurePath, str)):
        h = hash_alg()

        with open_file(data, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)

        data = h.digest()
    elif not is_hashed:
        data = hash_alg(data).digest()
    elif len(data) != hash_alg().digest_size:
        raise ValueError('Incorrect hash size')

    return _SSHSIG_MAGIC + String(namespace) + String(b'') + \
           String(hash_name) + String(data)


def import_allowed_signers(data: str) -> SSHAllowedSigners:
    """Import SSH allowed signers for SSHSIG

       This function imports public keys and associated options in
       OpenSSH allowed signers format.

       :param data:
           The allowed signers data to import.
       :type data: `str`

       :returns: An :class:`SSHAllowedSigners` object

    """

    return SSHAllowedSigners(data)


def read_allowed_signers(filelist: Union[FilePath, Sequence[FilePath]]) -> \
        SSHAllowedSigners:
    """Read SSH allowed signers for SSHSIG from a file or list of files

       This function reads public keys and associated options in
       OpenSSH allowed signers format from a file or list of files.

       :param filelist:
           The file or list of files to read allowed signers from.
       :type filelist: `PurePath`, `str`, or a list of these

       :returns: An :class:`SSHAllowedSigners` object

    """

    allowed_signers = SSHAllowedSigners()

    if isinstance(filelist, (PurePath, str)):
        files: Sequence[FilePath] = [filelist]
    else:
        files = filelist

    for filename in files:
        allowed_signers.load(read_file(filename, 'r'))

    return allowed_signers


def create_sshsig(key: KeyPairListArg, data: BytesOrFilePath, *,
                  is_hashed: bool = False, hash_name: str = 'sha512',
                  namespace: str = 'file', raw: bool = False) -> bytes:
    """Create an SSHSIG signature

       This function creates and returns an SSHSIG for a block of data signed
       with the requested private key.

       :param key:
           The signing key to use. If this corresponds to multiple keys, the
           first one will be used.
       :param data:
           The data bytes to sign, or a string filename of where to read the
           data from.
       :param is_hashed: (optional)
           Whether or not hashing has already been performed on the data
           passed in. This can be useful when signing large blocks of data
           which have already had a hash calculated on them. If set to
           `True`, the `data` argument must be a byte string of the length
           required by the specified `hash_name`. This defaults to `False`,
           meaning that hashing will be performed on the data before signing.
       :param hash_name: (optional)
           The name of the hash algorithm to use. This can currently be
           `'sha256'` or `'sha512'`, defaulting to `'sha512'`.
       :param namespace: (optional)
           The namespace the hash should be created for, defaulting to
           `'file'`.
       :param raw: (optional)
           Whether to return the signature as a raw SSH blob or as a
           "armored" base64 encoded data with a PEM-style header and
           footer. This defaults to `False`, which returns the signature
           in standard "amored" format.
       :type key: *see* :ref:`SpecifyingPrivateKeys`
       :type data: `bytes` or `str`
       :type is_hashed: `bool`
       :type hash_name: `str`
       :type namespace: `str`
       :type raw: `bool`

       :returns: `bytes`

    """

    try:
        keypair = load_keypairs(key)[0]
    except IndexError:
        raise ValueError('No signing key specified') from None

    if keypair.has_x509_chain: # pragma: no cover
        raise ValueError('X.509 certificates not supported')

    hash_name = hash_name.encode('utf-8')

    if keypair.sig_algorithm == b'ssh-rsa':
        keypair.set_sig_algorithm(b'rsa-sha2-' + hash_name[-3:])

    data_to_sign = _signed_data(data, is_hashed, hash_name, namespace)

    sig = _SSHSIG_MAGIC + UInt32(_SSHSIG_VERSION) + \
          String(keypair.public_data) + String(namespace) + String(b'') + \
          String(hash_name) + String(keypair.sign(data_to_sign))

    if not raw:
        sig = wrap_base64(sig, b'SSH SIGNATURE')

    return sig


def _load_allowed_signers(
        allowed_signers: SSHAllowedSignersArg) -> SSHAllowedSigners:
    """Load an allowed signers list from the supported argument types"""

    if isinstance(allowed_signers, bytes):
        return import_allowed_signers(allowed_signers.decode())
    elif isinstance(allowed_signers, SSHAllowedSigners):
        return allowed_signers
    else:
        return read_allowed_signers(allowed_signers)


def _parse_sshsig(sig: bytes) -> \
        Tuple[SSHKey, Optional[SSHOpenSSHCertificate], str, bytes, bytes]:
    """Parse an armored or raw SSHSIG signature blob"""

    if sig[:1] == b'-':
        end = sig.find(b'\n') + 1

        if not end:
            raise SSHSIGParseError('Incomplete SSH signature header')

        line = sig[:end].rstrip()

        if line != b'-----BEGIN SSH SIGNATURE-----':
            raise SSHSIGParseError('Invalid SSH signature header')

        try:
            sig, _end = match_base64(sig[end:], 0, line)
            sig = binascii.a2b_base64(sig)
        except (ValueError, binascii.Error) as exc:
            raise SSHSIGParseError('Invalid base64 SSH signature data') \
                from exc

    try:
        packet = SSHPacket(sig)
        magic = packet.get_bytes(6)
        version = packet.get_uint32()
        pubdata = packet.get_string()
        namespace_raw = packet.get_string()
        reserved = packet.get_string()
        hash_name = packet.get_string()
        sig = packet.get_string()
        packet.check_end()
    except PacketDecodeError as exc:
        raise SSHSIGParseError('Truncated or malformed SSH signature') \
            from exc

    if magic != _SSHSIG_MAGIC or version != _SSHSIG_VERSION:
        raise SSHSIGParseError('Invalid SSHSIG magic or version')

    try:
        cert = decode_ssh_certificate(pubdata)
    except KeyImportError:
        cert = None
    else:
        if cert.is_x509: # pragma: no cover
            raise SSHSIGParseError('X.509 certificates not supported')

        cert = cast(SSHOpenSSHCertificate, cert)

    if cert is not None:
        key = cert.key
    else:
        try:
            key = decode_ssh_public_key(pubdata)
        except KeyImportError as exc:
            raise SSHSIGParseError(
                'Invalid public key in SSH signature') from exc

    try:
        namespace = namespace_raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise SSHSIGParseError(
            'Invalid namespace in SSH signature') from exc

    if not namespace:
        raise SSHSIGParseError(
            'Namespace in SSH signature must be a non-empty string')

    if reserved:
        raise SSHSIGParseError('Unexpected data in reserved field')

    if hash_name not in _hashes:
        raise SSHSIGParseError('Unsupported hash algorithm')

    return key, cert, namespace, hash_name, sig


def _validate_certificate(cert: SSHOpenSSHCertificate, principal: str,
                          check_principal: bool,
                          check_validity: bool) -> None:
    """Validate an SSH certificate against the active policy checks"""

    if check_validity:
        now = time.time()

        if now < cert._valid_after:
            raise SSHSIGPolicyError('Certificate not yet valid')

        if now >= cert._valid_before:
            raise SSHSIGPolicyError('Certificate expired')

    if check_principal and cert.principals and \
            principal not in cert.principals:
        raise SSHSIGPolicyError('Certificate principal mismatch')


def validate_sshsig(data: BytesOrFilePath, sig: BytesOrFilePath,
                    principal: str, allowed_signers: SSHAllowedSignersArg, *,
                    is_hashed: bool = False,
                    policy: Optional[SSHSIGPolicy] = None) -> bool:
    """Validate an SSHSIG signature

       This function validates an SSHSIG signature against an explicit
       :class:`SSHSIGPolicy`. The namespace embedded in the signature,
       the requested principal, the hash algorithm, the validity period,
       and the cryptographic signature over the signed data are all
       checked together. A separate check in :class:`SSHSIGPolicy` may
       be disabled by the caller, but all checks are enabled by default,
       so a signature is never accepted implicitly.

       Because the namespace is cryptographically bound to the signed
       data and is checked against the policy, a signature cannot be
       replayed in a different namespace. Likewise, the principal must
       be non-empty and must match an allowed signers entry, so a
       signature cannot be replayed for a different user unless the
       principal check is explicitly disabled.

       In the case where an SSH certificate is used to sign the block,
       the specified principal must also match the certificate
       principals and the validity period of the certificate is also
       enforced, unless the corresponding policy checks are disabled.

       The `allowed_signers` argument can be any of the following:

           * a string or list of strings containing filenames to load
             allowed signers from
           * a byte string containing allowed signer data to match against
           * an already loaded :class:`SSHAllowedSigners` object containing
             allowed signers to match against

       :param data:
           The data bytes to validate, or a string filename of where to read
           the data from.
       :param sig:
           The signature bytes to validate, or a string filename of where to
           read the signature from.
       :param principal:
           The principal to look up in the allowed signers list.
       :param allowed_signers:
           A mapping from principals to allowed public keys or certificates.
       :param is_hashed: (optional)
           Whether or not hashing has already been performed on the data
           passed in. This can be useful when signing large blocks of data
           which have already had a hash calculated on them. If set to
           `True`, the `data` argument must be a byte string of the length
           required by the specified `hash_name`. This defaults to `False`,
           meaning that hashing will be performed on the data before signing.
       :param policy: (optional)
           The :class:`SSHSIGPolicy` to enforce. This defaults to a policy
           with every check enabled and an expected namespace of
           ``'file'``.
       :type data: `PurePath`, `str`, or `bytes`
       :type sig: `PurePath`, `str`, or `bytes`
       :type principal: `str`
       :type allowed_signers: *see* :ref:`SpecifyingAllowedSigners`
       :type is_hashed: `bool`
       :type policy: :class:`SSHSIGPolicy`

       :returns: `True` if the signature is valid and satisfies the policy

       :raises SSHSIGParseError: The signature or its contents could not
           be parsed.
       :raises SSHSIGSignatureError: The cryptographic signature does not
           verify against the signed data.
       :raises SSHSIGPolicyError: A check in the active policy rejected
           the signature.

    """

    if isinstance(sig, (PurePath, str)):
        sig = read_file(sig)

    if policy is None:
        policy = SSHSIGPolicy()

    key, cert, namespace, hash_name, sig = _parse_sshsig(sig)

    try:
        data_to_verify = _signed_data(data, is_hashed, hash_name, namespace)
    except ValueError as exc:
        raise SSHSIGParseError(str(exc)) from exc

    if policy.check_signed_data and not key.verify(data_to_verify, sig):
        raise SSHSIGSignatureError(
            'SSHSIG signature does not match the signed data')

    if policy.check_namespace and namespace != policy.namespace:
        raise SSHSIGPolicyError(
            'SSHSIG namespace mismatch: expected %r, got %r' %
            (policy.namespace, namespace))

    if policy.check_hash_algorithm and \
            hash_name not in policy.allowed_hashes:
        raise SSHSIGPolicyError(
            'SSHSIG hash algorithm %r not allowed by policy' %
            hash_name.decode('utf-8'))

    if policy.check_principal and not principal:
        raise SSHSIGPolicyError(
            'SSHSIG principal must be a non-empty string')

    signers = _load_allowed_signers(allowed_signers)

    result = signers.validate(key, principal, namespace,
                              check_principal=policy.check_principal,
                              check_validity=policy.check_validity)

    if cert and not result:
        result = signers.validate(cert.signing_key, principal, namespace,
                                  ca=True,
                                  check_principal=policy.check_principal,
                                  check_validity=policy.check_validity)

        if result:
            _validate_certificate(cert, principal,
                                  policy.check_principal,
                                  policy.check_validity)

    if not result:
        raise SSHSIGPolicyError(
            'SSHSIG signer not allowed for principal %r in namespace %r' %
            (principal, namespace))

    return True
