from datetime import datetime
from typing import List, Optional, Sequence, Set, Type, Union

import cbor2

from pycose.algorithms import CoseAlgorithm
from pycose.exceptions import CoseInvalidCertificate
from pycose.extensions._x509_validate import (
    load_certificate,
    public_key_matches,
    validate_certificate_chain,
)
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import KeyOps

__all__ = ['X5Bag', 'X5T', 'X5U', 'X5Chain']


class X5Bag:
    def __init__(self, certificates: Union[List[bytes], bytes]):
        if isinstance(certificates, list) and len(certificates) == 1:
            self.certificates = certificates[0]
        else:
            self.certificates = certificates

    def encode(self) -> Union[bytes, List[bytes]]:
        return self.certificates


class X5T:
    @classmethod
    def from_certificate(cls, alg: Type['CoseAlg'], certificate: bytes, cbor_encoded: bool = False):
        """ Extract thumbprint from an encoded certificate. """
        if cbor_encoded:
            certificate = cbor2.loads(certificate)

        return cls(alg=alg, thumbprint=alg.compute_hash(certificate))

    @classmethod
    def decode(cls, item):
        """ Decode from a CBOR item. """

        return cls(alg=CoseAlgorithm.from_id(item[0]), thumbprint=item[1])

    def __init__(self, alg: Type['CoseAlg'], thumbprint: bytes):
        self.alg = alg
        self.thumbprint = thumbprint

    def __eq__(self, other: 'X5T'):
        return self.alg == other.alg and self.thumbprint == other.thumbprint

    def encode(self):
        """ Encode to a CBOR item. """
        return [self.alg, self.thumbprint]

    def matches(self, certificate: bytes, cbor_encoded: bool = False) -> bool:
        """ Determine if this thumbprint is for a given certificate."""

        if not self.thumbprint:
            return False

        if cbor_encoded:
            certificate = cbor2.loads(certificate)

        return self.thumbprint == self.alg.compute_hash(certificate)


class X5U:
    def __init__(self, uri: str):
        self.uri = uri

    def encode(self):
        return self.uri


class X5Chain:
    """An X.509 certificate chain as carried in a COSE ``x5chain`` header.

    The chain is a single DER-encoded certificate or an ordered list of
    DER-encoded certificates with the end-entity certificate first.
    """

    def __init__(
        self,
        cert_chain: Union[List[bytes], bytes],
        verify: bool = False,
        cose_key: Optional[CoseKey] = None,
        trust_roots: Optional[Sequence[bytes]] = None,
        key_ops: Optional[Sequence[Type[KeyOps]]] = None,
        moment: Optional[datetime] = None,
    ):
        if isinstance(cert_chain, list) and len(cert_chain) == 1:
            self.cert_chain = cert_chain[0]
        else:
            self.cert_chain = cert_chain

        if verify:
            self.validate(cose_key=cose_key, trust_roots=trust_roots,
                          key_ops=key_ops, moment=moment)

    @property
    def certificates(self) -> List[bytes]:
        """The chain as a list of DER-encoded certificates."""

        if isinstance(self.cert_chain, list):
            return self.cert_chain
        return [self.cert_chain]

    def leaf_certificate(self):
        """The parsed end-entity certificate of the chain."""

        return load_certificate(self.certificates[0])

    def public_key_matches(self, cose_key: CoseKey) -> bool:
        """Whether the leaf certificate's public key matches the CoseKey."""

        return public_key_matches(cose_key, self.leaf_certificate())

    def validate(
        self,
        cose_key: Optional[CoseKey] = None,
        trust_roots: Optional[Sequence[bytes]] = None,
        key_ops: Optional[Sequence[Type[KeyOps]]] = None,
        moment: Optional[datetime] = None,
    ) -> None:
        """Validate the chain and its binding to a CoseKey.

        Checks, in order:
          * the leaf certificate public key equals the CoseKey public key;
          * every required COSE key operation is in the CoseKey ``key_ops``
            and authorized by the leaf certificate's X.509 key usage;
          * every certificate is within its validity period;
          * each certificate is signed by the next one;
          * the chain terminates at one of the trusted roots.

        :raises CoseInvalidCertificate: on parse, binding, path or validity errors.
        :raises CoseIllegalKeyOps: when the CoseKey forbids a required key op.
        """

        if cose_key is None:
            raise CoseInvalidCertificate(
                "A CoseKey is required to validate an X.509 certificate chain."
            )

        validate_certificate_chain(
            encoded_chain=self.certificates,
            cose_key=cose_key,
            trust_roots=trust_roots,
            key_ops=key_ops,
            moment=moment,
        )

    def verify_chain(self, key_usage: Set[str]):
        """Backward-compatible path/key-usage check without a CoseKey binding.

        Prefer :meth:`validate`, which additionally binds the chain to a CoseKey.
        """

        from certvalidator import CertificateValidator

        certificates = self.certificates
        validator = CertificateValidator(
            end_entity_cert=certificates[0],
            intermediate_certs=certificates[1:],
        )
        return validator.validate_usage(key_usage)

    def encode(self) -> Union[bytes, List[bytes]]:
        return self.cert_chain
