import abc
from typing import Optional, TYPE_CHECKING

import cbor2

from pycose import headers
from pycose.exceptions import CoseException
from pycose.keys.keyops import DecryptOp, EncryptOp
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.cosemessage import CoseMessage

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK


class EncCommon(CoseMessage, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def context(self) -> str:
        """ Getter for the context of the message. """

        raise NotImplementedError()

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 *args,
                 **kwargs):
        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

    def decrypt(self,
                detached_payload: Optional[bytes] = None,
                external_aad: Optional[bytes] = None,
                *args,
                **kwargs) -> bytes:
        """
        Decrypts the payload.

        :param detached_payload: The detached ciphertext. Must be provided when the message does not
            carry a payload (i.e. the payload is ``None``).
        :param external_aad: Optional external authenticated data. When given it overrides the
            message-level ``external_aad`` attribute for this operation and is checked against the
            configured length limit.

        :raises CoseException: When the key is not of type 'SymmetricKey' or neither an attached
            nor a detached payload is available.
        :returns: plaintext as bytes
        """

        with self._detached_content(detached_payload, external_aad, empty_means_absent=True) as payload:
            alg = self.get_attr(headers.Algorithm)
            nonce = self._get_nonce()

            if self.key is None:
                raise CoseException("Key cannot be None")

            self.key.verify(SymmetricKey, alg, [DecryptOp])

            return alg.decrypt(key=self.key, ciphertext=payload, aad=self._enc_structure, nonce=nonce)

    def encrypt(self,
                detached_payload: Optional[bytes] = None,
                external_aad: Optional[bytes] = None,
                *args,
                **kwargs) -> bytes:
        """
        Encrypts the payload.

        :param detached_payload: The detached plaintext. Must be provided when the message does not
            carry a payload (i.e. the payload is ``None`` or empty). When given, the message is
            encoded without a payload and the resulting ciphertext is returned to the caller for
            out-of-band transport.
        :param external_aad: Optional external authenticated data. When given it overrides the
            message-level ``external_aad`` attribute for this operation and is checked against the
            configured length limit.

        :raises CoseException: When the key is not of type 'SymmetricKey' or neither an attached
            nor a detached payload is available.
        :returns: ciphertext as bytes
        """

        # first check if key is set (since a part of the nonce can be stored in the key)
        if self.key is None:
            raise CoseException("Key cannot be None")

        with self._detached_content(detached_payload, external_aad, empty_means_absent=True) as payload:
            alg = self.get_attr(headers.Algorithm)
            nonce = self._get_nonce()

            self.key.verify(SymmetricKey, alg, [EncryptOp])

            return alg.encrypt(key=self.key, data=payload, aad=self._enc_structure, nonce=nonce)

    @property
    def _enc_structure(self) -> bytes:
        """ Build the encryption context. """

        enc_structure = [self.context]

        enc_structure = self._base_structure(enc_structure)
        aad = cbor2.dumps(enc_structure)
        return aad

    def _get_nonce(self):
        nonce = self.get_attr(headers.IV)

        if nonce is None and self.key.base_iv != b'':
            partial_iv = self.get_attr(headers.PartialIV)
            nonce = int.from_bytes(partial_iv, "big") ^ int.from_bytes(self.key.base_iv, "big")
            nonce = nonce.to_bytes((nonce.bit_length() + 7) // 8, byteorder="big")

        if nonce is None and self.key.base_iv == b'':
            raise CoseException('No IV found')

        return nonce
