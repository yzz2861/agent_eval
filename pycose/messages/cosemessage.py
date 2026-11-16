import abc
from typing import Optional, TypeVar, Type, TYPE_CHECKING

import cbor2

from pycose.exceptions import CoseInvalidKey
from pycose.exceptions import CoseException
from pycose.exceptions import CoseIllegalExternalAad
from pycose.keys import CoseKey
from pycose.keys.ec2 import EC2Key
from pycose.keys.okp import OKPKey
from pycose.keys.rsa import RSAKey
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.cosebase import CoseBase

CBOR = bytes


class CoseMessage(CoseBase, metaclass=abc.ABCMeta):
    """ Parent class of all COSE message types. """

    # private dictionary to record all COSE message types dynamically
    _COSE_MSG_ID = {}

    #: Optional upper bound (in bytes) on the length of the external AAD.
    #: Set to ``None`` (the default) to disable the limit. Override on a
    #: subclass or instance to enforce a message-specific maximum length.
    MAX_EXTERNAL_AAD_LENGTH = None

    @classmethod
    def record_cbor_tag(cls, cbor_tag: int):
        """ Decorator to record all the CBOR tags dynamically. """

        def decorator(the_class):
            if not issubclass(the_class, CoseMessage):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls._COSE_MSG_ID[cbor_tag] = the_class
            return the_class

        return decorator

    @classmethod
    def decode(cls: Type['CM'], received: bytes, *args, **kwargs) -> 'CM':
        """
        Decode received COSE message based on the CBOR tag.

        If called on CoseMessage, this function can decode any supported
        message type. Otherwise, if called on a sub-class of CoseMessage,
        only messages of that type will be allowed to be decoded.

        :param received: COSE messages encoded as bytes

        :raises AttributeError: When the COSE message, it cannot be decoded properly
        :raises ValueError: The received parameter must be bytes
        :raises KeyError: thrown when the CBOR tag, identifying the COSE message is unrecognized
        :raises TypeError: thrown when the messages cannot be decoded properly
        :raises TypeError: The message's tag does not match the expected type.
        :returns: An initialized CoseMessage
        """

        try:
            cbor_msg = cbor2.loads(received)
            cbor_tag = cbor_msg.tag
            cose_obj = cbor_msg.value
        except AttributeError:
            raise AttributeError("Message was not tagged.")
        except ValueError:
            raise ValueError("Decode accepts only bytes as input.")

        if isinstance(cose_obj, list):
            try:
                decoded = cls._COSE_MSG_ID[cbor_tag].from_cose_obj(cose_obj, kwargs.get("allow_unknown_attributes", True))
            except KeyError as e:
                raise KeyError("CBOR tag is not recognized", e)

            if not isinstance(decoded, cls):
                raise TypeError(f"CBOR tag {cbor_tag} does not match the expected message type {cls.__name__}.")

            return decoded
        else:
            raise TypeError("Bytes cannot be decoded as COSE message")

    @classmethod
    def from_cose_obj(cls: Type['CM'], cose_obj: list, allow_unknown_attributes: bool) -> 'CM':
        """ Internal function that returns an initialized COSE message object. """

        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.payload = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: Optional[bytes] = None,
                 external_aad: bytes = b'',
                 key: Optional[CoseKey] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, *args, **kwargs)

        self.payload = payload
        self.external_aad = external_aad
        self.key = key

    @property
    def external_aad(self) -> bytes:
        return self._external_aad

    @property
    @abc.abstractmethod
    def cbor_tag(self):
        raise NotImplementedError()

    @external_aad.setter
    def external_aad(self, new_external_aad: bytes) -> None:
        if type(new_external_aad) is not bytes:
            raise TypeError("external_aad must be of type 'bytes'")
        if self.MAX_EXTERNAL_AAD_LENGTH is not None and len(new_external_aad) > self.MAX_EXTERNAL_AAD_LENGTH:
            raise CoseIllegalExternalAad(
                f"external_aad length ({len(new_external_aad)} B) exceeds the maximum allowed length "
                f"({self.MAX_EXTERNAL_AAD_LENGTH} B)")
        self._external_aad = new_external_aad

    def _detached_content(self,
                          detached_payload: Optional[bytes],
                          external_aad: Optional[bytes],
                          content_owner: Optional['CoseMessage'] = None,
                          empty_means_absent: bool = False):
        """
        Context manager for an explicit protect/unprotect operation.

        It (optionally) overrides the message's external AAD and selects the payload that
        participates in the authenticated structure. The original external AAD is always
        restored on exit, and the stored payload is never mutated.

        :param detached_payload: Explicit payload supplied out-of-band. Mutually exclusive
            with a payload stored on the message.
        :param external_aad: Explicit external AAD. ``None`` leaves the message's own AAD
            untouched; an explicit ``bytes`` value (including ``b''``) overrides it.
        :param content_owner: Message that owns the signed/encrypted content. Defaults to
            self; COSE_Signature objects point this at their parent message.
        :param empty_means_absent: When True, an empty bytes payload is treated as no
            attached payload (used by encryption messages that default to empty bytes).
        :raises CoseException: When neither an attached nor a detached payload is available
            or when both payload sources are provided.
        """

        return _DetachedContent(content_owner or self, detached_payload, external_aad, empty_means_absent)

    @property
    def key(self) -> CoseKey:
        return self._key

    @key.setter
    def key(self, key: Optional[CoseKey]):
        if not isinstance(key, SymmetricKey) and \
                not isinstance(key, EC2Key) and \
                not isinstance(key, OKPKey) and \
                not isinstance(key, RSAKey) and \
                key is not None:

            raise CoseInvalidKey(f"Unknown key type: {type(key)}")
        else:
            self._key = key

    @property
    def payload(self) -> Optional[bytes]:
        return self._payload

    @payload.setter
    def payload(self, new_payload: Optional[bytes]) -> None:
        if new_payload is not None and type(new_payload) is not bytes:
            raise TypeError("payload should be of type 'bytes' not {}".format(type(new_payload)))
        self._payload = new_payload  # can be plaintext or ciphertext

    @abc.abstractmethod
    def encode(self, message: list, tag: bool = True, *args, **kwargs) -> CBOR:
        if tag:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)
        else:
            message = cbor2.dumps(message, default=self._custom_cbor_encoder)

        return message

    def _base_structure(self, structure: list) -> list:
        if len(self.phdr) == 0:
            structure.append(b'')
        else:
            structure.append(self.phdr_encoded)

        structure.append(self._external_aad)

        return structure


class _DetachedContent:
    """
    Context manager backing :meth:`CoseMessage._detached_content`.

    Temporarily installs an explicit external AAD and resolves the payload that
    participates in the authenticated structure, always restoring the original
    external AAD on exit. The payload stored on the message is never mutated.
    """

    def __init__(self, msg, detached_payload, external_aad, empty_means_absent=False):
        self._msg = msg
        self._detached_payload = detached_payload
        self._external_aad = external_aad
        self._empty_means_absent = empty_means_absent
        self._original_aad = None

    def __enter__(self):
        self._original_aad = self._msg.external_aad
        if self._external_aad is not None:
            self._msg.external_aad = self._external_aad

        if self._empty_means_absent:
            # Encryption messages default to b''. An empty payload is a valid plaintext
            # unless an explicit detached payload is supplied, in which case it marks the
            # message as carrying no attached payload.
            attached = self._msg.payload
            if attached is not None and len(attached) == 0 and self._detached_payload is not None:
                attached = None
        else:
            attached = self._msg.payload

        if self._detached_payload is not None:
            if attached is not None:
                raise CoseException("Detached payload must be None when payload is set")
            return self._detached_payload

        if attached is None:
            raise CoseException("Missing payload and no detached payload provided")

        return attached

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._msg.external_aad = self._original_aad
        return False


CM = TypeVar('CM', bound=CoseMessage)
