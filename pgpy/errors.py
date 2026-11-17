""" errors.py
"""

__all__ = ('PGPError',
           'PGPParseError',
           'PGPArmorError',
           'PGPArmorHeaderError',
           'PGPArmorCRCError',
           'PGPPacketError',
           'PGPEncryptionError',
           'PGPDecryptionError',
           'PGPIncompatibleECPointFormatError',
           'PGPOpenSSLCipherNotSupportedError',
           'PGPInsecureCipherError',
           'WontImplementError',)


class PGPError(Exception):
    """Raised as a general error in PGPy"""
    pass


class PGPParseError(PGPError):
    """
    Raised when PGP data (ASCII-armored or binary packets) cannot be parsed because it is
    truncated, spliced, or otherwise malformed.

    :param message: A description of what was expected at the point of failure.
    :param offset: The byte (or character, for armor text) offset where the problem was
                   detected, measured from the start of the input. ``None`` if the offset
                   is not applicable.
    :param partial: The object that had already been partially populated when parsing
                    failed, if any. Preserving it allows the successfully parsed packets
                    to be inspected for forensic purposes.
    """

    def __init__(self, message, offset=None, partial=None):
        if offset is not None:
            message = "{:s} (at offset {:d})".format(message, offset)

        super(PGPParseError, self).__init__(message)
        self.message = message
        self.offset = offset
        self.partial = partial


class PGPArmorError(PGPParseError, ValueError):
    """
    Raised when an ASCII-armored PGP block is malformed (missing head/tail, bad body, ...).

    Also subclasses :py:exc:`ValueError` for backwards compatibility with callers that
    relied on the previous ``ValueError`` raised by :py:meth:`Armorable.ascii_unarmor`.
    """
    pass


class PGPArmorHeaderError(PGPArmorError):
    """Raised when an ASCII-armor header or tail line is missing, truncated, or mismatched"""
    pass


class PGPArmorCRCError(PGPArmorError):
    """
    Raised when the CRC24 checksum embedded in an ASCII-armored block does not match
    the decoded body.

    :param expected: The CRC24 value carried in the armor.
    :param actual: The CRC24 value computed over the decoded body.
    """

    def __init__(self, message, offset=None, partial=None, expected=None, actual=None):
        super(PGPArmorCRCError, self).__init__(message, offset, partial)
        self.expected = expected
        self.actual = actual


class PGPPacketError(PGPParseError):
    """
    Raised when a binary OpenPGP packet cannot be parsed: its declared length runs past
    the end of the input (truncation), a field is invalid, or the packet tag is unknown.

    :param tag: The packet tag read from the packet header, if one could be read.
    """

    def __init__(self, message, offset=None, partial=None, tag=None):
        super(PGPPacketError, self).__init__(message, offset, partial)
        self.tag = tag


class PGPEncryptionError(Exception):
    """Raised when encryption fails"""
    pass


class PGPDecryptionError(Exception):
    """Raised when decryption fails"""
    pass


class PGPIncompatibleECPointFormatError(Exception):
    """Raised when the point format is incompatible with the elliptic curve"""
    pass


class PGPOpenSSLCipherNotSupportedError(Exception):
    """Raised when OpenSSL does not support the requested cipher"""
    pass


class PGPInsecureCipherError(Exception):
    """Raised when a cipher known to be insecure is attempted to be used to encrypt data"""
    pass


class WontImplementError(NotImplementedError):
    """Raised when something that is not implemented, will not be implemented"""
    pass
