import base64
import io
import logging
import zipfile
from enum import Enum
from struct import error as struct_error
from struct import unpack
from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError

import olefile

from msoffcrypto import exceptions
from msoffcrypto.format import base
from msoffcrypto.format.common import _parse_encryptionheader, _parse_encryptionverifier
from msoffcrypto.method.ecma376_agile import ECMA376Agile
from msoffcrypto.method.ecma376_standard import ECMA376Standard

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class OOXMLDetectionReason(Enum):
    """Diagnostic reason codes describing how an input was classified.

    The codes never require decryption: they are derived solely from the
    container structure (OLE compound file vs. ZIP/OPC package) and the
    presence of well-known streams or parts.
    """

    #: OLE compound file containing an ``EncryptionInfo`` stream.
    ENCRYPTED = "encrypted"
    #: OLE compound file without an ``EncryptionInfo`` stream (e.g. legacy Office).
    OLE_NO_ENCRYPTION_INFO = "ole_no_encryption_info"
    #: OLE compound file whose structure cannot be parsed.
    OLE_CORRUPT = "ole_corrupt"
    #: ZIP/OPC package with a valid ``[Content_Types].xml`` (unencrypted OOXML).
    PLAIN_OOXML = "plain_ooxml"
    #: A ZIP archive that is not an OOXML package (no ``[Content_Types].xml``).
    ZIP_NOT_OOXML = "zip_not_ooxml"
    #: ``[Content_Types].xml`` is missing from the archive.
    MISSING_CONTENT_TYPES = "missing_content_types"
    #: ``[Content_Types].xml`` exists but cannot be parsed as XML.
    MALFORMED_CONTENT_TYPES = "malformed_content_types"
    #: ``[Content_Types].xml`` is not an OPC ``Types`` element.
    INVALID_CONTENT_TYPES = "invalid_content_types"
    #: The file claims to be a ZIP but its central directory is broken.
    ZIP_CORRUPT = "zip_corrupt"
    #: The file is neither an OLE compound file nor a ZIP archive.
    NOT_OOXML = "not_ooxml"


class OOXMLDetectionResult:
    """Outcome of a non-destructive OOXML classification attempt.

    Attributes:
        encrypted: ``True`` only when an ``EncryptionInfo`` stream is found.
        reason: Member of :class:`OOXMLDetectionReason` explaining the verdict.
    """

    __slots__ = ("encrypted", "reason")

    def __init__(self, encrypted, reason):
        self.encrypted = bool(encrypted)
        self.reason = reason

    def __bool__(self):
        return self.encrypted

    def __eq__(self, other):
        if isinstance(other, OOXMLDetectionResult):
            return self.encrypted == other.encrypted and self.reason == other.reason
        if isinstance(other, bool):
            return self.encrypted == other
        return NotImplemented

    def __repr__(self):
        return "OOXMLDetectionResult(encrypted={!r}, reason=<OOXMLDetectionReason.{}>)".format(
            self.encrypted, self.reason.name
        )


def detect_ooxml(file):
    """Classify *file* without decrypting it.

    The input is never closed and is rewound to its start on return. All
    malformed-container errors are captured in the returned
    :class:`OOXMLDetectionResult` instead of propagating as bare exceptions.

    Args:
        file: A seekable binary file-like object.

    Returns:
        OOXMLDetectionResult: ``encrypted`` is ``True`` only for OLE
        compound files carrying an ``EncryptionInfo`` stream.
    """
    file.seek(0)
    try:
        return _detect_ooxml_inner(file)
    finally:
        file.seek(0)


def _detect_ooxml_inner(file):
    if olefile.isOleFile(file):
        try:
            ole = olefile.OleFileIO(file)
        except Exception as exc:
            logger.debug("OLE container could not be parsed: %s", exc)
            return OOXMLDetectionResult(False, OOXMLDetectionReason.OLE_CORRUPT)
        try:
            if ole.exists("EncryptionInfo"):
                return OOXMLDetectionResult(True, OOXMLDetectionReason.ENCRYPTED)
            return OOXMLDetectionResult(False, OOXMLDetectionReason.OLE_NO_ENCRYPTION_INFO)
        finally:
            ole.close()

    if not zipfile.is_zipfile(file):
        return OOXMLDetectionResult(False, OOXMLDetectionReason.NOT_OOXML)

    try:
        zfile = zipfile.ZipFile(file)
        try:
            try:
                stream = zfile.open("[Content_Types].xml")
            except KeyError:
                return OOXMLDetectionResult(False, OOXMLDetectionReason.MISSING_CONTENT_TYPES)
            with stream:
                try:
                    xml = parseString(stream.read())
                except ExpatError as exc:
                    logger.debug("[Content_Types].xml is not well-formed: %s", exc)
                    return OOXMLDetectionResult(
                        False, OOXMLDetectionReason.MALFORMED_CONTENT_TYPES
                    )
        finally:
            zfile.close()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError) as exc:
        logger.debug("ZIP container could not be parsed: %s", exc)
        return OOXMLDetectionResult(False, OOXMLDetectionReason.ZIP_CORRUPT)

    # Heuristic: an OPC package starts with a Types element in the
    # package/content-types namespace.
    if (
        xml.documentElement.tagName == "Types"
        and xml.documentElement.namespaceURI
        == "http://schemas.openxmlformats.org/package/2006/content-types"
    ):
        return OOXMLDetectionResult(False, OOXMLDetectionReason.PLAIN_OOXML)
    return OOXMLDetectionResult(False, OOXMLDetectionReason.INVALID_CONTENT_TYPES)


def _is_ooxml(file):
    """Return ``True`` when *file* is an unencrypted OOXML (ZIP/OPC) package.

    Retained for backwards compatibility; prefer :func:`detect_ooxml` when a
    diagnostic reason code is needed.
    """
    result = detect_ooxml(file)
    return result.reason == OOXMLDetectionReason.PLAIN_OOXML


def _parseinfo_standard(ole):
    try:
        (headerFlags,) = unpack("<I", ole.read(4))
        (encryptionHeaderSize,) = unpack("<I", ole.read(4))
        block = ole.read(encryptionHeaderSize)
        blob = io.BytesIO(block)
        header = _parse_encryptionheader(blob)
        block = ole.read()
        blob = io.BytesIO(block)
        algIdMap = {
            0x0000660E: "AES-128",
            0x0000660F: "AES-192",
            0x00006610: "AES-256",
        }
        verifier = _parse_encryptionverifier(
            blob, "AES" if header["algId"] & 0xFF00 == 0x6600 else "RC4"
        )  # TODO: Fix
        info = {
            "header": header,
            "verifier": verifier,
        }
        return info
    except (struct_error, ValueError, KeyError, EOFError) as exc:
        raise exceptions.ParseError("Malformed standard EncryptionInfo stream: {}".format(exc))


def _parseinfo_agile(ole):
    try:
        ole.seek(8)
        xml = parseString(ole.read())
        keyDataSalt = base64.b64decode(
            xml.getElementsByTagName("keyData")[0].getAttribute("saltValue")
        )
        keyDataHashAlgorithm = xml.getElementsByTagName("keyData")[0].getAttribute(
            "hashAlgorithm"
        )
        keyDataBlockSize = int(
            xml.getElementsByTagName("keyData")[0].getAttribute("blockSize")
        )
        encryptedHmacKey = base64.b64decode(
            xml.getElementsByTagName("dataIntegrity")[0].getAttribute("encryptedHmacKey")
        )
        encryptedHmacValue = base64.b64decode(
            xml.getElementsByTagName("dataIntegrity")[0].getAttribute("encryptedHmacValue")
        )
        password_node = xml.getElementsByTagNameNS(
            "http://schemas.microsoft.com/office/2006/keyEncryptor/password", "encryptedKey"
        )[0]
        spinValue = int(password_node.getAttribute("spinCount"))
        # [MS-OFFCRYPTO] 2.3.4.10 SpinCount: An unsigned integer that specifies the number of times to iterate on a hash of a password. It MUST NOT be greater than 10,000,000.
        # https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/87020a34-e73f-4139-99bc-bbdf6cf6fa55
        if not 0 <= spinValue <= 10_000_000:
            raise exceptions.DecryptionError("Agile spinCount must be between 0 and 10000000")
        encryptedKeyValue = base64.b64decode(
            password_node.getAttribute("encryptedKeyValue")
        )
        encryptedVerifierHashInput = base64.b64decode(
            password_node.getAttribute("encryptedVerifierHashInput")
        )
        encryptedVerifierHashValue = base64.b64decode(
            password_node.getAttribute("encryptedVerifierHashValue")
        )
        passwordSalt = base64.b64decode(password_node.getAttribute("saltValue"))
        passwordHashAlgorithm = password_node.getAttribute("hashAlgorithm")
        passwordKeyBits = int(password_node.getAttribute("keyBits"))
        info = {
            "keyDataSalt": keyDataSalt,
            "keyDataHashAlgorithm": keyDataHashAlgorithm,
            "keyDataBlockSize": keyDataBlockSize,
            "encryptedHmacKey": encryptedHmacKey,
            "encryptedHmacValue": encryptedHmacValue,
            "encryptedVerifierHashInput": encryptedVerifierHashInput,
            "encryptedVerifierHashValue": encryptedVerifierHashValue,
            "encryptedKeyValue": encryptedKeyValue,
            "spinValue": spinValue,
            "passwordSalt": passwordSalt,
            "passwordHashAlgorithm": passwordHashAlgorithm,
            "passwordKeyBits": passwordKeyBits,
        }
        return info
    except (ExpatError, IndexError, ValueError, TypeError) as exc:
        raise exceptions.ParseError("Malformed agile EncryptionInfo stream: {}".format(exc))


def _parseinfo(ole):
    try:
        versionMajor, versionMinor = unpack("<HH", ole.read(4))
    except struct_error as exc:
        raise exceptions.ParseError("Truncated EncryptionInfo stream: {}".format(exc))
    if versionMajor == 4 and versionMinor == 4:  # Agile
        return "agile", _parseinfo_agile(ole)
    elif versionMajor in [2, 3, 4] and versionMinor == 2:  # Standard
        return "standard", _parseinfo_standard(ole)
    elif versionMajor in [3, 4] and versionMinor == 3:  # Extensible
        raise exceptions.DecryptionError(
            "Unsupported EncryptionInfo version (Extensible Encryption)"
        )
    raise exceptions.DecryptionError(
        "Unsupported EncryptionInfo version ({}:{})".format(versionMajor, versionMinor)
    )


class OOXMLFile(base.BaseOfficeFile):
    """Return an OOXML file object.

    Examples:
        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key(password="Password1234_", verify_password=True)

        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key(password="0000", verify_password=True)
        Traceback (most recent call last):
            ...
        msoffcrypto.exceptions.InvalidKeyError: ...
    """

    def __init__(self, file):
        self.format = "ooxml"

        file.seek(0)
        detection = detect_ooxml(file)

        if detection.encrypted:
            try:
                self.file = olefile.OleFileIO(file)
                with self.file.openstream("EncryptionInfo") as stream:
                    self.type, self.info = _parseinfo(stream)
            except exceptions.ParseError:
                raise
            except OSError:
                raise exceptions.FileFormatError(
                    "Supposed to be an encrypted OOXML file, but no EncryptionInfo stream found"
                )

            logger.debug("OOXMLFile.type: {}".format(self.type))

            self.secret_key = None

            if self.type == "agile":
                # TODO: Support aliases?
                self.keyTypes = ("password", "private_key", "secret_key")
            elif self.type == "standard":
                self.keyTypes = ("password", "secret_key")
            elif self.type == "extensible":
                pass
        elif detection.reason == OOXMLDetectionReason.PLAIN_OOXML:
            self.type = "plain"
            self.file = file
        else:
            raise exceptions.FileFormatError(
                "Unsupported file format: {}".format(detection.reason.value)
            )

        self.detection = detection

    def load_key(
        self, password=None, private_key=None, secret_key=None, verify_password=False
    ):
        """
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key("1234")
        """
        if password:
            if self.type == "agile":
                self.secret_key = ECMA376Agile.makekey_from_password(
                    password,
                    self.info["passwordSalt"],
                    self.info["passwordHashAlgorithm"],
                    self.info["encryptedKeyValue"],
                    self.info["spinValue"],
                    self.info["passwordKeyBits"],
                )
                if verify_password:
                    verified = ECMA376Agile.verify_password(
                        password,
                        self.info["passwordSalt"],
                        self.info["passwordHashAlgorithm"],
                        self.info["encryptedVerifierHashInput"],
                        self.info["encryptedVerifierHashValue"],
                        self.info["spinValue"],
                        self.info["passwordKeyBits"],
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError("Key verification failed")
            elif self.type == "standard":
                self.secret_key = ECMA376Standard.makekey_from_password(
                    password,
                    self.info["header"]["algId"],
                    self.info["header"]["algIdHash"],
                    self.info["header"]["providerType"],
                    self.info["header"]["keySize"],
                    self.info["verifier"]["saltSize"],
                    self.info["verifier"]["salt"],
                )
                if verify_password:
                    verified = ECMA376Standard.verifykey(
                        self.secret_key,
                        self.info["verifier"]["encryptedVerifier"],
                        self.info["verifier"]["encryptedVerifierHash"],
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError("Key verification failed")
            elif self.type == "extensible":
                pass
            elif self.type == "plain":
                pass
        elif private_key:
            if self.type == "agile":
                self.secret_key = ECMA376Agile.makekey_from_privkey(
                    private_key, self.info["encryptedKeyValue"]
                )
            else:
                raise exceptions.DecryptionError(
                    "Unsupported key type for the encryption method"
                )
        elif secret_key:
            self.secret_key = secret_key
        else:
            raise exceptions.DecryptionError("No key specified")

    def decrypt(self, outfile, verify_integrity=False):
        """
        >>> from msoffcrypto import exceptions
        >>> from io import BytesIO; outfile = BytesIO()
        >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.load_key("1234")
        ...     officefile.decrypt(outfile)
        Traceback (most recent call last):
        msoffcrypto.exceptions.DecryptionError: Document is not encrypted
        """
        if self.type == "agile":
            with self.file.openstream("EncryptedPackage") as stream:
                if verify_integrity:
                    verified = ECMA376Agile.verify_integrity(
                        self.secret_key,
                        self.info["keyDataSalt"],
                        self.info["keyDataHashAlgorithm"],
                        self.info["keyDataBlockSize"],
                        self.info["encryptedHmacKey"],
                        self.info["encryptedHmacValue"],
                        stream,
                    )
                    if not verified:
                        raise exceptions.InvalidKeyError(
                            "Payload integrity verification failed"
                        )

                obuf = ECMA376Agile.decrypt(
                    self.secret_key,
                    self.info["keyDataSalt"],
                    self.info["keyDataHashAlgorithm"],
                    stream,
                )
            outfile.write(obuf)
        elif self.type == "standard":
            with self.file.openstream("EncryptedPackage") as stream:
                obuf = ECMA376Standard.decrypt(self.secret_key, stream)
            outfile.write(obuf)
        elif self.type == "plain":
            raise exceptions.DecryptionError("Document is not encrypted")
        else:
            raise exceptions.DecryptionError("Unsupported encryption method")

        # If the file is successfully decrypted, there must be a valid OOXML file, i.e. a valid zip file
        if not zipfile.is_zipfile(io.BytesIO(obuf)):
            raise exceptions.InvalidKeyError(
                "The file could not be decrypted with this password"
            )

    def encrypt(self, password, outfile):
        """
        >>> from msoffcrypto.format.ooxml import OOXMLFile
        >>> from io import BytesIO; outfile = BytesIO()
        >>> with open("tests/outputs/example.docx", "rb") as f:
        ...     officefile = OOXMLFile(f)
        ...     officefile.encrypt("1234", outfile)
        """
        if self.is_encrypted():
            raise exceptions.EncryptionError("File is already encrypted")

        self.file.seek(0)

        buf = ECMA376Agile.encrypt(password, self.file)

        if not olefile.isOleFile(buf):
            raise exceptions.EncryptionError("Unable to encrypt this file")

        outfile.write(buf)

    def is_encrypted(self, with_reason=False):
        """Test whether the document is encrypted, without decrypting it.

        Args:
            with_reason: When ``False`` (the default) a plain :class:`bool`
                is returned for backwards compatibility. When ``True``, an
                :class:`OOXMLDetectionResult` is returned whose ``reason``
                attribute carries a diagnostic :class:`OOXMLDetectionReason`
                code explaining the classification.

        Examples:
            >>> with open("tests/inputs/example_password.docx", "rb") as f:
            ...     officefile = OOXMLFile(f)
            ...     officefile.is_encrypted()
            True
            >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
            ...     officefile = OOXMLFile(f)
            ...     officefile.is_encrypted()
            False
            >>> with open("tests/outputs/ecma376standard_password_plain.docx", "rb") as f:
            ...     officefile.is_encrypted(with_reason=True).reason.name
            'PLAIN_OOXML'
        """
        result = OOXMLDetectionResult(
            isinstance(self.file, olefile.OleFileIO), self.detection.reason
        )
        if with_reason:
            return result
        return result.encrypted
