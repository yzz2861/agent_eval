class FileFormatError(Exception):
    """Raised when the format of given file is unsupported or unrecognized."""

    pass


class ParseError(Exception):
    """Raised when the file cannot be parsed correctly."""

    pass


class DecryptionError(Exception):
    """Raised when the file cannot be decrypted."""

    pass


class EncryptionError(Exception):
    """Raised when the file cannot be encrypted."""

    pass


class InvalidKeyError(DecryptionError):
    """Raised when the given password or key is incorrect or cannot be verified."""

    pass


class EvidenceExportError(Exception):
    """Raised when a forensic evidence export cannot be completed.

    No handover receipt is issued when this is raised; an exception
    handling record is left behind instead.
    """

    pass
