# ----- binary parsing exceptions -----

class CredentialsError(Exception):
    pass

class PayloadChecksumError(Exception):
    pass

class HeaderChecksumError(Exception):
    pass

# ----- pykeepass exceptions -----

class BinaryError(Exception):
    pass

# ----- security / resource limit exceptions -----

class XMLSecurityError(Exception):
    """Raised when XML input contains a disallowed DTD or entity declaration.

    KeePass XML payloads never need DTDs or external entities.  Allowing them
    enables XML External Entity (XXE) attacks, so any such declaration is
    rejected.
    """
    pass

class PayloadLimitError(Exception):
    """Raised when a database exceeds a hardening limit.

    Limits cover XML node count and nesting depth, decompressed payload size
    and the number/size of attachment binaries.  They protect against
    decompression bombs and other malicious files that exhaust memory.
    """
    pass

# ----- Entry exceptions -----

# ----- Group exceptions -----

# ----- RecycleBin exceptions -----

class UnableToSendToRecycleBin(Exception):
    pass
