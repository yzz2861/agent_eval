# ----- binary parsing exceptions -----

class CredentialsError(Exception):
    pass

class PayloadChecksumError(Exception):
    pass

class HeaderChecksumError(Exception):
    pass


# structured hardening errors (parameter bounds, stream size limits and XML
# failures) are defined alongside the parsing code; re-exported here so
# callers only need to import from pykeepass.exceptions
from .kdbx_parsing.common import (  # noqa: E402
    KDBXFormatError,
    KDBXParameterError,
    StreamLimitError,
    XMLParseError,
)

# ----- pykeepass exceptions -----

class BinaryError(Exception):
    pass

# ----- Entry exceptions -----

# ----- Group exceptions -----

# ----- RecycleBin exceptions -----

class UnableToSendToRecycleBin(Exception):
    pass
