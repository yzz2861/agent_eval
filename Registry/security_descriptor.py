"""PEP 8 alias for :mod:`Registry.SecurityDescriptor`."""
from Registry.SecurityDescriptor import *  # noqa: F401,F403
from Registry.SecurityDescriptor import (  # noqa: F401
    compare_security_descriptors,
    parse_security_descriptor,
    resolve_sid,
)
