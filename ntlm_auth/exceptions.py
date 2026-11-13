# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


class NoAuthContextError(Exception):
    pass


class ChannelBindingError(Exception):
    """Base class for every channel binding failure.

    The ``args`` of these exceptions only ever carry structural metadata
    (field names, lengths, enum values). Certificate material, raw
    application data and endpoint addresses are deliberately excluded so a
    caught exception can be logged safely without leaking the certificate or
    the binding secret.
    """
    pass


class ChannelBindingStructureError(ChannelBindingError):
    """Raised when the input shape/type is not a valid channel binding.

    Examples are a non-bytes digest, an unknown binding type, an endpoint
    that is not an IP literal or a binding that mixes mutually exclusive
    fields.
    """
    pass


class ChannelBindingDigestError(ChannelBindingError):
    """Raised when a digest or pre-computed hash has an illegal length."""
    pass


class ChannelBindingPolicyError(ChannelBindingError):
    """Raised when the configured trust mode forbids the supplied binding.

    This is intentionally distinct from the structural errors: a proxy
    injected binding that is perfectly well formed is still rejected when the
    caller only trusts bindings observed on its own TLS connection.
    """
    pass
