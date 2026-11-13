# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import hashlib
import socket
import struct

from ntlm_auth.exceptions import ChannelBindingDigestError, \
    ChannelBindingPolicyError, ChannelBindingStructureError


# GSS-API (RFC 2744, Appendix A) address family identifiers used in the
# gss_channel_bindings_struct initiator/acceptor address type fields.
GSS_C_AF_UNSPEC = 0
GSS_C_AF_INET = 2
GSS_C_AF_INET6 = 23

# RFC 5929 channel binding type prefixes. NTLM channel binding tokens almost
# always use tls-server-end-point; tls-unique is exposed for callers that
# obtain the finished-message token from their TLS stack directly.
TLS_SERVER_END_POINT = 'tls-server-end-point'
TLS_UNIQUE = 'tls-unique'
TLS_BINDING_TYPES = frozenset([TLS_SERVER_END_POINT, TLS_UNIQUE])

# A tls-server-end-point token carries a certificate digest. Only the SHA-2
# digest sizes are accepted so a truncated/garbage value cannot be confused
# for a real certificate hash.
TLS_DIGEST_LENGTHS = frozenset([32, 48, 64])

# Informational only. The TLS version never participates in the serialized
# binding bytes; the same digest produces identical bytes on TLS 1.2 and
# TLS 1.3.
TLS_1_2 = 'TLSv1.2'
TLS_1_3 = 'TLSv1.3'
TLS_VERSIONS = frozenset([TLS_1_2, TLS_1_3])

# Trust modes for ChannelBindingPolicy:
#   LOCAL - only bindings observed on a TLS connection that terminates on
#           this host are trusted; proxy injected bindings are rejected
#   PROXY - bindings injected by a trusted reverse proxy (TLS terminator)
#           are accepted in addition to locally observed ones
#   NONE  - channel binding is explicitly disabled; any non-empty binding
#           is rejected
TRUST_MODE_LOCAL = 'local'
TRUST_MODE_PROXY = 'proxy'
TRUST_MODE_NONE = 'none'
TRUST_MODES = frozenset([
    TRUST_MODE_LOCAL, TRUST_MODE_PROXY, TRUST_MODE_NONE
])

# Length of the MD5 digest placed in the MsvAvChannelBindings AV_PAIR.
NTLM_CHANNEL_BINDING_HASH_LENGTH = 16


def _normalize_endpoint(endpoint):
    """Return ``(gss_address_type, packed_ip_bytes)`` for an endpoint.

    ``None`` maps to the GSS "unspecified" family with zero address bytes.
    IP literals are accepted as text (IPv4/IPv6, any letter case) or as
    already packed 4/16 byte strings. Text is canonicalized through
    ``socket.inet_pton`` so spelling differences (e.g. upper case IPv6 hex)
    cannot change the resulting binding bytes. Host names, ports and any
    other shape raise ``ChannelBindingStructureError``.
    """
    if endpoint is None:
        return GSS_C_AF_UNSPEC, b""

    if isinstance(endpoint, bytes):
        packed = endpoint
        if len(packed) == 4:
            return GSS_C_AF_INET, packed
        if len(packed) == 16:
            return GSS_C_AF_INET6, packed
        raise ChannelBindingStructureError(
            "Packed endpoint must be 4 bytes (IPv4) or 16 bytes (IPv6), "
            "got %d bytes" % len(packed)
        )

    if not isinstance(endpoint, str):
        raise ChannelBindingStructureError(
            "Endpoint must be an IP literal string or packed bytes, got "
            "%s" % type(endpoint).__name__
        )

    try:
        return GSS_C_AF_INET, socket.inet_pton(socket.AF_INET, endpoint)
    except socket.error:
        pass

    try:
        return GSS_C_AF_INET6, socket.inet_pton(socket.AF_INET6, endpoint)
    except socket.error:
        raise ChannelBindingStructureError(
            "Endpoint is not a valid IPv4 or IPv6 literal"
        )


class TLSChannelBinding(object):
    """Canonical, policy-aware description of a TLS channel binding.

    The object normalizes every input before serialization so that IPv4/IPv6
    spelling, IPv6 letter case, TLS version and intermediate certificate
    chain changes can never alter the produced GSS binding bytes. Only the
    leaf certificate digest (for ``tls-server-end-point``) or the raw
    application data supplied by the caller ends up in those bytes.

    Trust boundaries:
      * A normal binding is derived from the TLS connection terminating on
        this host (``injected_by_proxy=False``).
      * ``injected_by_proxy=True`` marks a binding produced by a reverse
        proxy that terminated the client TLS connection and injected the
        binding into the inner, possibly plaintext, NTLM exchange. The
        origin cannot verify the outer TLS itself and must opt in via a
        :class:`ChannelBindingPolicy` using ``TRUST_MODE_PROXY``.
      * An empty/absent certificate digest serializes the header-only GSS
        structure and provides no server identity proof; it must only be
        used when the peer does not enforce CBT or another layer secures
        the connection.

    Certificate material and raw application data are never included in
    exception messages, so failures can be logged safely.
    """

    def __init__(self, certificate_digest=None, application_data=None,
                 binding_type=TLS_SERVER_END_POINT, initiator_endpoint=None,
                 acceptor_endpoint=None, tls_version=None,
                 injected_by_proxy=False):
        if binding_type not in TLS_BINDING_TYPES:
            raise ChannelBindingStructureError(
                "Unknown TLS channel binding type: %r" % (binding_type,)
            )

        if tls_version is not None and tls_version not in TLS_VERSIONS:
            raise ChannelBindingStructureError(
                "Unknown TLS version: %r" % (tls_version,)
            )

        if application_data is not None and \
                not isinstance(application_data, bytes):
            raise ChannelBindingStructureError(
                "application_data must be a byte string"
            )

        if certificate_digest is not None and \
                not isinstance(certificate_digest, bytes):
            raise ChannelBindingStructureError(
                "certificate_digest must be a byte string"
            )

        if application_data is not None and certificate_digest:
            raise ChannelBindingStructureError(
                "application_data and certificate_digest are mutually "
                "exclusive"
            )

        if certificate_digest and binding_type != TLS_SERVER_END_POINT:
            raise ChannelBindingStructureError(
                "A certificate digest is only valid with the %s binding "
                "type; pass tls-unique tokens as application_data"
                % TLS_SERVER_END_POINT
            )

        if certificate_digest and \
                len(certificate_digest) not in TLS_DIGEST_LENGTHS:
            raise ChannelBindingDigestError(
                "Invalid tls-server-end-point digest length: %d. Allowed "
                "lengths are: %s"
                % (len(certificate_digest),
                   sorted(TLS_DIGEST_LENGTHS))
            )

        initiator_type, initiator_address = \
            _normalize_endpoint(initiator_endpoint)
        acceptor_type, acceptor_address = \
            _normalize_endpoint(acceptor_endpoint)

        if application_data is not None:
            serialized_application_data = application_data
        elif certificate_digest:
            serialized_application_data = \
                binding_type.encode('ascii') + b':' + certificate_digest
        else:
            # Empty binding mode: no application data at all. The header is
            # still serialized so the MD5 input is the well defined GSS
            # empty structure rather than an empty byte string.
            serialized_application_data = b""

        self.binding_type = binding_type
        self.tls_version = tls_version
        self.injected_by_proxy = bool(injected_by_proxy)
        self.initiator_addrtype = initiator_type
        self.initiator_address = initiator_address
        self.acceptor_addrtype = acceptor_type
        self.acceptor_address = acceptor_address
        self.application_data = serialized_application_data

    def get_gss_struct(self):
        """Return this binding as a populated GssChannelBindingsStruct."""
        gss_struct = GssChannelBindingsStruct()
        gss_struct[GssChannelBindingsStruct.INITIATOR_ADDTYPE] = \
            self.initiator_addrtype
        gss_struct[GssChannelBindingsStruct.INITIATOR_ADDRESS] = \
            self.initiator_address
        gss_struct[GssChannelBindingsStruct.ACCEPTOR_ADDRTYPE] = \
            self.acceptor_addrtype
        gss_struct[GssChannelBindingsStruct.ACCEPTOR_ADDRESS] = \
            self.acceptor_address
        gss_struct[GssChannelBindingsStruct.APPLICATION_DATA] = \
            self.application_data
        return gss_struct

    def get_data(self):
        """Return the length-prefixed GSS-API channel binding bytes."""
        return self.get_gss_struct().get_data()

    def channel_binding_hash(self):
        """Return the 16-byte MD5 of the GSS bytes used by NTLMv2."""
        return hashlib.md5(self.get_data()).digest()


def build_tls_channel_bindings(certificate_digest=None, application_data=None,
                               binding_type=TLS_SERVER_END_POINT,
                               initiator_endpoint=None,
                               acceptor_endpoint=None, tls_version=None,
                               injected_by_proxy=False):
    """Construct a :class:`TLSChannelBinding` from high level TLS inputs.

    This is the single, testable channel binding construction entry point:
    it normalizes the endpoints and binding type, validates the certificate
    digest length and serializes the GSS structure with the GSS-API length
    prefixes before any MD5 is calculated.
    """
    return TLSChannelBinding(
        certificate_digest=certificate_digest,
        application_data=application_data,
        binding_type=binding_type,
        initiator_endpoint=initiator_endpoint,
        acceptor_endpoint=acceptor_endpoint,
        tls_version=tls_version,
        injected_by_proxy=injected_by_proxy
    )


class ChannelBindingPolicy(object):
    """Enforces the trust boundary around a channel binding.

    The policy never inspects certificate or application-data contents, it
    only decides whether the *origin* of a binding is trusted. Error
    messages therefore contain no secret material.
    """

    def __init__(self, trust_mode=TRUST_MODE_LOCAL):
        if trust_mode not in TRUST_MODES:
            raise ChannelBindingStructureError(
                "Unknown channel binding trust mode: %r" % (trust_mode,)
            )
        self.trust_mode = trust_mode

    def check(self, binding):
        """Raise ``ChannelBindingPolicyError`` when ``binding`` is forbidden."""
        if binding is None:
            return

        if self.trust_mode == TRUST_MODE_NONE:
            raise ChannelBindingPolicyError(
                "Channel binding is disabled by the configured trust mode"
            )

        if getattr(binding, 'injected_by_proxy', False) and \
                self.trust_mode != TRUST_MODE_PROXY:
            raise ChannelBindingPolicyError(
                "Proxy injected channel binding rejected: the local trust "
                "mode does not trust a TLS terminator"
            )

    def allows(self, binding):
        """Return ``True`` when :meth:`check` would accept ``binding``."""
        try:
            self.check(binding)
        except ChannelBindingPolicyError:
            return False
        return True


def validate_precomputed_channel_binding_hash(channel_binding_hash):
    """Validate a caller supplied MsvAvChannelBindings value.

    A pre-computed hash bypasses GSS serialization and MD5 (typically
    because an authenticated proxy already performed them); the only check
    possible at this layer is the fixed MD5 length.
    """
    if not isinstance(channel_binding_hash, bytes):
        raise ChannelBindingStructureError(
            "Pre-computed channel binding hash must be a byte string"
        )
    if len(channel_binding_hash) != NTLM_CHANNEL_BINDING_HASH_LENGTH:
        raise ChannelBindingDigestError(
            "Pre-computed channel binding hash must be %d bytes (MD5), "
            "got %d bytes"
            % (NTLM_CHANNEL_BINDING_HASH_LENGTH,
               len(channel_binding_hash))
        )
    return channel_binding_hash


def compute_ntlm_channel_binding_hash(binding, policy=None):
    """Compute the 16-byte hash placed in MsvAvChannelBindings.

    This is the single place where the policy is enforced and the GSS
    binding bytes are MD5 hashed for NTLMv2. Both the legacy
    :class:`GssChannelBindingsStruct` and the new
    :class:`TLSChannelBinding` are accepted so existing callers keep
    producing byte identical output. Returns ``None`` when no binding is
    supplied.
    """
    if binding is None:
        return None

    if policy is not None:
        policy.check(binding)

    if isinstance(binding, TLSChannelBinding):
        return binding.channel_binding_hash()

    if isinstance(binding, GssChannelBindingsStruct):
        return hashlib.md5(binding.get_data()).digest()

    raise ChannelBindingStructureError(
        "Unsupported channel binding object: %s"
        % type(binding).__name__
    )


class GssChannelBindingsStruct(object):

    INITIATOR_ADDTYPE = 'initiator_addtype'
    INITIATOR_ADDRESS_LENGTH = 'initiator_address_length'
    ACCEPTOR_ADDRTYPE = 'acceptor_addrtype'
    ACCEPTOR_ADDRESS_LENGTH = 'acceptor_address_length'
    APPLICATION_DATA_LENGTH = 'application_data_length'
    INITIATOR_ADDRESS = 'initiator_address'
    ACCEPTOR_ADDRESS = 'acceptor_address'
    APPLICATION_DATA = 'application_data'

    def __init__(self):
        """
        Used to send the out of band channel info as part of the authentication
        process. This is used as a way of verifying the target is who it says
        it is as this information is provided by the higher layer. In most
        cases, the CBT is just the hash of the server's TLS certificate to the
        application_data field.

        This bytes string of the packed structure is then MD5 hashed and
        included in the NTv2 response.
        """
        self.fields = {
            self.INITIATOR_ADDTYPE: 0,
            self.INITIATOR_ADDRESS_LENGTH: 0,
            self.ACCEPTOR_ADDRTYPE: 0,
            self.ACCEPTOR_ADDRESS_LENGTH: 0,
            self.APPLICATION_DATA_LENGTH: 0,
            self.INITIATOR_ADDRESS: b"",
            self.ACCEPTOR_ADDRESS: b"",
            self.APPLICATION_DATA: b""
        }

    def __setitem__(self, key, value):
        self.fields[key] = value

    def __getitem__(self, key):
        return self.fields[key]

    def get_data(self):
        # Set the lengths of each len field in case they have changed
        self[self.INITIATOR_ADDRESS_LENGTH] = len(self[self.INITIATOR_ADDRESS])
        self[self.ACCEPTOR_ADDRESS_LENGTH] = len(self[self.ACCEPTOR_ADDRESS])
        self[self.APPLICATION_DATA_LENGTH] = len(self[self.APPLICATION_DATA])

        # Add all the values together to create the gss_channel_bindings_struct
        data = struct.pack("<L", self[self.INITIATOR_ADDTYPE])
        data += struct.pack("<L", self[self.INITIATOR_ADDRESS_LENGTH])
        data += self[self.INITIATOR_ADDRESS]
        data += struct.pack("<L", self[self.ACCEPTOR_ADDRTYPE])
        data += struct.pack("<L", self[self.ACCEPTOR_ADDRESS_LENGTH])
        data += self[self.ACCEPTOR_ADDRESS]
        data += struct.pack("<L", self[self.APPLICATION_DATA_LENGTH])
        data += self[self.APPLICATION_DATA]

        return data
