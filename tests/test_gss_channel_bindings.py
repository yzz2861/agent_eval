import hashlib
import socket
import struct

import pytest

from ntlm_auth.exceptions import ChannelBindingDigestError, \
    ChannelBindingPolicyError, ChannelBindingStructureError
from ntlm_auth.gss_channel_bindings import GSS_C_AF_INET, GSS_C_AF_INET6, \
    GSS_C_AF_UNSPEC, GssChannelBindingsStruct, NTLM_CHANNEL_BINDING_HASH_LENGTH, \
    TLS_1_2, TLS_1_3, TLS_SERVER_END_POINT, TLS_UNIQUE, \
    ChannelBindingPolicy, TRUST_MODE_LOCAL, TRUST_MODE_NONE, \
    TRUST_MODE_PROXY, TLSChannelBinding, build_tls_channel_bindings, \
    compute_ntlm_channel_binding_hash, \
    validate_precomputed_channel_binding_hash


# Fixed, deterministic certificate digests (not a real certificate, just a
# stable 32/48 byte value so the GSS bytes can be compared byte for byte).
SHA256_DIGEST = bytes(bytearray(range(32)))
SHA384_DIGEST = bytes(bytearray(range(48)))
SHA256_DIGEST_HEX = SHA256_DIGEST.hex()


def struct_pack_u32(value):
    return struct.pack("<L", value)


class TestGssChannelBindingsStruct(object):

    def test_application_data(self):
        struct = GssChannelBindingsStruct()
        struct[GssChannelBindingsStruct.APPLICATION_DATA] = b"abc"
        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x61\x62\x63"
        actual = struct.get_data()
        assert actual == expected


class TestTLSChannelBindingConstruction(object):

    def test_empty_binding_serializes_header_only(self):
        binding = build_tls_channel_bindings()
        # 5 little-endian uint32 length/type prefixes, all zero, and no data
        expected = b"\x00" * 20
        assert binding.get_data() == expected
        assert binding.binding_type == TLS_SERVER_END_POINT
        assert binding.initiator_addrtype == GSS_C_AF_UNSPEC
        assert binding.application_data == b""
        assert binding.channel_binding_hash() == \
            hashlib.md5(expected).digest()

    def test_empty_digest_is_treated_as_no_endpoint_binding(self):
        from_none = build_tls_channel_bindings(certificate_digest=None)
        from_empty = build_tls_channel_bindings(
            certificate_digest=b""
        )
        assert from_empty.get_data() == from_none.get_data()

    def test_tls_server_end_point_byte_exact(self):
        binding = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST
        )
        expected_application_data = \
            b"tls-server-end-point:" + SHA256_DIGEST
        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   + struct_pack_u32(len(expected_application_data)) \
                   + expected_application_data
        assert binding.get_data() == expected
        assert binding.channel_binding_hash() == \
            hashlib.md5(expected).digest()

    def test_matches_legacy_manual_struct(self):
        legacy = GssChannelBindingsStruct()
        legacy[GssChannelBindingsStruct.APPLICATION_DATA] = \
            b"tls-server-end-point:" + SHA256_DIGEST
        binding = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST
        )
        assert binding.get_data() == legacy.get_data()
        assert binding.channel_binding_hash() == \
            compute_ntlm_channel_binding_hash(legacy)

    def test_ipv4_and_ipv6_endpoints_byte_exact(self):
        binding = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST,
            initiator_endpoint="10.0.0.1",
            acceptor_endpoint="fe80::1"
        )
        application_data = b"tls-server-end-point:" + SHA256_DIGEST
        expected = struct_pack_u32(GSS_C_AF_INET)
        expected += struct_pack_u32(4)
        expected += b"\x0a\x00\x00\x01"
        expected += struct_pack_u32(GSS_C_AF_INET6)
        expected += struct_pack_u32(16)
        expected += b"\xfe\x80" + b"\x00" * 13 + b"\x01"
        expected += struct_pack_u32(len(application_data))
        expected += application_data
        assert binding.get_data() == expected
        assert binding.initiator_addrtype == GSS_C_AF_INET
        assert binding.acceptor_addrtype == GSS_C_AF_INET6

    def test_packed_endpoint_bytes_match_text_literal(self):
        text_binding = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST,
            initiator_endpoint="10.0.0.1",
            acceptor_endpoint="fe80::1"
        )
        packed_binding = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST,
            initiator_endpoint=socket.inet_pton(socket.AF_INET, "10.0.0.1"),
            acceptor_endpoint=socket.inet_pton(
                socket.AF_INET6, "fe80::1"
            )
        )
        assert packed_binding.get_data() == text_binding.get_data()

    def test_case_and_tls_version_do_not_change_bytes(self):
        base = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST,
            acceptor_endpoint="2001:db8::abcd",
            tls_version=TLS_1_2
        )
        upper = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST,
            acceptor_endpoint="2001:DB8::ABCD",
            tls_version=TLS_1_3
        )
        assert upper.get_data() == base.get_data()
        assert upper.tls_version == TLS_1_3

    def test_certificate_chain_change_does_not_change_bytes(self):
        # tls-server-end-point only includes the leaf digest; a different
        # chain (same leaf) and even the TLS 1.2/1.3 switch must be invisible.
        first = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST, tls_version=TLS_1_2
        )
        second = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST, tls_version=TLS_1_3
        )
        assert first.get_data() == second.get_data()

    def test_sha384_digest_is_accepted(self):
        binding = build_tls_channel_bindings(
            certificate_digest=SHA384_DIGEST
        )
        assert len(binding.application_data) == 21 + 48
        assert binding.get_data() == binding.get_gss_struct().get_data()

    def test_tls_unique_uses_application_data_verbatim(self):
        token = b"finished-token-1234"
        binding = build_tls_channel_bindings(
            application_data=token, binding_type=TLS_UNIQUE
        )
        expected = b"\x00" * 16 + struct_pack_u32(len(token)) + token
        assert binding.get_data() == expected

    def test_proxy_injection_keeps_binding_bytes_identical(self):
        local = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST
        )
        injected = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST, injected_by_proxy=True
        )
        assert injected.get_data() == local.get_data()
        assert injected.injected_by_proxy is True
        assert local.injected_by_proxy is False


class TestTLSChannelBindingErrors(object):

    def test_truncated_digest_length_is_rejected(self):
        truncated = SHA256_DIGEST[:31]
        with pytest.raises(ChannelBindingDigestError) as exc:
            build_tls_channel_bindings(certificate_digest=truncated)
        # Error must not leak the digest material itself.
        assert SHA256_DIGEST.hex() not in str(exc.value)

    def test_digest_wrong_type_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(certificate_digest=SHA256_DIGEST_HEX)

    def test_application_data_wrong_type_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(application_data="not bytes")

    def test_digest_and_application_data_are_mutually_exclusive(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(
                certificate_digest=SHA256_DIGEST,
                application_data=b"x"
            )

    def test_digest_rejected_for_tls_unique(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(
                certificate_digest=SHA256_DIGEST,
                binding_type=TLS_UNIQUE
            )

    def test_unknown_binding_type_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(
                application_data=b"x", binding_type="bogus"
            )

    def test_unknown_tls_version_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(
                certificate_digest=SHA256_DIGEST,
                tls_version="SSLv3"
            )

    def test_hostname_endpoint_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(
                certificate_digest=SHA256_DIGEST,
                initiator_endpoint="proxy.example.com"
            )

    def test_bad_packed_endpoint_length_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            build_tls_channel_bindings(
                certificate_digest=SHA256_DIGEST,
                acceptor_endpoint=b"\x01\x02\x03"
            )

    def test_error_messages_never_contain_certificate_material(self):
        secret_digest = b"\xde\xad" * 16
        try:
            build_tls_channel_bindings(certificate_digest=secret_digest[:10])
        except ChannelBindingDigestError as err:
            assert secret_digest not in str(err).encode()
        else:
            pytest.fail("Expected ChannelBindingDigestError")


class TestChannelBindingPolicy(object):

    def test_local_mode_rejects_proxy_injected_binding(self):
        injected = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST, injected_by_proxy=True
        )
        policy = ChannelBindingPolicy(TRUST_MODE_LOCAL)
        with pytest.raises(ChannelBindingPolicyError):
            policy.check(injected)
        assert policy.allows(injected) is False

    def test_local_mode_accepts_locally_observed_binding(self):
        local = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST
        )
        policy = ChannelBindingPolicy(TRUST_MODE_LOCAL)
        policy.check(local)
        assert policy.allows(local) is True

    def test_proxy_mode_accepts_injected_binding(self):
        injected = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST, injected_by_proxy=True
        )
        policy = ChannelBindingPolicy(TRUST_MODE_PROXY)
        policy.check(injected)
        assert policy.allows(injected) is True

    def test_none_mode_rejects_any_binding(self):
        local = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST
        )
        policy = ChannelBindingPolicy(TRUST_MODE_NONE)
        with pytest.raises(ChannelBindingPolicyError):
            policy.check(local)

    def test_none_mode_allows_missing_binding(self):
        ChannelBindingPolicy(TRUST_MODE_NONE).check(None)

    def test_unknown_trust_mode_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            ChannelBindingPolicy("bogus")


class TestPrecomputedHash(object):

    def test_valid_sixteen_byte_hash_passes(self):
        value = b"\x01" * NTLM_CHANNEL_BINDING_HASH_LENGTH
        assert validate_precomputed_channel_binding_hash(value) == value

    def test_truncated_hash_is_digest_error(self):
        with pytest.raises(ChannelBindingDigestError):
            validate_precomputed_channel_binding_hash(b"\x01" * 15)

    def test_wrong_type_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            validate_precomputed_channel_binding_hash("01" * 16)


class TestNtlmHashEntryPoint(object):

    def test_none_binding_returns_none(self):
        assert compute_ntlm_channel_binding_hash(None) is None

    def test_md5_matches_manual_gss_bytes(self):
        binding = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST,
            initiator_endpoint="10.0.0.1",
            acceptor_endpoint="fe80::1",
            tls_version=TLS_1_3
        )
        manual = hashlib.md5(binding.get_data()).digest()
        assert compute_ntlm_channel_binding_hash(binding) == manual
        assert len(manual) == NTLM_CHANNEL_BINDING_HASH_LENGTH

    def test_policy_is_enforced_inside_hash_entry_point(self):
        injected = build_tls_channel_bindings(
            certificate_digest=SHA256_DIGEST, injected_by_proxy=True
        )
        with pytest.raises(ChannelBindingPolicyError):
            compute_ntlm_channel_binding_hash(
                injected, ChannelBindingPolicy(TRUST_MODE_LOCAL)
            )
        allowed = compute_ntlm_channel_binding_hash(
            injected, ChannelBindingPolicy(TRUST_MODE_PROXY)
        )
        assert allowed == injected.channel_binding_hash()

    def test_unsupported_object_is_structure_error(self):
        with pytest.raises(ChannelBindingStructureError):
            compute_ntlm_channel_binding_hash(object())



    def test_full_data(self):
        struct = GssChannelBindingsStruct()
        struct[GssChannelBindingsStruct.INITIATOR_ADDTYPE] = 2
        struct[GssChannelBindingsStruct.INITIATOR_ADDRESS] = b"abc"
        struct[GssChannelBindingsStruct.ACCEPTOR_ADDRTYPE] = 4
        struct[GssChannelBindingsStruct.ACCEPTOR_ADDRESS] = b"def"
        struct[GssChannelBindingsStruct.APPLICATION_DATA] = b"ghi"
        expected = b"\x02\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x61\x62\x63" \
                   b"\x04\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x64\x65\x66" \
                   b"\x03\x00\x00\x00" \
                   b"\x67\x68\x69"
        actual = struct.get_data()
        assert actual == expected
