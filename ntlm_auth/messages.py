# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import hashlib
import hmac
import os
import struct

from ntlm_auth.compute_response import ComputeResponse
from ntlm_auth.constants import AvId, AvFlags, MessageTypes, NegotiateFlags, \
    NTLM_SIGNATURE
from ntlm_auth.exceptions import MalformedMessageError
from ntlm_auth.rc4 import ARC4

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict


# The largest value that can be represented by a 32-bit unsigned integer.
_UINT32_MAX = 0xFFFFFFFF


class _BoundedCursor(object):
    """A bounded cursor over a single raw NTLM message.

    Every read is validated against the actual size of the backing buffer so
    an attacker controlled length or offset can never cause an integer wrap
    or a read past the end of the message. Payload slices additionally share
    a budget of disjoint byte ranges which makes overlapping payloads a
    deterministic error in strict mode.

    The cursor never copies payload data into an exception; error messages
    only reference the message type, field name and numeric bounds.
    """

    def __init__(self, data, message_type, strict=False):
        self.data = data
        self.message_type = message_type
        self.strict = strict
        self.message_size = len(data)
        # Each entry is the exclusive (start, end) byte range of a payload
        # field that has already been consumed from the shared message buffer.
        self._claimed_ranges = []

    def fail(self, field_name, reason, *format_args):
        if format_args:
            reason = reason % format_args
        raise MalformedMessageError(
            "Invalid NTLM message type %d: %s - %s"
            % (self.message_type, field_name, reason))

    def require_header(self, end, field_name):
        # end is exclusive. A negative end can never be <= a non-negative
        # message size, so truncated/negative inputs fail deterministically.
        if end < 0 or end > self.message_size:
            self.fail(field_name,
                      "needs %d bytes but the message is only %d bytes long",
                      end, self.message_size)

    def read_fixed(self, start, size, field_name):
        end = start + size
        self.require_header(end, field_name)
        return self.data[start:end]

    def read_uint16(self, offset, field_name):
        raw_value = self.read_fixed(offset, 2, field_name)
        return struct.unpack("<H", raw_value)[0]

    def read_uint32(self, offset, field_name):
        raw_value = self.read_fixed(offset, 4, field_name)
        return struct.unpack("<I", raw_value)[0]

    def read_security_buffer(self, fields_offset, field_name, header_end):
        """Reads a SECURITY_BUFFER (length, maximum length, offset) and the
        payload it points at, validating every bound before touching data."""
        length = self.read_uint16(fields_offset, field_name + ".length")
        declared_max_length = self.read_uint16(
            fields_offset + 2, field_name + ".maximum_length")
        buffer_offset = self.read_uint32(
            fields_offset + 4, field_name + ".buffer_offset")

        if self.strict and declared_max_length < length:
            self.fail(field_name,
                      "maximum_length %d is smaller than length %d",
                      declared_max_length, length)

        # A zero length field carries no payload. The offset is not
        # dereferenced so any value is accepted for backwards compatibility.
        if length == 0:
            return b""

        # Check the 32-bit addition explicitly so a wrap around cannot turn
        # into a small valid-looking range on any platform.
        if buffer_offset > _UINT32_MAX - length:
            self.fail(field_name,
                      "offset %d plus length %d wraps past the 32-bit limit",
                      buffer_offset, length)

        buffer_end = buffer_offset + length
        if buffer_end > self.message_size:
            self.fail(field_name,
                      "payload range [%d:%d] exceeds the message size %d",
                      buffer_offset, buffer_end, self.message_size)

        if buffer_end <= header_end:
            # Payload fields must live in the variable payload section, never
            # inside the fixed header that describes them.
            self.fail(field_name,
                      "payload range [%d:%d] overlaps the fixed header",
                      buffer_offset, buffer_end)

        new_range = (buffer_offset, buffer_end)
        for claimed_start, claimed_end in self._claimed_ranges:
            if buffer_offset < claimed_end and claimed_start < buffer_end:
                if self.strict:
                    self.fail(field_name,
                              "payload range [%d:%d] overlaps another field "
                              "[%d:%d]", buffer_offset, buffer_end,
                              claimed_start, claimed_end)

        self._claimed_ranges.append(new_range)
        return self.data[buffer_offset:buffer_end]

    def check_no_trailing_data(self, field_name, expected_end):
        if self.message_size > expected_end:
            self.fail(field_name,
                      "%d trailing byte(s) after the end of the structured "
                      "message", self.message_size - expected_end)

    def claimed_end(self):
        """Returns the furthest byte claimed by any payload field."""
        if not self._claimed_ranges:
            return 0
        return max(claimed_end for _, claimed_end in self._claimed_ranges)


def _check_message_header(cursor, expected_type):
    signature = cursor.read_fixed(0, len(NTLM_SIGNATURE), "signature")
    if signature != NTLM_SIGNATURE:
        cursor.fail("signature", "does not match the NTLMSSP signature")

    message_type = cursor.read_uint32(8, "message_type")
    if message_type != expected_type:
        cursor.fail("message_type", "expected %d but got %d",
                    expected_type, message_type)
    return message_type


class TargetInfo(object):

    def __init__(self):
        self.fields = OrderedDict()

    def __setitem__(self, key, value):
        self.fields[key] = value

    def __getitem__(self, key):
        return self.fields.get(key, None)

    def __delitem__(self, key):
        del self.fields[key]

    def pack(self):
        if AvId.MSV_AV_EOL in self.fields:
            del self[AvId.MSV_AV_EOL]

        data = b''
        for attribute_type, attribute_value in self.fields.items():
            data += struct.pack("<HH", attribute_type, len(attribute_value))
            data += attribute_value

        # end with a NTLMSSP_AV_EOL
        data += struct.pack('<HH', AvId.MSV_AV_EOL, 0)
        return data

    def unpack(self, data, strict=False):
        """Parses a sequence of AV_PAIR structures from ``data``.

        All reads go through a bounded cursor so a truncated pair, a length
        that runs past the buffer or an integer wrap produces a deterministic
        MalformedMessageError instead of platform specific struct behaviour.
        """
        cursor = _BoundedCursor(data, MessageTypes.NTLM_CHALLENGE, strict)

        offset = 0
        attribute_type = None
        while attribute_type != AvId.MSV_AV_EOL:
            if offset >= cursor.message_size:
                # Reaching the end of the buffer without an MSV_AV_EOL pair
                # is only valid for an empty AV_PAIR sequence.
                if offset == 0:
                    break
                cursor.fail("target_info",
                            "missing MSV_AV_EOL terminator at offset %d",
                            offset)
            # The bounded cursor raises deterministically if these 4 header
            # bytes or the declared value do not fit in the buffer.
            attribute_type = cursor.read_uint16(
                offset, "target_info.av_id")
            attribute_length = cursor.read_uint16(
                offset + 2, "target_info.av_length")
            value_start = offset + 4
            value_end = value_start + attribute_length
            cursor.require_header(value_end, "target_info.av_value")
            self[attribute_type] = data[value_start:value_end]
            offset = value_end

        if strict:
            cursor.check_no_trailing_data("target_info", offset)


class NegotiateMessage(object):
    EXPECTED_BODY_LENGTH = 40

    def __init__(self, negotiate_flags, domain_name, workstation):
        """
        [MS-NLMP] v28.0 2016-07-14

        2.2.1.1 NEGOTIATE_MESSAGE
        The NEGOTIATE_MESSAGE defines an NTLM Negotiate message that is sent
        from the client to the server. This message allows the client to
        specify its supported NTLM options to the server.

        :param negotiate_flags: A NEGOTIATE structure that contains a set of
            bit flags. These flags are the options the client supports
        :param domain_name: The domain name of the user to authenticate with,
            default is None
        :param workstation: The worksation of the client machine, default is
            None

        Attributes:
            signature: An 8-byte character array that MUST contain the ASCII
                string 'NTLMSSP\0'
            message_type: A 32-bit unsigned integer that indicates the message
                type. This field must be set to 0x00000001
            negotiate_flags: A NEGOTIATE structure that contains a set of bit
                flags. These flags are the options the client supports
            version: Contains the windows version info of the client. It is
                used only debugging purposes and are only set when
                NTLMSSP_NEGOTIATE_VERSION flag is set
            domain_name: A byte-array that contains the name of the client
                authentication domain that MUST Be encoded in the negotiated
                character set
            workstation: A byte-array that contains the name of the client
                machine that MUST Be encoded in the negotiated character set
        """

        self.signature = NTLM_SIGNATURE
        self.message_type = struct.pack('<L', MessageTypes.NTLM_NEGOTIATE)

        # Check if the domain_name value is set, if it is, make sure the
        # negotiate_flag is also set
        if domain_name is None:
            self.domain_name = ''
        else:
            self.domain_name = domain_name
            negotiate_flags |= \
                NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED

        # Check if the workstation value is set, if it is, make sure the
        # negotiate_flag is also set
        if workstation is None:
            self.workstation = ''
        else:
            self.workstation = workstation
            negotiate_flags |= \
                NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

        # Set the encoding flag to use UNICODE, remove OEM if set.
        negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE
        negotiate_flags &= ~NegotiateFlags.NTLMSSP_NEGOTIATE_OEM

        # The domain name and workstation are always OEM encoded.
        self.domain_name = self.domain_name.encode('ascii')
        self.workstation = self.workstation.encode('ascii')

        self.version = get_version(negotiate_flags)

        self.negotiate_flags = struct.pack('<I', negotiate_flags)

    def get_data(self):
        payload_offset = self.EXPECTED_BODY_LENGTH

        # DomainNameFields - 8 bytes
        domain_name_len = struct.pack('<H', len(self.domain_name))
        domain_name_max_len = struct.pack('<H', len(self.domain_name))
        domain_name_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.domain_name)

        # WorkstationFields - 8 bytes
        workstation_len = struct.pack('<H', len(self.workstation))
        workstation_max_len = struct.pack('<H', len(self.workstation))
        workstation_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.workstation)

        # Payload - variable length
        payload = self.domain_name
        payload += self.workstation

        # Bring the header values together into 1 message
        msg1 = self.signature
        msg1 += self.message_type
        msg1 += self.negotiate_flags
        msg1 += domain_name_len
        msg1 += domain_name_max_len
        msg1 += domain_name_buffer_offset
        msg1 += workstation_len
        msg1 += workstation_max_len
        msg1 += workstation_buffer_offset
        msg1 += self.version

        assert self.EXPECTED_BODY_LENGTH == len(msg1),\
            "BODY_LENGTH: %d != msg1: %d"\
            % (self.EXPECTED_BODY_LENGTH, len(msg1))

        # Adding the payload data to the message
        msg1 += payload
        return msg1


class ChallengeMessage(object):

    # The fixed CHALLENGE_MESSAGE header (including the TargetInfoFields).
    FIXED_HEADER_LENGTH = 48

    def __init__(self, msg2, strict=False):
        """
        [MS-NLMP] v28.0 2016-07-14

        2.2.1.2 CHALLENGE_MESSAGE
        The CHALLENGE_MESSAGE defines an NTLM challenge message that is sent
        from the server to the client. The CHALLENGE_MESSAGE is used by the
        server to challenge the client to prove its identity, For
        connection-oriented requests, the CHALLENGE_MESSAGE generated by the
        server is in response to the NEGOTIATE_MESSAGE from the client.

        :param msg2: The CHALLENGE_MESSAGE received from the server after
            sending our NEGOTIATE_MESSAGE. This has been decoded from a base64
            string
        :param strict: When True, reject messages that can be partially parsed
            but are structurally incomplete or ambiguous (overlapping payload
            slices, payloads inside the fixed header, a smaller
            maximum_length or trailing bytes). The default of False keeps the
            historical lenient behaviour while still rejecting anything that
            cannot be bounded safely.

        Attributes
            signature: An 8-byte character array that MUST contain the ASCII
                string 'NTLMSSP\0'
            message_type: A 32-bit unsigned integer that indicates the message
                type. This field must be set to 0x00000002
            negotiate_flags: A NEGOTIATE strucutre that contains a set of bit
                flags. The server sets flags to indicate options it supports
            server_challenge: A 64-bit value that contains the NTLM challenge.
                The challenge is a 64-bit nonce. Used in the
                AuthenticateMessage message
            reserved: An 8-byte array whose elements MUST be zero when sent and
                MUST be ignored on receipt
            version: When NTLMSSP_NEGOTIATE_VERSION flag is set in
                negotiate_flags field which contains the windows version info.
                Used only for debugging purposes
            target_name: When NTLMSSP_REQUEST_TARGET is set is a byte array
                that contains the name of the server authentication realm. In a
                domain environment this is the domain name not server name
            target_info: When NTLMSSP_NEGOTIATE_TARGET_INFO is set is a byte
                array that contains a sequence of AV_PAIR structures
        """

        self.data = msg2
        self.strict = strict
        # All parsing goes through one bounded cursor that shares the byte
        # budget of this message between every variable length field.
        cursor = _BoundedCursor(msg2, MessageTypes.NTLM_CHALLENGE, strict)

        # The fixed header is required before any field can be interpreted.
        cursor.require_header(self.FIXED_HEADER_LENGTH, "fixed_header")
        self.message_type = _check_message_header(
            cursor, MessageTypes.NTLM_CHALLENGE)
        self.signature = NTLM_SIGNATURE
        self.negotiate_flags = cursor.read_uint32(20, "negotiate_flags")
        self.server_challenge = cursor.read_fixed(
            24, 8, "server_challenge")
        self.reserved = cursor.read_fixed(32, 8, "reserved")

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_REQUEST_TARGET:
            self.target_name = cursor.read_security_buffer(
                12, "target_name", self.FIXED_HEADER_LENGTH)
        else:
            self.target_name = None

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO:
            target_info_raw = cursor.read_security_buffer(
                40, "target_info", self.FIXED_HEADER_LENGTH)
            self.target_info = TargetInfo()
            self.target_info.unpack(target_info_raw, strict=strict)
        else:
            self.target_info = None

        if self.negotiate_flags & \
                NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION and \
                self.negotiate_flags & \
                NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and \
                len(msg2) > self.FIXED_HEADER_LENGTH:
            self.version = struct.unpack(
                "<q", cursor.read_fixed(48, 8, "version"))[0]
        else:
            self.version = None

        if strict:
            # The structured message ends at the furthest byte claimed by a
            # payload field or the fixed header/version when no payload exists.
            expected_end = self.FIXED_HEADER_LENGTH
            if self.version is not None:
                expected_end = max(expected_end, 56)
            expected_end = max(expected_end, cursor.claimed_end())
            cursor.check_no_trailing_data("payload", expected_end)

    def get_data(self):
        return self.data


class AuthenticateMessage(object):
    EXPECTED_BODY_LENGTH = 72
    EXPECTED_BODY_LENGTH_WITH_MIC = 88

    def __init__(self, user_name, password, domain_name, workstation,
                 challenge_message, ntlm_compatibility,
                 server_certificate_hash=None, cbt_data=None):
        """
        [MS-NLMP] v28.0 2016-07-14

        2.2.1.3 AUTHENTICATE_MESSAGE
        The AUTHENTICATE_MESSAGE defines an NTLM authenticate message that is
        sent from the client to the server after the CHALLENGE_MESSAGE is
        processed by the client.

        :param user_name: The user name of the user we are trying to
            authenticate with
        :param password: The password of the user we are trying to authenticate
            with
        :param domain_name: The domain name of the user account we are
            authenticated with, default is None
        :param workstation: The workstation we are using to authenticate with,
            default is None
        :param challenge_message: A ChallengeMessage object that was received
            from the server after the negotiate_message
        :param ntlm_compatibility: The Lan Manager Compatibility Level, used to
            determine what NTLM auth version to use, see Ntlm in ntlm.py for
            more details
        :param server_certificate_hash: Deprecated, used cbt_data instead
        :param cbt_data: The GssChannelBindingsStruct that contains the CBT
            data to bind in the auth response

        Message Attributes (Attributes used to compute the message structure):
            signature: An 8-byte character array that MUST contain the ASCII
                string 'NTLMSSP\0'
            message_type: A 32-bit unsigned integer that indicates the message
                type. This field must be set to 0x00000003
            negotiate_flags: A NEGOTIATE strucutre that contains a set of bit
                flags. These flags are the choices the client has made from the
                CHALLENGE_MESSAGE options
            version: Contains the windows version info of the client. It is
                used only debugging purposes and are only set when
                NTLMSSP_NEGOTIATE_VERSION flag is set
            mic: The message integrity for the NEGOTIATE_MESSAGE,
                CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE
            lm_challenge_response: An LM_RESPONSE of LMv2_RESPONSE structure
                that contains the computed LM response to the challenge
            nt_challenge_response: An NTLM_RESPONSE or NTLMv2_RESPONSE
                structure that contains the computed NT response to the
                challenge
            domain_name: The domain or computer name hosting the user account,
                MUST be encoded in the negotiated character set
            user_name: The name of the user to be authenticated, MUST be
                encoded in the negotiated character set
            workstation: The name of the computer to which the user is logged
                on, MUST Be encoded in the negotiated character set
            encrypted_random_session_key: The client's encrypted random session
                key

        Non-Message Attributes (Attributes not used in auth message):
            exported_session_key: A randomly generated session key based on
                other keys, used to derive the SIGNKEY and SEALKEY
            target_info: The AV_PAIR structure used in the nt response
                calculation
        """
        self.signature = NTLM_SIGNATURE
        self.message_type = struct.pack('<L', MessageTypes.NTLM_AUTHENTICATE)
        self.negotiate_flags = challenge_message.negotiate_flags
        self.version = get_version(self.negotiate_flags)
        self.mic = None

        if domain_name is None:
            self.domain_name = ''
        else:
            self.domain_name = domain_name

        if workstation is None:
            self.workstation = ''
        else:
            self.workstation = workstation

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE:
            self.negotiate_flags &= ~NegotiateFlags.NTLMSSP_NEGOTIATE_OEM
            encoding_value = 'utf-16-le'
        else:
            encoding_value = 'ascii'

        self.domain_name = self.domain_name.encode(encoding_value)
        self.user_name = user_name.encode(encoding_value)
        self.workstation = self.workstation.encode(encoding_value)

        compute_response = ComputeResponse(user_name, password, domain_name,
                                           challenge_message,
                                           ntlm_compatibility)

        self.lm_challenge_response = \
            compute_response.get_lm_challenge_response()
        self.nt_challenge_response, key_exchange_key, target_info = \
            compute_response.get_nt_challenge_response(
                self.lm_challenge_response, server_certificate_hash, cbt_data)
        self.target_info = target_info

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH:
            self.exported_session_key = get_random_export_session_key()

            rc4_handle = ARC4(key_exchange_key)
            self.encrypted_random_session_key = \
                rc4_handle.update(self.exported_session_key)
        else:
            self.exported_session_key = key_exchange_key
            self.encrypted_random_session_key = b''

        self.negotiate_flags = struct.pack('<I', self.negotiate_flags)

    def get_data(self):
        if self.mic is None:
            mic = b''
            expected_body_length = self.EXPECTED_BODY_LENGTH
        else:
            mic = self.mic
            expected_body_length = self.EXPECTED_BODY_LENGTH_WITH_MIC

        payload_offset = expected_body_length

        # DomainNameFields - 8 bytes
        domain_name_len = struct.pack('<H', len(self.domain_name))
        domain_name_max_len = struct.pack('<H', len(self.domain_name))
        domain_name_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.domain_name)

        # UserNameFields - 8 bytes
        user_name_len = struct.pack('<H', len(self.user_name))
        user_name_max_len = struct.pack('<H', len(self.user_name))
        user_name_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.user_name)

        # WorkstatonFields - 8 bytes
        workstation_len = struct.pack('<H', len(self.workstation))
        workstation_max_len = struct.pack('<H', len(self.workstation))
        workstation_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.workstation)

        # LmChallengeResponseFields - 8 bytes
        lm_challenge_response_len = \
            struct.pack('<H', len(self.lm_challenge_response))
        lm_challenge_response_max_len = \
            struct.pack('<H', len(self.lm_challenge_response))
        lm_challenge_response_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.lm_challenge_response)

        # NtChallengeResponseFields - 8 bytes
        nt_challenge_response_len = \
            struct.pack('<H', len(self.nt_challenge_response))
        nt_challenge_response_max_len = \
            struct.pack('<H', len(self.nt_challenge_response))
        nt_challenge_response_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.nt_challenge_response)

        # EncryptedRandomSessionKeyFields - 8 bytes
        encrypted_random_session_key_len = \
            struct.pack('<H', len(self.encrypted_random_session_key))
        encrypted_random_session_key_max_len = \
            struct.pack('<H', len(self.encrypted_random_session_key))
        encrypted_random_session_key_buffer_offset = \
            struct.pack('<I', payload_offset)
        payload_offset += len(self.encrypted_random_session_key)

        # Payload - variable length
        payload = self.domain_name
        payload += self.user_name
        payload += self.workstation
        payload += self.lm_challenge_response
        payload += self.nt_challenge_response
        payload += self.encrypted_random_session_key

        msg3 = self.signature
        msg3 += self.message_type
        msg3 += lm_challenge_response_len
        msg3 += lm_challenge_response_max_len
        msg3 += lm_challenge_response_buffer_offset
        msg3 += nt_challenge_response_len
        msg3 += nt_challenge_response_max_len
        msg3 += nt_challenge_response_buffer_offset
        msg3 += domain_name_len
        msg3 += domain_name_max_len
        msg3 += domain_name_buffer_offset
        msg3 += user_name_len
        msg3 += user_name_max_len
        msg3 += user_name_buffer_offset
        msg3 += workstation_len
        msg3 += workstation_max_len
        msg3 += workstation_buffer_offset
        msg3 += encrypted_random_session_key_len
        msg3 += encrypted_random_session_key_max_len
        msg3 += encrypted_random_session_key_buffer_offset
        msg3 += self.negotiate_flags
        msg3 += self.version
        msg3 += mic

        # Adding the payload data to the message
        msg3 += payload

        return msg3

    def add_mic(self, negotiate_message, challenge_message):
        if self.target_info is not None:
            av_flags = self.target_info[AvId.MSV_AV_FLAGS]

            if av_flags is not None and av_flags == \
                    struct.pack("<L", AvFlags.MIC_PROVIDED):
                self.mic = struct.pack("<IIII", 0, 0, 0, 0)
                negotiate_data = negotiate_message.get_data()
                challenge_data = challenge_message.get_data()
                authenticate_data = self.get_data()

                hmac_data = negotiate_data + challenge_data + authenticate_data
                mic = hmac.new(self.exported_session_key, hmac_data,
                               digestmod=hashlib.md5).digest()
                self.mic = mic


def get_version(negotiate_flags):
    # Check the negotiate_flag version is set, if it is make sure the version
    # info is added to the data
    if negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION:
        # TODO: Get the major and minor version of Windows instead of using
        # default values
        product_major_version = struct.pack('<B', 6)
        product_minor_version = struct.pack('<B', 1)
        product_build = struct.pack('<H', 7601)
        version_reserved = b'\x00' * 3
        ntlm_revision_current = struct.pack('<B', 15)
        version = product_major_version
        version += product_minor_version
        version += product_build
        version += version_reserved
        version += ntlm_revision_current
    else:
        version = b'\x00' * 8

    return version


def get_random_export_session_key():
    return os.urandom(16)
