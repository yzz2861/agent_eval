#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Functions that load and write PEM-encoded files."""

import base64
import binascii
import hashlib
import typing

# Should either be ASCII strings or bytes.
FlexiText = typing.Union[str, bytes]


class PEMError(ValueError):
    """Base class for errors while decoding a PEM container.

    Messages in this module deliberately never contain the supplied PEM body,
    decoded key material, or encryption passphrases.
    """


class PEMLabelError(PEMError):
    """The requested PEM label is missing or malformed."""


class PEMBase64Error(PEMError):
    """The PEM block does not contain valid base64."""


class PEMEncodingError(PEMError):
    """The PEM input is not valid ASCII text."""


class PEMEncryptionError(PEMError):
    """Encrypted PEM metadata or its cipher parameters are invalid."""


class PEMDecryptionError(PEMError):
    """The encrypted PEM payload could not be authenticated or decrypted."""


InvalidPEMError = PEMError
PEMBase64DecodeError = PEMBase64Error


_BEGIN = b"-----BEGIN "
_END = b"-----END "
_DASHES = b"-----"


def _markers(pem_marker: FlexiText) -> typing.Tuple[bytes, bytes]:
    """Returns the start and end PEM markers, as bytes."""

    if not isinstance(pem_marker, bytes):
        try:
            pem_marker = pem_marker.encode("ascii")
        except UnicodeEncodeError:
            raise PEMEncodingError("PEM marker must contain ASCII characters only") from None

    return (
        _BEGIN + pem_marker + _DASHES,
        _END + pem_marker + _DASHES,
    )


def _as_bytes(contents: FlexiText) -> bytes:
    if isinstance(contents, bytes):
        return contents
    if not isinstance(contents, str):
        raise TypeError("PEM contents must be str or bytes")
    try:
        return contents.encode("ascii")
    except UnicodeEncodeError:
        raise PEMEncodingError("PEM contents must contain ASCII characters only") from None


def _marker_label(line: bytes, prefix: bytes) -> typing.Optional[bytes]:
    if not line.startswith(prefix) or not line.endswith(_DASHES):
        return None
    label = line[len(prefix) : -len(_DASHES)]
    if not label:
        return None
    return label


def _scan_labels(contents: bytes) -> typing.List[str]:
    labels = []
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        label = _marker_label(line, _BEGIN)
        if label is not None:
            try:
                text = label.decode("ascii")
            except UnicodeDecodeError:
                raise PEMEncodingError("PEM label must contain ASCII characters only") from None
            labels.append(text)
    return labels


def find_pem_label(
    contents: FlexiText,
    preferred: typing.Iterable[str],
) -> str:
    """Finds the first PEM label from ``preferred`` present in ``contents``.

    Labels not listed in ``preferred`` are ignored. This keeps compatibility
    with files that wrap an RSA key in another, unrelated PEM-shaped container.
    If no preferred label is present, the first other label is reported.
    """

    data = _as_bytes(contents)
    labels = _scan_labels(data)
    for label in preferred:
        if label in labels:
            return label
    if labels:
        raise PEMLabelError("Unexpected PEM label %r" % labels[0])
    raise PEMLabelError("No PEM block found")


def _read_pem_block(
    contents: bytes,
    pem_start: bytes,
    pem_end: bytes,
) -> typing.Tuple[typing.List[bytes], typing.Dict[str, str]]:
    """Reads one PEM block without retaining or reporting its body."""

    body_lines: typing.List[bytes] = []
    headers: typing.Dict[str, str] = {}
    in_pem_part = False
    seen_pem_start = False
    expected_end_label = pem_end[len(_END) : -len(_DASHES)]

    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line == pem_start:
            if in_pem_part:
                raise PEMLabelError('Seen start marker "%r" twice' % pem_start)
            in_pem_part = True
            seen_pem_start = True
            continue

        if not in_pem_part:
            continue

        end_label = _marker_label(line, _END)
        if end_label is not None:
            if end_label != expected_end_label:
                raise PEMLabelError("PEM start and end labels do not match")
            in_pem_part = False
            break

        if b":" in line and not body_lines:
            key, value = line.split(b":", 1)
            try:
                header_name = key.strip().decode("ascii")
                header_value = value.strip().decode("ascii")
            except UnicodeDecodeError:
                raise PEMEncodingError("PEM headers must contain ASCII characters only") from None
            headers[header_name] = header_value
            continue

        body_lines.append(line)

    if not seen_pem_start:
        raise PEMLabelError('No PEM start marker "%r" found' % pem_start)
    if in_pem_part:
        raise PEMLabelError('No PEM end marker "%r" found' % pem_end)
    return body_lines, headers


def _pem_lines(
    contents: bytes,
    pem_start: bytes,
    pem_end: bytes,
) -> typing.Iterator[bytes]:
    """Generator over PEM body lines between pem_start and pem_end."""

    body_lines, _ = _read_pem_block(contents, pem_start, pem_end)
    yield from body_lines


def load_pem_with_headers(
    contents: FlexiText,
    pem_marker: FlexiText,
) -> typing.Tuple[bytes, typing.Dict[str, str]]:
    """Loads a PEM block and returns its DER body and plain-text headers."""

    data = _as_bytes(contents)
    pem_start, pem_end = _markers(pem_marker)
    body_lines, headers = _read_pem_block(data, pem_start, pem_end)
    if not body_lines:
        raise PEMBase64Error("PEM block contains no base64 data")

    encoded = b"".join(body_lines)
    try:
        der = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise PEMBase64Error("PEM block contains invalid base64 data") from None
    if not der:
        raise PEMBase64Error("PEM block contains no decoded data")
    return der, headers


def load_pem(contents: FlexiText, pem_marker: FlexiText) -> bytes:
    """Loads a PEM file.

    :param contents: the contents of the file to interpret
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.

    :return: the base64-decoded content between the start and end markers.

    @raise PEMError: when the content is invalid, for example when the start
        marker cannot be found, the labels do not match, or the base64 body is
        malformed.
    """

    der, _ = load_pem_with_headers(contents, pem_marker)
    return der


def save_pem(contents: bytes, pem_marker: FlexiText) -> bytes:
    """Saves a PEM file.

    :param contents: the contents to encode in PEM format
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.

    :return: the base64-encoded content between the start and end markers, as bytes.
    """

    pem_start, pem_end = _markers(pem_marker)

    b64 = base64.standard_b64encode(contents).replace(b"\n", b"")
    pem_lines = [pem_start]

    for block_start in range(0, len(b64), 64):
        block = b64[block_start : block_start + 64]
        pem_lines.append(block)

    pem_lines.append(pem_end)
    pem_lines.append(b"")

    return b"\n".join(pem_lines)


# AES is implemented here to keep encrypted PEM loading dependency-free. Only
# the decryption direction and CBC mode are required by the PEM formats that
# this module supports.
_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_AES_INV_SBOX = [0] * 256
for _index, _value in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_value] = _index


def _aes_xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def _aes_mul(left: int, right: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        left = _aes_xtime(left)
        right >>= 1
    return result


def _aes_expand_key(key: bytes) -> typing.List[bytes]:
    if len(key) not in (16, 24, 32):
        raise PEMEncryptionError("Invalid AES key length")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[offset : offset + 4]) for offset in range(0, len(key), 4)]
    rcon = 1

    for index in range(nk, 4 * (rounds + 1)):
        temp = list(words[index - 1])
        if index % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[value] for value in temp]
            temp[0] ^= rcon
            rcon = _aes_xtime(rcon)
        elif nk > 6 and index % nk == 4:
            temp = [_AES_SBOX[value] for value in temp]
        words.append([words[index - nk][offset] ^ temp[offset] for offset in range(4)])

    return [
        bytes(sum(words[round_index * 4 : round_index * 4 + 4], []))
        for round_index in range(rounds + 1)
    ]


def _aes_add_round_key(state: typing.List[int], round_key: bytes) -> typing.List[int]:
    return [value ^ round_key[index] for index, value in enumerate(state)]


def _aes_inv_shift_rows(state: typing.List[int]) -> typing.List[int]:
    shifted = [0] * 16
    for column in range(4):
        for row in range(4):
            shifted[4 * column + row] = state[4 * ((column - row) % 4) + row]
    return shifted


def _aes_inv_sub_bytes(state: typing.List[int]) -> typing.List[int]:
    return [_AES_INV_SBOX[value] for value in state]


def _aes_inv_mix_columns(state: typing.List[int]) -> typing.List[int]:
    mixed = [0] * 16
    for column in range(4):
        offset = 4 * column
        a0, a1, a2, a3 = state[offset : offset + 4]
        mixed[offset + 0] = (
            _aes_mul(a0, 14) ^ _aes_mul(a1, 11) ^ _aes_mul(a2, 13) ^ _aes_mul(a3, 9)
        )
        mixed[offset + 1] = (
            _aes_mul(a0, 9) ^ _aes_mul(a1, 14) ^ _aes_mul(a2, 11) ^ _aes_mul(a3, 13)
        )
        mixed[offset + 2] = (
            _aes_mul(a0, 13) ^ _aes_mul(a1, 9) ^ _aes_mul(a2, 14) ^ _aes_mul(a3, 11)
        )
        mixed[offset + 3] = (
            _aes_mul(a0, 11) ^ _aes_mul(a1, 13) ^ _aes_mul(a2, 9) ^ _aes_mul(a3, 14)
        )
    return mixed


def _aes_decrypt_block(block: bytes, round_keys: typing.List[bytes]) -> bytes:
    state = list(block)
    state = _aes_add_round_key(state, round_keys[-1])
    for round_index in range(len(round_keys) - 2, 0, -1):
        state = _aes_inv_shift_rows(state)
        state = _aes_inv_sub_bytes(state)
        state = _aes_add_round_key(state, round_keys[round_index])
        state = _aes_inv_mix_columns(state)
    state = _aes_inv_shift_rows(state)
    state = _aes_inv_sub_bytes(state)
    state = _aes_add_round_key(state, round_keys[0])
    return bytes(state)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != 16:
        raise PEMEncryptionError("Invalid AES IV length")
    if not ciphertext or len(ciphertext) % 16:
        raise PEMDecryptionError("Encrypted payload has an invalid length")

    round_keys = _aes_expand_key(key)
    plaintext = bytearray()
    previous = iv
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset : offset + 16]
        plaintext.extend(_xor_bytes(_aes_decrypt_block(block, round_keys), previous))
        previous = block
    return bytes(plaintext)


_DES_PC1 = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)

_DES_PC2 = (
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
)

_DES_IP = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
)

_DES_FP = (
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
)

_DES_E = (
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
)

_DES_P = (
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
)

_DES_SBOX = (
    (
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ),
    (
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ),
    (
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ),
    (
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ),
    (
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ),
    (
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ),
    (
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ),
    (
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ),
)

_DES_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)


def _des_permute(value: int, table: typing.Iterable[int], input_bits: int) -> int:
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (input_bits - position)) & 1)
    return result


def _des_subkeys(key: bytes) -> typing.List[int]:
    if len(key) != 8:
        raise PEMEncryptionError("Invalid DES key length")
    permuted = _des_permute(int.from_bytes(key, "big"), _DES_PC1, 64)
    left = permuted >> 28
    right = permuted & 0x0FFFFFFF
    subkeys = []
    for shift in _DES_SHIFTS:
        left = ((left << shift) | (left >> (28 - shift))) & 0x0FFFFFFF
        right = ((right << shift) | (right >> (28 - shift))) & 0x0FFFFFFF
        subkeys.append(_des_permute((left << 28) | right, _DES_PC2, 56))
    return subkeys


def _des_feistel(right: int, subkey: int) -> int:
    expanded = _des_permute(right, _DES_E, 32) ^ subkey
    combined = 0
    for index in range(8):
        six_bits = (expanded >> (42 - 6 * index)) & 0x3F
        row = ((six_bits & 0x20) >> 4) | (six_bits & 1)
        column = (six_bits >> 1) & 0x0F
        combined = (combined << 4) | _DES_SBOX[index][row * 16 + column]
    return _des_permute(combined, _DES_P, 32)


def _des_crypt_block(block: bytes, key: bytes, decrypt: bool) -> bytes:
    if len(block) != 8:
        raise PEMDecryptionError("Invalid DES block length")
    permuted = _des_permute(int.from_bytes(block, "big"), _DES_IP, 64)
    left = permuted >> 32
    right = permuted & 0xFFFFFFFF
    subkeys = _des_subkeys(key)
    if decrypt:
        subkeys.reverse()
    for subkey in subkeys:
        left, right = right, left ^ _des_feistel(right, subkey)
    result = (right << 32) | left
    return _des_permute(result, _DES_FP, 64).to_bytes(8, "big")


def _des3_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(key) == 24:
        key1, key2, key3 = key[:8], key[8:16], key[16:]
    elif len(key) == 16:
        key1, key2, key3 = key[:8], key[8:], key[:8]
    else:
        raise PEMEncryptionError("Invalid 3DES key length")
    block = _des_crypt_block(block, key3, True)
    block = _des_crypt_block(block, key2, False)
    return _des_crypt_block(block, key1, True)


def _cbc_decrypt(
    algorithm: str,
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    if algorithm.startswith("AES-"):
        return _aes_cbc_decrypt(key, iv, ciphertext)

    block_size = 8
    if len(iv) != block_size:
        raise PEMEncryptionError("Invalid DES IV length")
    if not ciphertext or len(ciphertext) % block_size:
        raise PEMDecryptionError("Encrypted payload has an invalid length")

    plaintext = bytearray()
    previous = iv
    for offset in range(0, len(ciphertext), block_size):
        block = ciphertext[offset : offset + block_size]
        if algorithm == "DES-CBC":
            decrypted = _des_crypt_block(block, key, True)
        elif algorithm == "DES-EDE3-CBC":
            decrypted = _des3_decrypt_block(block, key)
        else:
            raise PEMEncryptionError("Unsupported encrypted PEM cipher")
        plaintext.extend(_xor_bytes(decrypted, previous))
        previous = block
    return bytes(plaintext)


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data:
        raise PEMDecryptionError("Decrypted PEM payload is empty")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise PEMDecryptionError("Invalid encrypted PEM padding")
    return data[:-padding]


def _evp_bytes_to_key(password: bytes, salt: bytes, key_length: int) -> bytes:
    material = b""
    previous = b""
    while len(material) < key_length:
        previous = hashlib.md5(previous + password + salt).digest()
        material += previous
    return material[:key_length]


def decrypt_openssl_pem(
    encrypted_data: bytes,
    headers: typing.Mapping[str, str],
    passphrase: bytes,
) -> bytes:
    """Decrypts a traditional OpenSSL encrypted PEM body.

    This accepts the AES and DES/3DES CBC algorithms used by OpenSSL's
    ``Proc-Type: 4,ENCRYPTED`` PEM format.
    """

    normalized = {key.lower(): value for key, value in headers.items()}
    proc_type = normalized.get("proc-type", "").replace(" ", "").upper()
    if proc_type != "4,ENCRYPTED":
        raise PEMEncryptionError("PEM block is not marked as encrypted")

    dek_info = normalized.get("dek-info")
    if not dek_info or "," not in dek_info:
        raise PEMEncryptionError("Encrypted PEM is missing DEK-Info")
    algorithm, iv_hex = [part.strip() for part in dek_info.split(",", 1)]
    algorithm = algorithm.upper()

    cipher_lengths = {
        "AES-128-CBC": (16, 16),
        "AES-192-CBC": (24, 16),
        "AES-256-CBC": (32, 16),
        "DES-CBC": (8, 8),
        "DES-EDE3-CBC": (24, 8),
    }
    if algorithm not in cipher_lengths:
        raise PEMEncryptionError("Unsupported encrypted PEM cipher")
    key_length, block_size = cipher_lengths[algorithm]

    try:
        iv = bytes.fromhex(iv_hex)
    except ValueError:
        raise PEMEncryptionError("Encrypted PEM has an invalid IV") from None
    if len(iv) != block_size:
        raise PEMEncryptionError("Encrypted PEM has an invalid IV")

    key = _evp_bytes_to_key(passphrase, iv[:8], key_length)
    plaintext = _cbc_decrypt(algorithm, key, iv, encrypted_data)
    return _pkcs7_unpad(plaintext, block_size)


def decrypt_pbes2(
    encrypted_data: bytes,
    algorithm_oid: str,
    parameters: typing.Any,
    passphrase: bytes,
) -> bytes:
    """Decrypts PBES2 encrypted PKCS#8 data.

    ``parameters`` is the pyasn1-decoded PBES2 AlgorithmIdentifier parameter.
    """

    if algorithm_oid != "1.2.840.113549.1.5.13":
        raise PEMEncryptionError("Unsupported encrypted PKCS#8 algorithm")

    try:
        kdf_algorithm = parameters[0]
        encryption_algorithm = parameters[1]
        kdf_oid = str(kdf_algorithm[0])
        encryption_oid = str(encryption_algorithm[0])
    except (IndexError, KeyError, TypeError):
        raise PEMEncryptionError("Invalid PBES2 parameters") from None

    if kdf_oid != "1.2.840.113549.1.5.12":
        raise PEMEncryptionError("Unsupported PKCS#8 key derivation function")

    kdf_parameters = kdf_algorithm[1]
    try:
        salt = bytes(kdf_parameters[0])
        iterations = int(kdf_parameters[1])
    except (IndexError, KeyError, TypeError, ValueError):
        raise PEMEncryptionError("Invalid PBKDF2 parameters") from None
    if not salt or iterations <= 0:
        raise PEMEncryptionError("Invalid PBKDF2 parameters")

    key_length = None
    prf_oid = "1.2.840.113549.2.7"
    for index in range(2, len(kdf_parameters)):
        field = kdf_parameters[index]
        try:
            field_value = int(field)
        except (TypeError, ValueError):
            try:
                prf_oid = str(field[0])
            except (IndexError, KeyError, TypeError):
                raise PEMEncryptionError("Invalid PBKDF2 parameters") from None
        else:
            key_length = field_value

    prf_names = {
        "1.2.840.113549.2.7": "sha1",
        "1.2.840.113549.2.8": "sha224",
        "1.2.840.113549.2.9": "sha256",
        "1.2.840.113549.2.10": "sha384",
        "1.2.840.113549.2.11": "sha512",
    }
    if prf_oid not in prf_names:
        raise PEMEncryptionError("Unsupported PBKDF2 PRF")

    cipher_lengths = {
        "2.16.840.1.101.3.4.1.2": (16, 16, "AES-128-CBC"),
        "2.16.840.1.101.3.4.1.22": (24, 16, "AES-192-CBC"),
        "2.16.840.1.101.3.4.1.42": (32, 16, "AES-256-CBC"),
        "1.2.840.113549.3.7": (24, 8, "DES-EDE3-CBC"),
        "1.3.14.3.2.7": (8, 8, "DES-CBC"),
    }
    if encryption_oid not in cipher_lengths:
        raise PEMEncryptionError("Unsupported encrypted PKCS#8 cipher")
    cipher_key_length, block_size, algorithm = cipher_lengths[encryption_oid]
    if key_length is None:
        key_length = cipher_key_length
    elif key_length != cipher_key_length:
        raise PEMEncryptionError("Invalid encrypted PKCS#8 key length")

    try:
        iv = bytes(encryption_algorithm[1])
    except (IndexError, KeyError, TypeError):
        raise PEMEncryptionError("Invalid encrypted PKCS#8 IV") from None
    if len(iv) != block_size:
        raise PEMEncryptionError("Invalid encrypted PKCS#8 IV")

    derived = hashlib.pbkdf2_hmac(
        prf_names[prf_oid],
        passphrase,
        salt,
        iterations,
        dklen=key_length,
    )
    plaintext = _cbc_decrypt(algorithm, derived, iv, encrypted_data)
    return _pkcs7_unpad(plaintext, block_size)
