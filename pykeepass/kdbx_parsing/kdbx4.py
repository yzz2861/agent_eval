# Evan Widloski - 2018-04-11
# keepass decrypt experimentation

import hashlib
import hmac
import struct

import argon2
from construct import (
    Byte,
    Bytes,
    Checksum,
    Computed,
    Flag,
    GreedyBytes,
    GreedyString,
    If,
    IfThenElse,
    Int32sl,
    Int32ul,
    Int64sl,
    Int64ul,
    Mapping,
    Padding,
    Peek,
    Pointer,
    RepeatUntil,
    Struct,
    Switch,
    Tell,
    this,
)

from .common import (
    MAX_AES_KDF_ROUNDS,
    MAX_ARGON2_ITERATIONS,
    MAX_ARGON2_MEMORY_BYTES,
    MAX_ARGON2_PARALLELISM,
    MAX_FIELD_SIZE,
    MAX_KDF_SALT_SIZE,
    MIN_KDF_SALT_SIZE,
    XML,
    AES256Payload,
    BoundedPrefixed,
    ChaCha20Payload,
    CipherId,
    CompressionFlags,
    Concatenated,
    Decompressed,
    DynamicDict,
    KDBXParameterError,
    ProtectedStreamId,
    Reparsed,
    TwoFishPayload,
    Unprotect,
    aes_kdf,
    compute_key_composite,
    compute_master,
)

# -------------------- Key Derivation --------------------

# https://github.com/keepassxreboot/keepassxc/blob/bc55974ff304794e53c925442784c50a2fdaf6ee/src/format/KeePass2.cpp#L30-L33
kdf_uuids = {
    'argon2': b'\xefcm\xdf\x8c)DK\x91\xf7\xa9\xa4\x03\xe3\n\x0c',
    'argon2id': b'\x9e)\x8b\x19V\xdbGs\xb2=\xfc>\xc6\xf0\xa1\xe6',
    'aeskdf': b'\xc9\xd9\xf3\x9ab\x8aD`\xbft\r\x08\xc1\x8aO\xea',
}


def _require_kdf_parameter(kdf_parameters, key):
    """Fetch a variant-dictionary KDF parameter or raise a structured error."""

    try:
        return kdf_parameters[key].value
    except (KeyError, AttributeError):
        raise KDBXParameterError(
            "KDF parameter {} is missing or malformed".format(key)
        )


def validate_kdf_parameters(kdf_parameters):
    """Validate attacker-controlled KDF parameters before expensive work.

    Bounds memory, iteration count, parallelism and salt size so that a
    malicious database cannot exhaust CPU or memory.  Only structural metadata
    (parameter names/limits) appears in error messages.
    """

    uuid = _require_kdf_parameter(kdf_parameters, "$UUID")

    if uuid in (kdf_uuids["argon2"], kdf_uuids["argon2id"]):
        salt = _require_kdf_parameter(kdf_parameters, "S")
        iterations = _require_kdf_parameter(kdf_parameters, "I")
        memory_bytes = _require_kdf_parameter(kdf_parameters, "M")
        parallelism = _require_kdf_parameter(kdf_parameters, "P")

        if not (MIN_KDF_SALT_SIZE <= len(salt) <= MAX_KDF_SALT_SIZE):
            raise KDBXParameterError(
                "Argon2 salt size {} outside permitted range ({}, {})".format(
                    len(salt), MIN_KDF_SALT_SIZE, MAX_KDF_SALT_SIZE
                )
            )
        if not (1 <= iterations <= MAX_ARGON2_ITERATIONS):
            raise KDBXParameterError(
                "Argon2 iterations {} outside permitted range (1, {})".format(
                    iterations, MAX_ARGON2_ITERATIONS
                )
            )
        if not (1 <= memory_bytes <= MAX_ARGON2_MEMORY_BYTES):
            raise KDBXParameterError(
                "Argon2 memory parameter outside permitted range "
                "(1, {} bytes)".format(MAX_ARGON2_MEMORY_BYTES)
            )
        if not (1 <= parallelism <= MAX_ARGON2_PARALLELISM):
            raise KDBXParameterError(
                "Argon2 parallelism {} outside permitted range (1, {})".format(
                    parallelism, MAX_ARGON2_PARALLELISM
                )
            )

    elif uuid == kdf_uuids["aeskdf"]:
        salt = _require_kdf_parameter(kdf_parameters, "S")
        rounds = _require_kdf_parameter(kdf_parameters, "R")

        if not (MIN_KDF_SALT_SIZE <= len(salt) <= MAX_KDF_SALT_SIZE):
            raise KDBXParameterError(
                "AES-KDF salt size {} outside permitted range ({}, {})".format(
                    len(salt), MIN_KDF_SALT_SIZE, MAX_KDF_SALT_SIZE
                )
            )
        if not (1 <= rounds <= MAX_AES_KDF_ROUNDS):
            raise KDBXParameterError(
                "AES-KDF rounds {} outside permitted range (1, {})".format(
                    rounds, MAX_AES_KDF_ROUNDS
                )
            )

    else:
        raise KDBXParameterError("Unsupported key derivation method")


def compute_transformed(context):
    """Compute transformed key for opening database"""

    kdf_parameters = context._.header.value.dynamic_header.kdf_parameters.data.dict
    # reject out-of-bounds/missing parameters before doing any expensive work
    validate_kdf_parameters(kdf_parameters)

    if context._._.transformed_key is not None:
        return context._._.transformed_key

    key_composite = compute_key_composite(
        password=context._._.password,
        keyfile=context._._.keyfile
    )
    uuid = kdf_parameters['$UUID'].value

    if uuid in (kdf_uuids['argon2'], kdf_uuids['argon2id']):
        transformed_key = argon2.low_level.hash_secret_raw(
            secret=key_composite,
            salt=kdf_parameters['S'].value,
            hash_len=32,
            type=(argon2.low_level.Type.ID if uuid == kdf_uuids['argon2id'] else argon2.low_level.Type.D),
            time_cost=kdf_parameters['I'].value,
            memory_cost=kdf_parameters['M'].value // 1024,
            parallelism=kdf_parameters['P'].value,
            version=kdf_parameters['V'].value
        )
    elif uuid == kdf_uuids['aeskdf']:
        transformed_key = aes_kdf(
            kdf_parameters['S'].value,
            kdf_parameters['R'].value,
            key_composite
        )
    else:
        # unreachable: validate_kdf_parameters already rejected the UUID
        raise KDBXParameterError('Unsupported key derivation method')

    return transformed_key


def compute_header_hmac_hash(context):
    """Compute HMAC-SHA256 hash of header.
    Used to prevent header tampering."""

    return hmac.new(
        hashlib.sha512(
            b'\xff' * 8 +
            hashlib.sha512(
                context._.header.value.dynamic_header.master_seed.data +
                context.transformed_key +
                b'\x01'
            ).digest()
        ).digest(),
        context._.header.data,
        hashlib.sha256
    ).digest()


# --------------- KDF Params / Plugin Data ----------------
VariantDictionaryItem = Struct(
    "type" / Byte,
    "key" / BoundedPrefixed(Int32ul, GreedyString('utf-8'), MAX_FIELD_SIZE, "variant dictionary key"),
    "value" / BoundedPrefixed(
        Int32ul,
        Switch(
            this.type,
            {0x04: Int32ul,
             0x05: Int64ul,
             0x08: Flag,
             0x0C: Int32sl,
             0x0D: Int64sl,
             0x42: GreedyBytes,
             0x18: GreedyString('utf-8')
             }
        ),
        MAX_FIELD_SIZE,
        "variant dictionary value"
    ),
    "next_byte" / Peek(Byte)
)

# new dynamic dictionary structure added in KDBX4
VariantDictionary = Struct(
    "version" / Bytes(2),
    "dict" / DynamicDict(
        'key',
        RepeatUntil(
            lambda item, a, b: item.next_byte == 0x00,
            VariantDictionaryItem
        )
    ),
    Padding(1) * "null padding"
)

# -------------------- Dynamic Header --------------------

# https://github.com/dlech/KeePass2.x/blob/dbb9d60095ef39e6abc95d708fb7d03ce5ae865e/KeePassLib/Serialization/KdbxFile.cs#L234-L246

DynamicHeaderItem = Struct(
    "id" / Mapping(
        Byte,
        {'end': 0,
         'comment': 1,
         'cipher_id': 2,
         'compression_flags': 3,
         'master_seed': 4,
         'encryption_iv': 7,
         'kdf_parameters': 11,
         'public_custom_data': 12
         }
    ),
    "data" / BoundedPrefixed(
        Int32ul,
        Switch(
            this.id,
            {'compression_flags': CompressionFlags,
             'kdf_parameters': VariantDictionary,
             'cipher_id': CipherId
             },
            default=GreedyBytes
        ),
        MAX_FIELD_SIZE,
        "dynamic header field"
    )
)

DynamicHeader = DynamicDict(
    'id',
    RepeatUntil(
        lambda item, a, b: item.id == 'end',
        DynamicHeaderItem
    )
)


# -------------------- Payload Verification --------------------
def compute_payload_block_hash(this):
    """Compute hash of each payload block.
    Used to prevent payload corruption and tampering."""

    return hmac.new(
        hashlib.sha512(
            struct.pack('<Q', this._index) +
            hashlib.sha512(
                this._._.header.value.dynamic_header.master_seed.data +
                this._.transformed_key + b'\x01'
            ).digest()
        ).digest(),
        struct.pack('<Q', this._index) +
        struct.pack('<I', len(this.block_data)) +
        this.block_data, hashlib.sha256
    ).digest()


# -------------------- Payload Decryption/Decompression --------------------
# encrypted payload is split into multiple data blocks with hashes
EncryptedPayloadBlock = Struct(
    "hmac_hash_offset" / Tell,
    Padding(32),
    "block_data" / BoundedPrefixed(Int32ul, GreedyBytes, MAX_FIELD_SIZE, "encrypted payload block"),
    # hmac_hash has to be at the end with a pointer because it needs to
    # come after other fields
    "hmac_hash" / Pointer(
        this.hmac_hash_offset,
        Checksum(
            Bytes(32),
            compute_payload_block_hash,
            this,
            # exception=PayloadChecksumError
        )
    )
)

EncryptedPayload = Concatenated(RepeatUntil(
    lambda item, a, b: len(item.block_data) == 0,
    EncryptedPayloadBlock
))

DecryptedPayload = Switch(
    this._.header.value.dynamic_header.cipher_id.data,
    {'aes256': AES256Payload(EncryptedPayload),
     'chacha20': ChaCha20Payload(EncryptedPayload),
     'twofish': TwoFishPayload(EncryptedPayload)
     }
)


InnerHeaderItem = Struct(
    "type" / Mapping(
        Byte,
        {'end': 0x00,
         'protected_stream_id': 0x01,
         'protected_stream_key': 0x02,
         'binary': 0x03
         }
    ),
    "data" / BoundedPrefixed(
        Int32ul,
        Switch(
            this.type,
            {'protected_stream_id': ProtectedStreamId},
            default=GreedyBytes
        ),
        MAX_FIELD_SIZE,
        "inner header field"
    )
)

# another binary header inside decrypted and decompressed Payload
InnerHeader = DynamicDict(
    'type',
    RepeatUntil(lambda item, a, b: item.type == 'end', InnerHeaderItem),
    # FIXME - this is a hack because inner header is not truly a dict,
    #  it has multiple binary elements.
    lump=['binary']
)

UnpackedPayload = Reparsed(
    Struct(
        "inner_header" / InnerHeader,
        "xml" / Unprotect(
            this.inner_header.protected_stream_id.data,
            this.inner_header.protected_stream_key.data,
            XML(GreedyBytes)
        )
    )
)


# -------------------- Main KDBX Structure --------------------

Body = Struct(
    "transformed_key" / Computed(compute_transformed),
    "master_key" / Computed(compute_master),
    "sha256" / Checksum(
        Bytes(32),
        lambda data: hashlib.sha256(data).digest(),
        this._.header.data,
        # exception=HeaderChecksumError,
    ),
    "cred_check" / If(this._._.decrypt,
        Checksum(
            Bytes(32),
            compute_header_hmac_hash,
            this,
            # exception=CredentialsError,
        )
    ),
    "payload" / If(this._._.decrypt,
        UnpackedPayload(
            IfThenElse(
                this._.header.value.dynamic_header.compression_flags.data.compression,
                Decompressed(DecryptedPayload),
                DecryptedPayload
            )
        )
    )
)
