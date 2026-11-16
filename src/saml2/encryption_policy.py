"""Algorithm and key policies for SAML XML Encryption decryption.

The policy layer inspects every EncryptedData/EncryptedKey structure before
the crypto backend (xmlsec) is invoked and rejects anything that is not
explicitly allowed. Policies are allow-lists grouped by purpose:

* key transport algorithms (RSA PKCS#1 v1.5 / RSA-OAEP variants)
* block encryption algorithms (AES-GCM / AES-CBC / 3DES)
* digest algorithms usable inside OAEP parameters

There is no wildcard: a policy can never be configured to accept "any
algorithm". The legacy algorithms RSA-1.5 and the CBC family are only
available through the explicit legacy profile.
"""

import base64
import binascii
import logging

import defusedxml.ElementTree as ET

from saml2.encryption_errors import DecryptionCorruptError
from saml2.encryption_errors import DecryptionKeyMismatchError
from saml2.encryption_errors import DecryptionPolicyError
from saml2.encryption_errors import EncryptionPolicyConfigurationError


logger = logging.getLogger(__name__)

XENC_NS = "http://www.w3.org/2001/04/xmlenc#"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

# Key transport algorithms
RSA_1_5 = f"{XENC_NS}rsa-1_5"
RSA_OAEP_MGF1P = f"{XENC_NS}rsa-oaep-mgf1p"
RSA_OAEP_11 = f"{XENC_NS}rsa-oaep-1.1"
RSA_OAEP_224 = f"{XENC_NS}rsa-oaep-224"
RSA_OAEP_256 = f"{XENC_NS}rsa-oaep"
RSA_OAEP_384 = f"{XENC_NS}rsa-oaep-384"
RSA_OAEP_512 = f"{XENC_NS}rsa-oaep-512"

# Block encryption algorithms
TRIPLE_DES_CBC = f"{XENC_NS}tripledes-cbc"
AES128_CBC = f"{XENC_NS}aes128-cbc"
AES192_CBC = f"{XENC_NS}aes192-cbc"
AES256_CBC = f"{XENC_NS}aes256-cbc"
AES128_GCM = f"{XENC_NS}aes128-gcm"
AES192_GCM = f"{XENC_NS}aes192-gcm"
AES256_GCM = f"{XENC_NS}aes256-gcm"

# Digest algorithms
DIGEST_SHA1 = f"{DSIG_NS}sha1"
DIGEST_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224"
DIGEST_SHA256 = f"{XENC_NS}sha256"
DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
DIGEST_SHA512 = f"{XENC_NS}sha512"

# Algorithms that must never be enabled by a non-legacy policy.
INSECURE_KEY_TRANSPORT = frozenset({RSA_1_5})
INSECURE_BLOCK_ENCRYPTION = frozenset(
    {TRIPLE_DES_CBC, AES128_CBC, AES192_CBC, AES256_CBC}
)

#: Minimum RSA modulus size (bits) accepted for key transport.
MIN_RSA_KEY_SIZE = 2048
#: Minimum RSA modulus size kept available through the explicit legacy profile.
LEGACY_MIN_RSA_KEY_SIZE = 1024

#: Static parameters of the block ciphers referenced by XML Encryption.
#: key = key length in bytes, iv = IV/nonce length in bytes,
#: mode = "cbc" or "gcm", tag = GCM authentication tag length in bytes.
BLOCK_CIPHER_PARAMS = {
    TRIPLE_DES_CBC: {"key": 24, "iv": 8, "mode": "cbc"},
    AES128_CBC: {"key": 16, "iv": 16, "mode": "cbc"},
    AES192_CBC: {"key": 24, "iv": 16, "mode": "cbc"},
    AES256_CBC: {"key": 32, "iv": 16, "mode": "cbc"},
    AES128_GCM: {"key": 16, "iv": 12, "mode": "gcm", "tag": 16},
    AES192_GCM: {"key": 24, "iv": 12, "mode": "gcm", "tag": 16},
    AES256_GCM: {"key": 32, "iv": 12, "mode": "gcm", "tag": 16},
}

#: OAEP URI -> digest implied when no explicit DigestMethod is present.
DEFAULT_OAEP_DIGEST = {
    RSA_OAEP_MGF1P: DIGEST_SHA1,
    RSA_OAEP_11: DIGEST_SHA256,
    RSA_OAEP_224: DIGEST_SHA256,
    RSA_OAEP_256: DIGEST_SHA256,
    RSA_OAEP_384: DIGEST_SHA384,
    RSA_OAEP_512: DIGEST_SHA512,
}

KEY_TRANSPORT_ALGORITHMS = frozenset(
    {RSA_1_5, RSA_OAEP_MGF1P, RSA_OAEP_11, RSA_OAEP_224,
     RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512}
)

DIGEST_ALGORITHMS = frozenset(
    {DIGEST_SHA1, DIGEST_SHA224, DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512}
)

class EncryptionPolicy:
    """Allowed algorithms and key sizes for SAML decryption.

    A policy is split in three independent allow-lists, one per algorithm
    usage: key transport, block encryption and OAEP digest. An empty
    allow-list rejects everything; there is no wildcard and therefore no
    way to configure "any algorithm".
    """

    def __init__(
        self,
        key_transport,
        block_encryption,
        digest,
        min_rsa_key_size=MIN_RSA_KEY_SIZE,
        name="custom",
    ):
        self.name = str(name)
        self.key_transport = frozenset(key_transport)
        self.block_encryption = frozenset(block_encryption)
        self.digest = frozenset(digest)
        self.min_rsa_key_size = int(min_rsa_key_size)
        self._validate()

    def _validate(self):
        for alg in self.key_transport:
            if alg not in KEY_TRANSPORT_ALGORITHMS:
                raise EncryptionPolicyConfigurationError(
                    f"Unknown key transport algorithm in policy {self.name!r}: {alg}"
                )
        for alg in self.block_encryption:
            if alg not in BLOCK_CIPHER_PARAMS:
                raise EncryptionPolicyConfigurationError(
                    f"Unknown block encryption algorithm in policy {self.name!r}: {alg}"
                )
        for alg in self.digest:
            if alg not in DIGEST_ALGORITHMS:
                raise EncryptionPolicyConfigurationError(
                    f"Unknown digest algorithm in policy {self.name!r}: {alg}"
                )
        if self.min_rsa_key_size < LEGACY_MIN_RSA_KEY_SIZE:
            raise EncryptionPolicyConfigurationError(
                "min_rsa_key_size must be at least 1024 bits"
            )

    @classmethod
    def from_profile(cls, profile_name):
        """Build one of the fixed named profiles."""
        try:
            spec = PROFILES[profile_name]
        except KeyError as exc:
            raise EncryptionPolicyConfigurationError(
                f"Unknown encryption profile {profile_name!r}; "
                f"available profiles: {sorted(PROFILES)}"
            ) from exc
        return cls(name=profile_name, **spec)

    @classmethod
    def from_dict(cls, spec, name="custom"):
        """Build a policy from a plain mapping (configuration files)."

        A mapping may reference a named profile through the "profile" key or
        define explicit allow-lists. Explicit lists may never contain
        algorithms outside the fixed catalog, so "any algorithm" remains
        impossible.
        """
        if not isinstance(spec, dict):
            raise EncryptionPolicyConfigurationError(
                "Encryption policy must be a mapping"
            )
        if "profile" in spec:
            if len(spec) > 1:
                raise EncryptionPolicyConfigurationError(
                    "Encryption policy cannot combine \"profile\" with other keys"
                )
            return cls.from_profile(spec["profile"])
        unknown = set(spec) - {
            "key_transport",
            "block_encryption",
            "digest",
            "min_rsa_key_size",
            "name",
        }
        if unknown:
            raise EncryptionPolicyConfigurationError(
                f"Unknown encryption policy options: {sorted(unknown)}"
            )
        try:
            return cls(
                key_transport=spec["key_transport"],
                block_encryption=spec["block_encryption"],
                digest=spec["digest"],
                min_rsa_key_size=spec.get("min_rsa_key_size", MIN_RSA_KEY_SIZE),
                name=spec.get("name", name),
            )
        except KeyError as exc:
            raise EncryptionPolicyConfigurationError(
                f"Missing required encryption policy option: {exc.args[0]}"
            ) from exc

    def to_dict(self):
        return {
            "name": self.name,
            "key_transport": sorted(self.key_transport),
            "block_encryption": sorted(self.block_encryption),
            "digest": sorted(self.digest),
            "min_rsa_key_size": self.min_rsa_key_size,
        }

    def is_legacy(self):
        """True when the policy relies on legacy-only algorithms."""
        return bool(
            (self.key_transport & INSECURE_KEY_TRANSPORT)
            or (self.block_encryption & INSECURE_BLOCK_ENCRYPTION)
        )

#: Fixed named profiles. Profiles are closed sets; they can never be
#: configured to accept any algorithm. RSA-1.5 and the CBC family only
#: appear in the explicit legacy profile.
PROFILES = {
    "modern": {
        "key_transport": frozenset(
            {RSA_OAEP_11, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512}
        ),
        "block_encryption": frozenset({AES128_GCM, AES192_GCM, AES256_GCM}),
        "digest": frozenset({DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512}),
        "min_rsa_key_size": MIN_RSA_KEY_SIZE,
    },
    "intermediate": {
        "key_transport": frozenset(
            {RSA_OAEP_MGF1P, RSA_OAEP_11, RSA_OAEP_224, RSA_OAEP_256,
             RSA_OAEP_384, RSA_OAEP_512}
        ),
        "block_encryption": frozenset({AES128_GCM, AES192_GCM, AES256_GCM}),
        "digest": frozenset(
            {DIGEST_SHA1, DIGEST_SHA224, DIGEST_SHA256,
             DIGEST_SHA384, DIGEST_SHA512}
        ),
        "min_rsa_key_size": MIN_RSA_KEY_SIZE,
    },
    "legacy": {
        "key_transport": frozenset(
            {RSA_1_5, RSA_OAEP_MGF1P, RSA_OAEP_11, RSA_OAEP_224,
             RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512}
        ),
        "block_encryption": frozenset(
            {TRIPLE_DES_CBC, AES128_CBC, AES192_CBC, AES256_CBC,
             AES128_GCM, AES192_GCM, AES256_GCM}
        ),
        "digest": frozenset(
            {DIGEST_SHA1, DIGEST_SHA224, DIGEST_SHA256,
             DIGEST_SHA384, DIGEST_SHA512}
        ),
        "min_rsa_key_size": LEGACY_MIN_RSA_KEY_SIZE,
    },
}

#: Profile used when no policy is configured at all. It stays compatible with
#: messages that were produced by older deployments (CBC block ciphers,
#: rsa-oaep-mgf1p, 1024-bit RSA). New deployments that want to reject
#: RSA-1.5/CBC must explicitly select the "intermediate" or "modern"
#: profile, or configure an explicit legacy profile to acknowledge the risk.
DEFAULT_PROFILE = "legacy"

class EncryptionPolicyRegistry:
    """Resolves the decryption policy applicable to a remote entity.

    A global policy always applies. Per-entity overrides may reference
    another named profile or supply an explicit policy, but may only
    narrow the global policy: an override can never re-enable an algorithm
    the global policy forbids, and no configuration can select
    "any algorithm".
    """

    def __init__(self, default_policy=None, entity_overrides=None):
        self.default_policy = default_policy or EncryptionPolicy.from_profile(
            DEFAULT_PROFILE
        )
        if not isinstance(self.default_policy, EncryptionPolicy):
            raise EncryptionPolicyConfigurationError(
                "default_policy must be an EncryptionPolicy instance"
            )
        self._entity_overrides = {}
        for entity_id, spec in (entity_overrides or {}).items():
            self.set_entity_policy(entity_id, spec)

    def set_entity_policy(self, entity_id, spec):
        """Register a per-entity policy (profile name, mapping or policy)."""

        if not isinstance(entity_id, str) or not entity_id:
            raise EncryptionPolicyConfigurationError(
                "Entity override key must be a non-empty entityID string"
            )
        if isinstance(spec, EncryptionPolicy):
            policy = spec
        elif isinstance(spec, str):
            policy = EncryptionPolicy.from_profile(spec)
        elif isinstance(spec, dict):
            policy = EncryptionPolicy.from_dict(spec)
        else:
            raise EncryptionPolicyConfigurationError(
                f"Invalid encryption policy override for {entity_id!r}"
            )
        self._guard_narrows(policy)
        self._entity_overrides[entity_id] = policy

    def _guard_narrows(self, candidate):
        """Reject overrides that would widen the global policy."""
        base = self.default_policy
        widened_kt = candidate.key_transport - base.key_transport
        widened_be = candidate.block_encryption - base.block_encryption
        widened_dg = candidate.digest - base.digest
        if widened_kt or widened_be or widened_dg:
            raise EncryptionPolicyConfigurationError(
                "Entity encryption policy override may only narrow the global "
                f"policy; extra algorithms: {sorted(widened_kt | widened_be | widened_dg)}"
            )
        if candidate.min_rsa_key_size < base.min_rsa_key_size:
            raise EncryptionPolicyConfigurationError(
                "Entity encryption policy override may not lower the minimum RSA key size"
            )

    def policy_for(self, entity_id=None):
        """Return the policy to enforce for the given SAML entityID."""
        if entity_id is not None and entity_id in self._entity_overrides:
            return self._entity_overrides[entity_id]
        return self.default_policy

    @property
    def entity_overrides(self):
        return dict(self._entity_overrides)

    @classmethod
    def from_config(cls, config=None):
        """Build a registry from a config mapping.

        Accepted keys:
          * "profile": name of the global named profile
            (defaults to DEFAULT_PROFILE);
          * "policy": explicit global allow-list mapping;
          * "entity_overrides": mapping of entityID to a profile name,
            mapping or EncryptionPolicy.
        """
        config = config or {}
        if not isinstance(config, dict):
            raise EncryptionPolicyConfigurationError(
                "encryption_policy configuration must be a mapping"
            )
        unknown = set(config) - {"profile", "policy", "entity_overrides"}
        if unknown:
            raise EncryptionPolicyConfigurationError(
                f"Unknown encryption_policy options: {sorted(unknown)}"
            )
        if "profile" in config and "policy" in config:
            raise EncryptionPolicyConfigurationError(
                "encryption_policy cannot define both \"profile\" and \"policy\""
            )
        if "policy" in config:
            default_policy = EncryptionPolicy.from_dict(config["policy"])
        else:
            default_policy = EncryptionPolicy.from_profile(
                config.get("profile", DEFAULT_PROFILE)
            )
        return cls(
            default_policy=default_policy,
            entity_overrides=config.get("entity_overrides"),
        )

def _local(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def _namespace(tag):
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


def _find_child(element, local_name, namespace=XENC_NS):
    for child in list(element):
        if _local(child.tag) == local_name and _namespace(child.tag) == namespace:
            return child
    return None


def _find_children(element, local_name, namespace=XENC_NS):
    return [
        child
        for child in list(element)
        if _local(child.tag) == local_name and _namespace(child.tag) == namespace
    ]


def _decode_cipher_value(cipher_value_element, context):
    """Return the raw bytes of a CipherValue or raise a corrupt error."""
    if cipher_value_element is None or cipher_value_element.text is None:
        raise DecryptionCorruptError(f"Missing CipherValue in {context}")
    text = "".join(cipher_value_element.text.split())
    if not text:
        raise DecryptionCorruptError(f"Empty CipherValue in {context}")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionCorruptError(
            f"Invalid base64 CipherValue in {context}"
        ) from exc


def _cipher_value_bytes(encrypted_type, context):
    """Extract and decode the CipherValue of an EncryptedType element."""
    cipher_data = _find_child(encrypted_type, "CipherData")
    if cipher_data is None:
        raise DecryptionCorruptError(f"Missing CipherData in {context}")
    if _find_child(cipher_data, "CipherReference") is not None:
        raise DecryptionCorruptError(
            f"CipherReference is not supported for decryption in {context}"
        )
    cipher_value = _find_child(cipher_data, "CipherValue")
    return _decode_cipher_value(cipher_value, context)


def _encryption_algorithm(encrypted_type, context):
    method = _find_child(encrypted_type, "EncryptionMethod")
    if method is None or not method.get("Algorithm"):
        raise DecryptionCorruptError(f"Missing EncryptionMethod in {context}")
    return method.get("Algorithm")


def _validate_block_ciphertext(algorithm, raw_ciphertext, context):
    """Check IV and ciphertext lengths against the block cipher profile."""
    params = BLOCK_CIPHER_PARAMS[algorithm]
    iv_length = params["iv"]
    if len(raw_ciphertext) < iv_length:
        raise DecryptionCorruptError(
            f"Ciphertext in {context} is shorter than the required IV length"
        )
    body = raw_ciphertext[iv_length:]
    if params["mode"] == "cbc":
        block_size = 16 if algorithm != TRIPLE_DES_CBC else 8
        if len(body) == 0 or len(body) % block_size != 0:
            raise DecryptionCorruptError(
                f"Ciphertext in {context} is truncated or not a whole number of blocks"
            )
    else:
        tag_length = params["tag"]
        if len(body) < tag_length:
            raise DecryptionCorruptError(
                f"Ciphertext in {context} is truncated and missing its GCM authentication tag"
        )

def _oaep_digest(encrypted_key, key_transport_algorithm, context):
    """Resolve the digest used by an OAEP EncryptedKey element."""
    method = _find_child(encrypted_key, "EncryptionMethod")
    digest_method = None
    if method is not None:
        digest_method = _find_child(method, "DigestMethod", namespace=DSIG_NS)
    if digest_method is not None:
        if not digest_method.get("Algorithm"):
            raise DecryptionCorruptError(f"Empty DigestMethod in {context}")
        return digest_method.get("Algorithm")
    return DEFAULT_OAEP_DIGEST.get(key_transport_algorithm, DIGEST_SHA1)


def _validate_encrypted_key(encrypted_key, policy, available_key_sizes, context):
    """Validate the EncryptedKey structure against policy and local keys.

    :param available_key_sizes: RSA modulus sizes in bits that the local
        entity actually holds for decryption.
    """
    key_algorithm = _encryption_algorithm(encrypted_key, context + "/EncryptedKey")
    if key_algorithm not in policy.key_transport:
        raise DecryptionPolicyError(
            f"Key transport algorithm {key_algorithm} is not allowed by policy"
        )

    if key_algorithm != RSA_1_5:
        digest_algorithm = _oaep_digest(encrypted_key, key_algorithm, context)
        if digest_algorithm not in policy.digest:
            raise DecryptionPolicyError(
                f"OAEP digest {digest_algorithm} is not allowed by policy"
            )

    raw_key_cipher = _cipher_value_bytes(encrypted_key, context + "/EncryptedKey")
    if not raw_key_cipher:
        raise DecryptionCorruptError(f"Empty wrapped key in {context}/EncryptedKey")

    if available_key_sizes:
        matching_sizes = [
            key_size
            for key_size in available_key_sizes
            if key_size >= policy.min_rsa_key_size
            and len(raw_key_cipher) == key_size // 8
        ]
        if not matching_sizes:
            if any(key_size < policy.min_rsa_key_size for key_size in available_key_sizes):
                raise DecryptionKeyMismatchError(
                    "Available RSA key is smaller than the policy minimum"
                )
            raise DecryptionKeyMismatchError(
                "Wrapped key length matches none of the available RSA keys"
            )

    for nested in _find_children(encrypted_key, "EncryptedKey"):
        _validate_encrypted_key(nested, policy, available_key_sizes, context + "/EncryptedKey")
    return key_algorithm



def _resolve_encrypted_keys(encrypted_data, key_info, key_by_id, context):
    """Collect the EncryptedKey elements protecting an EncryptedData.

    Two standard layouts are accepted:

    * EncryptedKey nested inside the EncryptedData KeyInfo;
    * a RetrievalMethod in KeyInfo pointing at an EncryptedKey located
      elsewhere in the document.
    """
    encrypted_keys = _find_children(key_info, "EncryptedKey") if key_info is not None else []

    retrieval_methods = (
        _find_children(key_info, "RetrievalMethod", namespace=DSIG_NS)
        if key_info is not None
        else []
    )
    for retrieval_method in retrieval_methods:
        reference = retrieval_method.get("URI", "")
        if not reference.startswith("#") or reference[1:] not in key_by_id:
            raise DecryptionCorruptError(
                f"RetrievalMethod in {context} does not resolve to an EncryptedKey"
            )
        encrypted_keys.append(key_by_id[reference[1:]])

    if not encrypted_keys:
        raise DecryptionCorruptError(f"No usable EncryptedKey found for {context}")
    return encrypted_keys


def _validate_encrypted_data(encrypted_data, policy, available_key_sizes, index, key_by_id):
    context = f"EncryptedData[{index}]"

    key_info = _find_child(encrypted_data, "KeyInfo", namespace=DSIG_NS)
    if _find_child(encrypted_data, "AgreementMethod") is not None or (
        key_info is not None and _find_child(key_info, "AgreementMethod") is not None
    ):
        raise DecryptionPolicyError(
            "AgreementMethod key agreement is not allowed by policy"
        )

    encrypted_keys = _resolve_encrypted_keys(
        encrypted_data, key_info, key_by_id, context
    )
    for encrypted_key in encrypted_keys:
        _validate_encrypted_key(
            encrypted_key, policy, available_key_sizes, context
        )

    block_algorithm = _encryption_algorithm(encrypted_data, context)
    if block_algorithm not in policy.block_encryption:
        raise DecryptionPolicyError(
            f"Block encryption algorithm {block_algorithm} is not allowed by policy"
        )

    raw_ciphertext = _cipher_value_bytes(encrypted_data, context)
    _validate_block_ciphertext(block_algorithm, raw_ciphertext, context)

    if key_info is not None:
        for nested_data in _find_children(key_info, "EncryptedData"):
            _validate_encrypted_data(
                nested_data, policy, available_key_sizes, index + 1, key_by_id
            )


def validate_encrypted_xml(enctext, policy, available_key_sizes=None, entity_id=None):
    """Validate an encrypted XML document before the crypto backend runs.

    Every EncryptedData element in the document is checked against the
    policy resolved for ``entity_id``. On failure one of the three
    DecryptionError subclasses is raised and no backend call is made.

    :param enctext: encrypted XML document as str or bytes
    :param policy: EncryptionPolicy or EncryptionPolicyRegistry
    :param available_key_sizes: iterable of RSA modulus sizes (bits)
        available locally; used for key/ciphertext length matching
    :param entity_id: remote entityID for per-entity policy overrides
    :return: the resolved EncryptionPolicy that was enforced
    """
    if isinstance(policy, EncryptionPolicyRegistry):
        resolved_policy = policy.policy_for(entity_id)
    elif isinstance(policy, EncryptionPolicy):
        resolved_policy = policy
    else:
        raise EncryptionPolicyConfigurationError(
            "validate_encrypted_xml requires an EncryptionPolicy or EncryptionPolicyRegistry"
        )

    if isinstance(enctext, bytes):
        try:
            enctext = enctext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecryptionCorruptError("Encrypted document is not valid UTF-8") from exc
    if not isinstance(enctext, str):
        raise DecryptionCorruptError("Encrypted document must be XML text")

    try:
        document = ET.fromstring(enctext)
    except ET.ParseError as exc:
        raise DecryptionCorruptError("Encrypted document is not well-formed XML") from exc
    except Exception as exc:
        # defusedxml raises dedicated errors for entity expansion attacks
        raise DecryptionCorruptError("Encrypted document failed safe XML parsing") from exc

    key_sizes = frozenset(int(size) for size in (available_key_sizes or ()) if int(size) > 0)

    key_by_id = {}
    for element in document.iter():
        if _local(element.tag) == "EncryptedKey" and element.get("Id"):
            key_by_id[element.get("Id")] = element

    encrypted_data_elements = [
        element for element in document.iter() if _local(element.tag) == "EncryptedData"
    ]
    if not encrypted_data_elements:
        raise DecryptionCorruptError("Document contains no EncryptedData element")

    for index, encrypted_data in enumerate(encrypted_data_elements):
        _validate_encrypted_data(
            encrypted_data, resolved_policy, key_sizes, index, key_by_id
        )

    logger.debug(
        "Encryption policy %s enforced for entity %s on %d EncryptedData element(s)",
        resolved_policy.name,
        entity_id,
        len(encrypted_data_elements),
    )
    return resolved_policy
