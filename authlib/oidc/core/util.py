import hashlib

from authlib.common.encoding import to_bytes
from authlib.common.encoding import urlsafe_b64encode
from authlib.oauth2.rfc6749.util import normalize_response_type

#: The response matrix of the OpenID Connect flows, per OpenID Connect
#: Core 1.0 Sections 3.1.2.5, 3.2.2.5 and 3.3.2.5. For each response type:
#:
#: - ``params``: the parameters the authorization response MUST contain
#: - ``hash_claims``: the hash claims of the front-channel ID Token, mapped
#:   to the response parameter each of them binds (``c_hash`` covers the
#:   ``code`` of the same response, ``at_hash`` its ``access_token``)
#: - ``nonce``: whether the authorization request MUST contain a ``nonce``,
#:   which the ID Token MUST then contain as a claim
#:
#: The generation and the validation of the authorization responses share
#: this matrix, so a response type cannot be emitted with a parameter or a
#: claim missing, and a response cannot be validated against the matrix of
#: another response type.
RESPONSE_TYPE_MATRIX = {
    "code": {
        "params": frozenset(["code"]),
        "hash_claims": {},
        "nonce": False,
    },
    "id_token": {
        "params": frozenset(["id_token"]),
        "hash_claims": {},
        "nonce": True,
    },
    "id_token token": {
        "params": frozenset(["id_token", "access_token"]),
        "hash_claims": {"at_hash": "access_token"},
        "nonce": True,
    },
    "code id_token": {
        "params": frozenset(["code", "id_token"]),
        "hash_claims": {"c_hash": "code"},
        "nonce": True,
    },
    "code token": {
        "params": frozenset(["code", "access_token"]),
        "hash_claims": {},
        "nonce": True,
    },
    "code id_token token": {
        "params": frozenset(["code", "id_token", "access_token"]),
        "hash_claims": {"c_hash": "code", "at_hash": "access_token"},
        "nonce": True,
    },
}


def get_response_type_spec(response_type):
    """Return the response matrix entry of a response type.

    Per RFC 6749 3.1.1, the order of the response type values does not
    matter.

    :param response_type: the ``response_type`` of an authorization request
    :return: the matrix entry, or ``None`` if the response type is unknown
    """
    return RESPONSE_TYPE_MATRIX.get(normalize_response_type(response_type))


def is_nonce_required(response_type):
    """Tell if the authorization request of a response type MUST contain a
    ``nonce``, per the response matrix. Unknown response types require it,
    so a missing matrix entry cannot disable the check.

    :param response_type: the ``response_type`` of an authorization request
    :return: boolean
    """
    spec = get_response_type_spec(response_type)
    return spec["nonce"] if spec is not None else True


def create_half_hash(s, alg):
    if alg == "EdDSA":
        hash_alg = hashlib.sha512
    else:
        hash_type = f"sha{alg[2:]}"
        hash_alg = getattr(hashlib, hash_type, None)
        if not hash_alg:
            return None

    data_digest = hash_alg(to_bytes(s)).digest()
    slice_index = int(len(data_digest) / 2)
    return urlsafe_b64encode(data_digest[:slice_index])
