"""Decryption error classification.

The generic :class:`~saml2.sigver.DecryptError` used to hide every failure of
the underlying crypto backend.  The policy layer needs to distinguish failures
that happen *before* the backend is invoked:

* :class:`DecryptionPolicyError` - the message uses an algorithm or parameter
  that the configured policy forbids;
* :class:`DecryptionKeyMismatchError` - the key material (for example the RSA
  key size) does not match the ciphertext;
* :class:`DecryptionCorruptError` - the ciphertext structure, encoding or
  lengths are malformed.

None of these exceptions ever carries key material or raw ciphertext: only
algorithm identifiers, integer lengths and structural descriptions are
included in the messages.
"""

from saml2 import SAMLError


class DecryptionError(SAMLError):
    """Base class for all decryption failures raised by the policy layer."""


class DecryptionPolicyError(DecryptionError):
    """Raised when an algorithm or key parameter is forbidden by policy.

    The failure occurs before the crypto backend is called, so a backend
    decryption attempt can never have happened.
    """


class DecryptionKeyMismatchError(DecryptionError):
    """Raised when the available key does not match the ciphertext.

    Typical examples are an RSA modulus smaller than an RSA-OAEP ciphertext
    or an EncryptedKey that none of the configured keys can unwrap.
    """


class DecryptionCorruptError(DecryptionError):
    """Raised when the ciphertext is malformed.

    This covers invalid base64, missing CipherData/CipherValue, unexpected
    CipherReference usage, bad IV or ciphertext lengths and truncation.
    """


class EncryptionPolicyConfigurationError(ValueError):
    """Raised when a decryption policy itself is misconfigured.

    This is a configuration-time error (unknown algorithm, wildcard
    request, sub-1024 bit RSA floor); it is never raised while processing
    a SAML message.
    """
