# frozen_string_literal: true

module JWT
  module SDJWT
    # The base error class for all selective disclosure errors.
    class Error < JWT::Error; end

    # Raised when a disclosure cannot be parsed or is structurally invalid.
    class MalformedDisclosureError < Error; end

    # Raised when the same digest appears more than once, either in the
    # token's digests or among the provided disclosures.
    class DuplicateDigestError < Error; end

    # Raised when a provided disclosure does not match any digest in the token.
    class OrphanDisclosureError < Error; end

    # Raised when a disclosed claim name collides with a claim that is
    # already present in plaintext at the same object level.
    class ClaimCollisionError < Error; end

    # Raised when the token declares an unsupported digest algorithm.
    class UnsupportedSdAlgError < Error; end

    # Raised when the issuer is asked to hide a claim path that does not
    # exist or is otherwise invalid.
    class IssuanceError < Error; end
  end
end
