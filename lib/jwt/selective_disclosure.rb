# frozen_string_literal: true

require 'jwt'
require 'jwt/selective_disclosure/digester'
require 'jwt/selective_disclosure/disclosure'
require 'jwt/selective_disclosure/issuer'
require 'jwt/selective_disclosure/issued_token'
require 'jwt/selective_disclosure/resolver'
require 'jwt/selective_disclosure/verifier'

module JWT
  # Selective Disclosure for JWT (a constrained, explicit-encoding profile).
  #
  # The issuer replaces selected object fields or array elements with SHA-256
  # salted digests inside an otherwise normal signed JWT. The holder later
  # presents only a subset of the matching disclosures. The verifier checks the
  # JWT signature first and then rebuilds only the claims whose digests are
  # anchored in the signed payload; undisclosed fields stay invisible.
  #
  # Only SHA-256 is supported and the disclosure encoding is fixed:
  # * object field disclosure: Base64url(JSON([salt, key, value]))
  # * array element disclosure: Base64url(JSON([salt, value]))
  # * hidden object fields are listed in a "_sd" digest array
  # * hidden array elements are {"...": "<digest>"} markers
  # * the combined token is "<jwt>~<disclosure>~...~<disclosure>~"
  module SelectiveDisclosure
    module_function

    # Issues a selectively-disclosable token.
    #
    # @param payload [Hash] all claims known to the issuer.
    # @param key [Object] the signing key.
    # @param algorithm [String] the JWS signing algorithm (default HS256).
    # @param disclosable_paths [Array<Array>] paths of fields/elements to hide
    #   behind digests, e.g. [%w[address], ['addresses', 0], %w[nationalities]] .
    # @param salt_source [#call] injectable secure random salt source.
    # @param header_fields [Hash] additional JWT header fields.
    # @return [IssuedToken]
    def issue(payload, key, algorithm = 'HS256', disclosable_paths: [], salt_source: nil, header_fields: {})
      Issuer.new(
        payload,
        key,
        algorithm,
        disclosable_paths: disclosable_paths,
        salt_source: salt_source,
        header_fields: header_fields
      ).issue
    end

    # Verifies a presentation and reconstructs the provable claims.
    #
    # @param combined [String] the JWT plus the holder-selected disclosures.
    # @param key [Object] the verification key.
    # @param algorithm [String, Array<String>] accepted signing algorithms.
    # @param options [Hash] decode and registered-claims options for {JWT.decode}.
    # @param keyfinder [Proc] optional dynamic key finder.
    # @return [VerificationResult]
    def verify(combined, key, algorithm = 'HS256', options = {}, &keyfinder)
      Verifier.new(combined, key, algorithm, options, &keyfinder).verify
    end
  end
end
