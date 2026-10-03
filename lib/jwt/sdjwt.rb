# frozen_string_literal: true

require 'jwt/sdjwt/errors'
require 'jwt/sdjwt/disclosure'
require 'jwt/sdjwt/issued_credential'
require 'jwt/sdjwt/issuer'
require 'jwt/sdjwt/verifier'

module JWT
  # Selective disclosure for JWTs (SD-JWT style).
  #
  # The issuer replaces selected object properties or array elements with
  # salted sha-256 digests before signing. The holder presents the token
  # together with a subset of the disclosures. The verifier checks the
  # signature and reconstructs exactly the claims proven by the presented
  # disclosures; everything else stays hidden.
  #
  # Only sha-256 is supported and disclosures use an explicit encoding:
  # base64url(JSON[salt, name, value]) for object properties and
  # base64url(JSON[salt, value]) for array elements.
  #
  # Reconstructed claims are only available through JWT::SDJWT.verify;
  # plain JWT.decode never resolves digests.
  module SDJWT
    # Separator between the token and the disclosures in a presentation.
    SEPARATOR = '~'
    # Claim holding the digests of hidden object properties.
    SD_KEY = '_sd'
    # Claim declaring the digest algorithm.
    SD_ALG_KEY = '_sd_alg'
    # The only supported digest algorithm.
    SD_ALG = 'sha-256'
    # Key of the placeholder object replacing a hidden array element.
    ARRAY_DIGEST_KEY = '...'

    module_function

    # Issues a selectively disclosable token.
    #
    # @param payload [Hash] the claims to issue.
    # @param key [String] the signing key.
    # @param algorithm [String] the JWT signing algorithm.
    # @param disclose [Array<Array>] claim paths to make selectively
    #   disclosable, e.g. [[:email], [:address, :street], [:tags, 0]].
    # @param random [#call] injectable secure random source for salts.
    # @param headers [Hash] additional JWT headers.
    # @return [IssuedCredential] the token and all disclosures.
    def issue(payload, key, algorithm: 'HS256', disclose: [], random: nil, headers: {})
      Issuer.new(payload, key,
                 algorithm: algorithm,
                 disclose: disclose,
                 random: random,
                 headers: headers).issue
    end

    # Verifies a presentation and reconstructs the provable claims.
    #
    # @param presentation [String] jwt~disclosure~disclosure...
    # @param key [String] the verification key.
    # @param decode_options [Hash] options forwarded to JWT.decode.
    # @return [Hash] the reconstructed claims.
    def verify(presentation, key, **decode_options)
      Verifier.new(presentation, key, decode_options).verify
    end
  end
end
