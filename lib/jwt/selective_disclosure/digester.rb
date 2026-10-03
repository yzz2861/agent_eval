# frozen_string_literal: true

require 'openssl'

module JWT
  module SelectiveDisclosure
    # Computes the SHA-256 digests used to anchor disclosures.
    module Digester
      HASH_ALGORITHM = 'sha-256'.freeze
      OPENSSL_DIGEST = 'SHA256'.freeze

      module_function

      # @param data [String] the encoded disclosure.
      # @return [String] the unpadded URL-safe Base64 encoded SHA-256 digest.
      def digest(data)
        ::JWT::Base64.url_encode(OpenSSL::Digest.digest(OPENSSL_DIGEST, data))
      end
    end

    # Default salt source backed by OpenSSL's secure random generator.
    class SecureRandomSalt
      DEFAULT_BYTES = 16

      def initialize(bytes: DEFAULT_BYTES)
        @bytes = bytes
      end

      # @return [String] a URL-safe Base64 encoded random salt.
      def call
        ::JWT::Base64.url_encode(OpenSSL::Random.random_bytes(@bytes))
      end
    end

    # Wire format constants for the combined token.
    module Format
      # Marker object field holding the digests of hidden properties.
      SD_CLAIM = '_sd'.freeze
      # Claim carrying the hash algorithm in the signed payload.
      SD_ALG_CLAIM = '_sd_alg'.freeze
      # Single-key object wrapping an array element digest.
      ARRAY_MARKER = '...'.freeze
      # Media subtype written to the JWT `typ` header.
      TYPE = 'sd+jwt'.freeze
      # Separator between the JWT and the disclosures.
      SEPARATOR = '~'.freeze

      RESERVED_CLAIMS = [SD_CLAIM, SD_ALG_CLAIM].freeze
      private_constant(:RESERVED_CLAIMS)

      module_function

      def reserved_claim?(name)
        RESERVED_CLAIMS.include?(name)
      end

      def array_marker?(value)
        value.is_a?(::Hash) && value.size == 1 && value.key?(ARRAY_MARKER)
      end
    end
  end
end
