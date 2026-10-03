# frozen_string_literal: true

module JWT
  module SelectiveDisclosure
    # Verifies a combined token: the signed JWT is validated first, then the
    # presented disclosures are checked against the digests they claim to match
    # and the provable claims are reconstructed.
    class Verifier
      # @param combined [String] the JWT plus the holder-selected disclosures.
      # @param key [Object] the verification key.
      # @param algorithm [String, Array<String>] accepted signing algorithms.
      # @param options [Hash] extra decode/claims options passed to {JWT.decode}.
      # @param keyfinder [Proc] optional dynamic key finder for {JWT.decode}.
      def initialize(combined, key, algorithm = 'HS256', options = {}, &keyfinder)
        @combined = combined
        @key = key
        @algorithm = algorithm
        @options = options
        @keyfinder = keyfinder
      end

      # @return [VerificationResult] the reconstructed claims and JWT header.
      # @raise [JWT::MalformedSDToken] if the token is not a combined token.
      # @raise [JWT::VerificationError] if the JWT signature is invalid.
      # @raise [JWT::SelectiveDisclosureError] if a disclosure is invalid.
      def verify
        jwt, disclosures = Serializer.parse(@combined)

        # A plain JWT (three dot-separated segments and no disclosure separator)
        # never reaches this method; Serializer.parse already required the
        # trailing '~'. The JWT itself is verified through the normal code path.
        payload, header = decode_jwt(jwt)

        validate_format!(payload, header)
        claims = Resolver.new(payload, disclosures).resolve!

        VerificationResult.new(claims: claims, header: header, disclosures: disclosures)
      end

      private

      def decode_jwt(jwt)
        options = @options.key?(:algorithms) ? @options.merge(algorithm: @options[:algorithms]) : @options
        options = options.merge(algorithm: @algorithm) unless options.key?(:algorithm)

        if @keyfinder
          JWT.decode(jwt, @key, true, options, &@keyfinder)
        else
          JWT.decode(jwt, @key, true, options)
        end
      end

      def validate_format!(payload, header)
        unless header.is_a?(::Hash) && header['typ'] == Format::TYPE
          raise ::JWT::MalformedSDToken, "Expected JWT header typ #{Format::TYPE.inspect}"
        end
        unless payload.is_a?(::Hash)
          raise ::JWT::MalformedSDToken, 'Expected a JSON object payload'
        end
        unless payload[Format::SD_ALG_CLAIM] == Digester::HASH_ALGORITHM
          raise ::JWT::MalformedSDToken, "Unsupported or missing #{Format::SD_ALG_CLAIM}, only #{Digester::HASH_ALGORITHM.inspect} is allowed"
        end
      end
    end

    # The claims provably disclosed by the holder, together with the JWT header
    # and the disclosures that were accepted.
    class VerificationResult
      # @return [Hash] the reconstructed claims.
      attr_reader :claims
      # @return [Hash] the verified JWT header.
      attr_reader :header
      # @return [Array<Disclosure>] the disclosures accepted during verification.
      attr_reader :disclosures

      def initialize(claims:, header:, disclosures:)
        @claims = claims
        @header = header
        @disclosures = disclosures
      end

      # @return [Array<String>] the encoded disclosures that were accepted.
      def disclosed_keys
        disclosures.select(&:property?).map(&:key)
      end

      def to_h
        claims
      end
    end
  end
end
