# frozen_string_literal: true

module JWT
  module SelectiveDisclosure
    # The signed token handed from issuer to holder together with the disclosures
    # needed to reveal the fields and array elements the issuer selected.
    class IssuedToken
      # @return [String] the compact JWT.
      attr_reader :jwt

      # @param jwt [String] the signed compact JWT.
      # @param disclosures [Array<Disclosure>] all available disclosures.
      def initialize(jwt:, disclosures:)
        @jwt = jwt
        @disclosures = disclosures
      end

      # @return [Array<Disclosure>] every disclosure created by the issuer.
      def disclosures
        @disclosures.dup
      end

      # Builds a presentation revealing only the given disclosure objects.
      #
      # @param selected [Array<Disclosure>] the subset of disclosures to present.
      # @return [String] the serialized combined token (JWT + disclosures).
      # @raise [JWT::InvalidDisclosure] if a presented disclosure was not issued here.
      def present(*selected)
        chosen = selected.flatten
        unknown = chosen.reject { |disclosure| @disclosures.include?(disclosure) }
        unless unknown.empty?
          raise ::JWT::InvalidDisclosure, 'Cannot present a disclosure that was not issued with this token'
        end
        if chosen.uniq.size != chosen.size
          raise ::JWT::DuplicateDigest, 'Cannot present the same disclosure more than once'
        end

        Serializer.serialize(jwt: @jwt, disclosures: chosen)
      end

      # @return [String] the issuance serialization including every disclosure.
      def to_s
        Serializer.serialize(jwt: @jwt, disclosures: @disclosures)
      end
      alias to_combined to_s
    end

    # Serializes and parses the explicit disclosure container format:
    # <jwt>~<disclosure>~...~<disclosure>~ .
    module Serializer
      module_function

      # @param jwt [String] the signed compact JWT.
      # @param disclosures [Array<Disclosure>] disclosures to attach.
      # @return [String] the combined token.
      def serialize(jwt:, disclosures:)
        encoded = disclosures.map(&:encoded)
        ([jwt] + encoded + ['']).join(Format::SEPARATOR)
      end

      # @param combined [String] the combined token.
      # @return [Array(String, Array<Disclosure>)] the JWT and parsed disclosures.
      # @raise [JWT::MalformedSDToken] if the container shape is invalid.
      # @raise [JWT::InvalidDisclosure] if an attached disclosure is malformed.
      def parse(combined)
        unless combined.is_a?(::String) && !combined.empty?
          raise ::JWT::MalformedSDToken, 'Selectively disclosable token must be a non-empty string'
        end
        unless combined.start_with?('ey')
          raise ::JWT::MalformedSDToken, 'Token must start with the signed JWT'
        end
        unless combined.end_with?(Format::SEPARATOR)
          raise ::JWT::MalformedSDToken, 'Combined token must end with a disclosure separator'
        end

        segments = combined.split(Format::SEPARATOR, -1)
        if segments.size < 2
          raise ::JWT::MalformedSDToken, 'Combined token must contain the JWT and the trailing separator'
        end

        jwt = segments.first
        ensure_jwt_shape!(jwt)
        encoded_disclosures = segments[1..-2]
        if encoded_disclosures.any?(&:empty?)
          raise ::JWT::MalformedSDToken, 'Disclosure entries must not be empty'
        end

        disclosures = encoded_disclosures.map { |encoded| Disclosure.from_encoded(encoded) }
        [jwt, disclosures]
      end

      # A compact JWS has exactly two dots and no separator leakage.
      def ensure_jwt_shape!(jwt)
        return if jwt.count('.') == 2 && jwt.split('.').none?(&:empty?)

        raise ::JWT::MalformedSDToken, 'First segment must be a compact JWT'
      end
    end
  end
end
