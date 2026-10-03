# frozen_string_literal: true

require 'digest'

module JWT
  module SDJWT
    # A single selective disclosure.
    #
    # The encoded form is the unpadded base64url of a JSON array:
    #   - object property: [salt, claim_name, claim_value]
    #   - array element:   [salt, claim_value]
    #
    # The digest placed in the token is
    # base64url(sha256(encoded_disclosure)).
    class Disclosure
      attr_reader :salt, :name, :value

      def initialize(salt:, value:, name: nil)
        @salt  = salt
        @name  = name
        @value = value
      end

      # @return [Boolean] true when this disclosure hides an array element.
      def array_element?
        @name.nil?
      end

      # @return [String] the base64url encoded disclosure.
      def encode
        Base64.url_encode(JSON.generate(wire_array))
      end

      # @return [String] base64url encoded sha-256 digest of the encoded disclosure.
      def digest
        Base64.url_encode(Digest::SHA256.digest(encode))
      end

      class << self
        # Parses an encoded disclosure.
        #
        # @param encoded [String] the base64url encoded disclosure.
        # @return [Disclosure] the parsed disclosure.
        # @raise [MalformedDisclosureError] when the encoding or structure is invalid.
        def parse(encoded)
          data = decode_json(encoded)
          validate_shape!(data)
          new(salt: data[0], name: (data[1] if data.length == 3), value: data[-1])
        end

        private

        def decode_json(encoded)
          JSON.parse(Base64.url_decode(encoded))
        rescue Base64DecodeError, ::JSON::ParserError, TypeError
          raise MalformedDisclosureError, 'Disclosure is not valid base64url encoded JSON'
        end

        def validate_shape!(data)
          valid = data.is_a?(Array) &&
                  [2, 3].include?(data.length) &&
                  data[0].is_a?(String) &&
                  (data.length == 2 || data[1].is_a?(String))
          raise MalformedDisclosureError, 'Disclosure must be [salt, value] or [salt, name, value]' unless valid
        end
      end

      private

      def wire_array
        array_element? ? [@salt, @value] : [@salt, @name, @value]
      end
    end
  end
end
