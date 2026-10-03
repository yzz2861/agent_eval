# frozen_string_literal: true

module JWT
  module SelectiveDisclosure
    # A single selectively-disclosable claim or array element.
    #
    # Object fields are disclosed as `[salt, key, value]` and array elements
    # as `[salt, value]`. The disclosure is carried as compact, ASCII-only
    # JSON encoded with unpadded URL-safe Base64; the digest is computed over
    # the encoded string.
    class Disclosure
      PROPERTY = :property
      ARRAY_ELEMENT = :array_element

      # @return [String] the random salt bound to the disclosure.
      attr_reader :salt

      # @return [String] the disclosed object key, or nil for array elements.
      attr_reader :key

      # @return [Object] the disclosed value.
      attr_reader :value

      # Builds a disclosure from raw parts.
      #
      # @param salt [String] the random salt.
      # @param key [String, nil] the object key, or nil when disclosing an array element.
      # @param value [Object] the disclosed value.
      # @return [Disclosure]
      def self.create(salt:, value:, key: nil)
        new(salt: salt, key: key, value: value)
      end

      # Decodes and validates a disclosure carried in a combined token.
      #
      # @param encoded [String] the unpadded URL-safe Base64 encoded disclosure.
      # @return [Disclosure]
      # @raise [JWT::InvalidDisclosure] if the disclosure cannot be decoded or is malformed.
      def self.from_encoded(encoded)
        json = begin
          ::JWT::Base64.url_decode(encoded)
        rescue ::JWT::Base64DecodeError
          raise ::JWT::InvalidDisclosure, 'Disclosure is not valid Base64url'
        end

        parts = begin
          JWT::JSON.parse(json)
        rescue ::JSON::ParserError
          raise ::JWT::InvalidDisclosure, 'Disclosure is not valid JSON'
        end

        unless parts.is_a?(::Array) && (parts.size == 2 || parts.size == 3)
          raise ::JWT::InvalidDisclosure, 'Disclosure must be a two or three element array'
        end
        raise ::JWT::InvalidDisclosure, 'Disclosure salt must be a string' unless parts[0].is_a?(::String)

        if parts.size == 3
          raise ::JWT::InvalidDisclosure, 'Disclosure key must be a string' unless parts[1].is_a?(::String)

          new(salt: parts[0], key: parts[1], value: parts[2])
        else
          new(salt: parts[0], key: nil, value: parts[1])
        end
      end

      def initialize(salt:, key:, value:, encoded: nil)
        @salt = salt
        @key = key
        @value = value
        @encoded = encoded
      end

      # @return [:property, :array_element] the kind of disclosure.
      def kind
        key.nil? ? ARRAY_ELEMENT : PROPERTY
      end

      # @return [Boolean] true for an object field disclosure.
      def property?
        kind == PROPERTY
      end

      # @return [Boolean] true for an array element disclosure.
      def array_element?
        kind == ARRAY_ELEMENT
      end

      # @return [String] the unpadded URL-safe Base64 encoded disclosure.
      def encoded
        @encoded ||= ::JWT::Base64.url_encode(canonical_json)
      end

      # @return [String] the SHA-256 digest of the encoded disclosure, Base64url encoded.
      def digest
        @digest ||= Digester.digest(encoded)
      end

      # @return [Array] the disclosure as a JSON-serialisable array.
      def to_a
        canonical_parts
      end

      def ==(other)
        other.is_a?(self.class) && encoded == other.encoded
      end
      alias eql? ==

      def hash
        encoded.hash
      end

      private

      def canonical_json
        # Compact ASCII-only JSON pins down a single byte representation that
        # both issuer and verifier hash over.
        ::JSON.generate(canonical_parts, ascii_only: true)
      end

      def canonical_parts
        property? ? [salt, key, value] : [salt, value]
      end
    end
  end
end
