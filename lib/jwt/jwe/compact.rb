# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require_relative '../base64'
require_relative '../error'
require_relative '../json'

module JWT
  # JSON Web Encryption support.
  module JWE
    # Raised when a JWE message requests compression.
    class UnsupportedCompression < JWT::MalformedTokenError; end

    # Performs Compact JWE encryption and decryption using the direct key
    # agreement algorithm with AES-256-GCM.
    class Compact
      ALGORITHM = 'dir'
      ENCRYPTION = 'A256GCM'
      KEY_LENGTH = 32
      IV_LENGTH = 12
      TAG_LENGTH = 16

      BASE64URL_PATTERN = %r{\A[A-Za-z0-9_-]*\z}.freeze

      private_constant(:BASE64URL_PATTERN)

      class << self
        # Encrypts plaintext using Compact JWE serialization.
        #
        # @param plaintext [String] the data to encrypt.
        # @param key [String] the 32-byte AES-256 content encryption key.
        # @param iv [String, nil] an optional 12-byte initialization vector.
        # @param rng [#random_bytes, #call] the random source used when iv is omitted.
        # @return [String] the Compact JWE token.
        def encrypt(plaintext, key, iv: nil, rng: SecureRandom)
          new(rng: rng).encrypt(plaintext, key, iv: iv)
        end
        alias encode encrypt

        # Decrypts a Compact JWE token.
        #
        # Nested JWS values are returned unchanged and must be verified by
        # the caller, for example with JWT.decode.
        #
        # @param token [String] the Compact JWE token.
        # @param key [String] the 32-byte AES-256 content encryption key.
        # @return [String] the authenticated plaintext.
        def decrypt(token, key)
          new.decrypt(token, key)
        end
        alias decode decrypt
      end

      # @param rng [#random_bytes, #call] the random source for generated IVs.
      def initialize(rng: SecureRandom)
        @rng = rng
      end

      # Encrypts plaintext using Compact JWE serialization.
      #
      # @param plaintext [String] the data to encrypt.
      # @param key [String] the 32-byte AES-256 content encryption key.
      # @param iv [String, nil] an optional 12-byte initialization vector.
      # @return [String] the Compact JWE token.
      def encrypt(plaintext, key, iv: nil)
        @plaintext = plaintext
        @key = key
        @iv = iv

        validate_plaintext!
        validate_key!(::JWT::EncodeError)
        validate_or_generate_iv!

        ciphertext, tag = encrypt_ciphertext
        [encoded_protected_header, '', encode_segment(@iv), encode_segment(ciphertext), encode_segment(tag)].join('.')
      end
      alias encode encrypt

      # Decrypts a Compact JWE token.
      #
      # Nested JWS values are returned unchanged and must be verified by
      # the caller, for example with JWT.decode.
      #
      # @param token [String] the Compact JWE token.
      # @param key [String] the 32-byte AES-256 content encryption key.
      # @return [String] the authenticated plaintext.
      def decrypt(token, key)
        @token = token
        @key = key

        protected_header, encrypted_key_segment, iv_segment, ciphertext_segment, tag_segment = valid_segments
        encrypted_key = decode_segment(encrypted_key_segment, allow_empty: true)
        @iv = decode_segment(iv_segment)
        @ciphertext = decode_segment(ciphertext_segment, allow_empty: true)
        @tag = decode_segment(tag_segment)
        @header = parse_header(protected_header)

        validate_key!(::JWT::VerificationKeyError)
        validate_decrypted_segments!(encrypted_key)
        validate_header!
        decrypt_ciphertext(protected_header)
      end
      alias decode decrypt

      private

      class UniqueHeader < Hash
        def []=(name, value)
          raise ::JSON::ParserError, "Duplicate JWE header parameter: #{name}" if key?(name)

          super
        end
      end

      private_constant(:UniqueHeader)

      def validate_plaintext!
        return if @plaintext.is_a?(String)

        raise ::JWT::EncodeError, 'JWE plaintext must be a String'
      end

      def validate_key!(error_class)
        return if @key.is_a?(String) && @key.bytesize == KEY_LENGTH

        raise error_class, "JWE key must be a #{KEY_LENGTH}-byte String"
      end

      def validate_or_generate_iv!
        @iv = generated_iv if @iv.nil?
        return if @iv.is_a?(String) && @iv.bytesize == IV_LENGTH

        raise ::JWT::EncodeError, "JWE IV must be a #{IV_LENGTH}-byte String"
      end

      def generated_iv
        if @rng.respond_to?(:random_bytes)
          @rng.random_bytes(IV_LENGTH)
        elsif @rng.respond_to?(:call)
          @rng.call(IV_LENGTH)
        else
          raise ::JWT::EncodeError, 'JWE random source must respond to random_bytes or call'
        end
      end

      def encrypt_ciphertext
        cipher = build_cipher(:encrypt)
        ciphertext = cipher.update(@plaintext) + cipher.final
        [ciphertext, cipher.auth_tag]
      end

      def decrypt_ciphertext(encoded_header)
        cipher = build_cipher(:decrypt)
        cipher.auth_tag = @tag
        cipher.auth_data = encoded_header

        cipher.update(@ciphertext) + cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise ::JWT::VerificationError, 'JWE authentication failed'
      end

      def build_cipher(direction)
        cipher = OpenSSL::Cipher.new('AES-256-GCM')
        cipher.public_send(direction)
        cipher.key = @key
        cipher.iv = @iv
        cipher.auth_data = encoded_protected_header if direction == :encrypt
        cipher
      end

      def valid_segments
        raise ::JWT::MalformedTokenError, 'JWE token must be a String' unless @token.is_a?(String)

        segments = @token.split('.')
        unless segments.size == 5
          raise ::JWT::MalformedTokenError, 'JWE Compact serialization must contain five segments'
        end

        segments
      end

      def parse_header(encoded_header)
        raw_header = decode_segment(encoded_header).force_encoding(Encoding::UTF_8)
        unless raw_header.valid_encoding?
          raise ::JWT::MalformedTokenError, 'Invalid JWE protected header'
        end

        header = ::JSON.parse(raw_header, object_class: UniqueHeader)
        return header if header.is_a?(Hash)

        raise ::JWT::MalformedTokenError, 'JWE protected header must be a JSON object'
      rescue ::JSON::ParserError
        raise ::JWT::MalformedTokenError, 'Invalid JWE protected header'
      end

      def validate_decrypted_segments!(encrypted_key)
        unless encrypted_key.empty?
          raise ::JWT::MalformedTokenError, 'The dir algorithm requires an empty encrypted key segment'
        end
        unless @iv.bytesize == IV_LENGTH
          raise ::JWT::MalformedTokenError, "JWE IV must be #{IV_LENGTH} bytes"
        end
        unless @tag.bytesize == TAG_LENGTH
          raise ::JWT::MalformedTokenError, "JWE authentication tag must be #{TAG_LENGTH} bytes"
        end
      end

      def validate_header!
        if @header.key?('zip')
          raise ::JWT::JWE::UnsupportedCompression, 'JWE compression is not supported'
        end

        unless @header['alg'] == ALGORITHM && @header['enc'] == ENCRYPTION
          raise ::JWT::IncorrectAlgorithm, 'Only alg=dir and enc=A256GCM are supported'
        end
      end

      def decode_segment(segment, allow_empty: false)
        unless segment.match?(BASE64URL_PATTERN) && (allow_empty || !segment.empty?)
          raise ::JWT::Base64DecodeError, 'Invalid base64url encoding'
        end

        ::JWT::Base64.url_decode(segment)
      end

      def encode_segment(segment)
        ::JWT::Base64.url_encode(segment)
      end

      def encoded_protected_header
        @encoded_protected_header ||= encode_segment(::JWT::JSON.generate(alg: ALGORITHM, enc: ENCRYPTION))
      end
    end
  end
end
