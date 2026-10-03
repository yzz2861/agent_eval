# frozen_string_literal: true

require 'openssl'
require 'securerandom'

module JWT
  module JWE
    # Compact serialization for JWE tokens using `alg=dir` and `enc=A256GCM`.
    class Compact
      ALGORITHM = 'dir'
      ENCRYPTION = 'A256GCM'
      CIPHER = 'aes-256-gcm'
      KEY_LENGTH = 32
      IV_LENGTH = 12
      TAG_LENGTH = 16
      SEGMENT_COUNT = 5

      private_constant :ENCRYPTION, :CIPHER, :KEY_LENGTH, :IV_LENGTH, :TAG_LENGTH, :SEGMENT_COUNT

      class << self
        def encrypt(payload:, key:, headers: {}, iv_generator: SecureRandom)
          new(payload: payload, key: key, headers: headers, iv_generator: iv_generator).encrypt
        end

        def decrypt(jwe:, key:)
          new(jwe: jwe, key: key).decrypt
        end
      end

      def initialize(payload: nil, key:, headers: {}, iv_generator: SecureRandom, jwe: nil)
        @payload = payload
        @key = key
        @headers = headers || {}
        @iv_generator = iv_generator
        @jwe = jwe
      end

      def encrypt
        validate_encrypt_arguments!

        encoded_header = encode_header
        iv = generate_iv
        ciphertext, tag = encrypt_payload(encoded_header, iv)

        [
          encoded_header,
          '',
          ::JWT::Base64.url_encode(iv),
          ::JWT::Base64.url_encode(ciphertext),
          ::JWT::Base64.url_encode(tag)
        ].join('.')
      end

      def decrypt
        validate_decrypt_arguments!
        encoded_header, encoded_key, encoded_iv, encoded_ciphertext, encoded_tag = segments

        unless encoded_key.empty?
          raise JWT::MalformedTokenError, 'Encrypted key must be empty for dir algorithm'
        end

        header = decode_header(encoded_header)
        validate_header!(header)

        iv = decode_segment(encoded_iv, 'IV')
        ciphertext = decode_segment(encoded_ciphertext, 'Ciphertext', allow_empty: true)
        tag = decode_segment(encoded_tag, 'Authentication tag')

        validate_decoded_segments!(iv, tag)
        decrypt_payload(encoded_header, iv, ciphertext, tag)
      end

      private

      def validate_encrypt_arguments!
        validate_encryption_key!(@key)
        raise JWT::EncodeError, 'Payload must be a String' unless @payload.is_a?(::String)
        raise JWT::EncodeError, 'Headers must be a Hash' unless @headers.is_a?(::Hash)

        normalized_headers.each_key do |name|
          if name == 'alg' || name == 'enc'
            raise JWT::EncodeError, "Header #{name} is reserved"
          end
          raise JWT::EncodeError, 'Compression is not supported' if name == 'zip'
        end
      end

      def validate_decrypt_arguments!
        raise JWT::MalformedTokenError, 'Nil JWE token' unless @jwe
        raise JWT::MalformedTokenError, 'JWE token must be a String' unless @jwe.is_a?(::String)
        raise JWT::MalformedTokenError, 'Not enough or too many segments' unless segments.length == SEGMENT_COUNT

        validate_decryption_key!(@key)
      end

      def validate_encryption_key!(key)
        return if valid_key?(key)

        raise JWT::EncodeError, 'Key must be a 32-byte String'
      end

      def validate_decryption_key!(key)
        return if valid_key?(key)

        raise JWT::VerificationKeyError, 'Key must be a 32-byte String'
      end

      def valid_key?(key)
        key.is_a?(::String) && key.bytesize == KEY_LENGTH
      end

      def normalized_headers
        @normalized_headers ||= @headers.transform_keys(&:to_s)
      end

      def encode_header
        header = { 'alg' => ALGORITHM, 'enc' => ENCRYPTION }.merge(normalized_headers)
        ::JWT::Base64.url_encode(::JWT::JSON.generate(header))
      end

      def generate_iv
        unless @iv_generator.respond_to?(:random_bytes)
          raise JWT::EncodeError, 'IV generator must respond to random_bytes'
        end

        iv = @iv_generator.random_bytes(IV_LENGTH)
        return iv if iv.is_a?(::String) && iv.bytesize == IV_LENGTH

        raise JWT::EncodeError, 'IV generator must return a 12-byte String'
      end

      def encrypt_payload(encoded_header, iv)
        cipher = ::OpenSSL::Cipher.new(CIPHER)
        cipher.encrypt
        cipher.key = @key
        cipher.iv = iv
        cipher.auth_data = encoded_header

        ciphertext = cipher.update(@payload)
        ciphertext << cipher.final

        [ciphertext, cipher.auth_tag(TAG_LENGTH)]
      end

      def segments
        @segments ||= @jwe.split('.', -1)
      end

      def decode_header(encoded_header)
        if encoded_header.empty?
          raise JWT::MalformedTokenError, 'Protected header is empty'
        end

        raw_header = ::JWT::Base64.url_decode(encoded_header)
        ::JWT::JSON.parse(raw_header, object_class: StrictHeaderHash)
      rescue ::JSON::ParserError, ::EncodingError
        raise JWT::MalformedTokenError, 'Invalid protected header'
      end

      def validate_header!(header)
        raise JWT::MalformedTokenError, 'Protected header must be a JSON object' unless header.is_a?(::Hash)
        raise JWT::IncorrectAlgorithm, 'Expected alg to be dir' unless header['alg'] == ALGORITHM
        raise JWT::IncorrectAlgorithm, 'Expected enc to be A256GCM' unless header['enc'] == ENCRYPTION
        if header.key?('zip') || Array(header['crit']).include?('zip')
          raise JWT::MalformedTokenError, 'Compression is not supported'
        end
      end

      def decode_segment(segment, name, allow_empty: false)
        if !allow_empty && segment.empty?
          raise JWT::MalformedTokenError, "#{name} is empty"
        end

        ::JWT::Base64.url_decode(segment)
      end

      def validate_decoded_segments!(iv, tag)
        raise JWT::MalformedTokenError, 'IV must be 12 bytes' unless iv.bytesize == IV_LENGTH
        raise JWT::MalformedTokenError, 'Authentication tag must be 16 bytes' unless tag.bytesize == TAG_LENGTH
      end

      def decrypt_payload(encoded_header, iv, ciphertext, tag)
        cipher = ::OpenSSL::Cipher.new(CIPHER)
        cipher.decrypt
        cipher.key = @key
        cipher.iv = iv
        cipher.auth_tag = tag
        cipher.auth_data = encoded_header

        plaintext = cipher.update(ciphertext)
        plaintext << cipher.final
        plaintext
      rescue ::OpenSSL::Cipher::CipherError
        raise JWT::VerificationError, 'JWE authentication failed'
      end

      class StrictHeaderHash < ::Hash
        def []=(key, value)
          raise ::JSON::ParserError, 'Duplicate member in protected header' if key?(key)

          super
        end
      end

      private_constant :StrictHeaderHash
    end
  end
end
