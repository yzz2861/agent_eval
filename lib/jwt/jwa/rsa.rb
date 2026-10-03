# frozen_string_literal: true

module JWT
  module JWA
    # Implementation of the RSA family of algorithms
    class Rsa
      include JWT::JWA::SigningAlgorithm

      def initialize(alg)
        @alg = alg
        @digest = alg.sub('RS', 'SHA')
      end

      def sign(data:, signing_key:)
        validate_signing_key!(signing_key)

        signing_key.sign(OpenSSL::Digest.new(digest), data)
      end

      def verify(data:, signature:, verification_key:)
        validate_verification_key!(verification_key)

        verification_key.verify(OpenSSL::Digest.new(digest), signature, data)
      rescue OpenSSL::PKey::PKeyError
        raise JWT::VerificationError, 'Signature verification raised'
      end

      # @api private
      def stream_signer(signing_key:)
        validate_signing_key!(signing_key)

        StreamSigner.new(key: signing_key, digest_name: digest)
      end

      # @api private
      def stream_verifier(signature:, verification_key:)
        validate_verification_key!(verification_key)

        StreamVerifier.new(key: verification_key, digest_name: digest, signature: signature)
      end

      register_algorithm(new('RS256'))
      register_algorithm(new('RS384'))
      register_algorithm(new('RS512'))

      private

      attr_reader :digest

      def validate_signing_key!(key)
        raise_sign_error!("The given key is a #{key.class}. It has to be an OpenSSL::PKey::RSA instance") unless key.is_a?(OpenSSL::PKey::RSA)
        raise_sign_error!('The given key is not a private key') unless key.private?
        raise_sign_error!('The key length must be greater than or equal to 2048 bits') if key.n.num_bits < 2048
      end

      def validate_verification_key!(key)
        raise_verify_error!("The given key is a #{key.class}. It has to be an OpenSSL::PKey::RSA instance") unless key.is_a?(::OpenSSL::PKey::RSA)
      end

      # PKCS#1 v1.5 DigestInfo prefixes (RFC 8017 Section 9.2 note 1), used
      # only when the OpenSSL bindings do not expose sign_raw/verify_raw.
      DIGEST_INFO_PREFIXES = {
        'SHA256' => "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20".b.freeze,
        'SHA384' => "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30".b.freeze,
        'SHA512' => "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40".b.freeze
      }.freeze

      # @api private
      module Pkcs1
        module_function

        def sign(key, digest_name, hashed_data)
          key.private_encrypt(encode(digest_name, hashed_data, key), OpenSSL::PKey::RSA::NO_PADDING)
        end

        def valid?(key, digest_name, signature, hashed_data)
          em = key.public_decrypt(signature, OpenSSL::PKey::RSA::NO_PADDING)
          encode(digest_name, hashed_data, key) == em
        rescue OpenSSL::PKey::PKeyError
          false
        end

        def encode(digest_name, hashed_data, key)
          prefix = DIGEST_INFO_PREFIXES.fetch(digest_name)
          k = key.n.num_bytes
          padding_length = k - prefix.bytesize - hashed_data.bytesize - 3
          "\x00\x01#{"\xff".b * padding_length}\x00".b + prefix + hashed_data
        end
      end

      # Incremental RSASSA-PKCS1-v1_5 signer. The digest is updated with each
      # chunk and the hash is signed once, so the body is never buffered.
      # @api private
      class StreamSigner
        def initialize(key:, digest_name:)
          @key = key
          @digest = OpenSSL::Digest.new(digest_name)
          @digest_name = digest_name
        end

        def update(chunk)
          @digest.update(chunk)
          self
        end

        def sign
          hashed_data = @digest.digest
          if @key.respond_to?(:sign_raw)
            @key.sign_raw(@digest_name, hashed_data)
          else
            # :nocov: sign_raw is provided by modern ruby/openssl builds
            Pkcs1.sign(@key, @digest_name, hashed_data)
            # :nocov:
          end
        end
      end

      # Incremental RSASSA-PKCS1-v1_5 verifier.
      # @api private
      class StreamVerifier
        def initialize(key:, digest_name:, signature:)
          @key = key
          @digest = OpenSSL::Digest.new(digest_name)
          @digest_name = digest_name
          @signature = signature
        end

        def update(chunk)
          @digest.update(chunk)
          self
        end

        def valid?
          hashed_data = @digest.digest
          if @key.respond_to?(:verify_raw)
            @key.verify_raw(@digest_name, @signature, hashed_data)
          else
            # :nocov: verify_raw is provided by modern ruby/openssl builds
            Pkcs1.valid?(@key, @digest_name, @signature, hashed_data)
            # :nocov:
          end
        rescue OpenSSL::PKey::PKeyError
          raise JWT::VerificationError, 'Signature verification raised'
        end
      end
    end
  end
end
