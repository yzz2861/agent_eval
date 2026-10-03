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
        raise_sign_error!("The given key is a #{signing_key.class}. It has to be an OpenSSL::PKey::RSA instance") unless signing_key.is_a?(OpenSSL::PKey::RSA)
        raise_sign_error!('The given key is not a private key') unless signing_key.private?
        raise_sign_error!('The key length must be greater than or equal to 2048 bits') if signing_key.n.num_bits < 2048

        signing_key.sign(OpenSSL::Digest.new(digest), data)
      end

      def verify(data:, signature:, verification_key:)
        raise_verify_error!("The given key is a #{verification_key.class}. It has to be an OpenSSL::PKey::RSA instance") unless verification_key.is_a?(::OpenSSL::PKey::RSA)

        verification_key.verify(OpenSSL::Digest.new(digest), signature, data)
      rescue OpenSSL::PKey::PKeyError
        raise JWT::VerificationError, 'Signature verification raised'
      end

      def sign_stream(encoded_header:, payload_stream:, signing_key:)
        raise_sign_error!("The given key is a #{signing_key.class}. It has to be an OpenSSL::PKey::RSA instance") unless signing_key.is_a?(OpenSSL::PKey::RSA)
        raise_sign_error!('The given key is not a private key') unless signing_key.private?
        raise_sign_error!('The key length must be greater than or equal to 2048 bits') if signing_key.n.num_bits < 2048

        digest_instance = digest_for_stream(encoded_header, payload_stream)
        signing_key.private_encrypt(digest_info(digest_instance), OpenSSL::PKey::RSA::PKCS1_PADDING)
      rescue OpenSSL::PKey::PKeyError => e
        raise_sign_error!(e.message)
      end

      def verify_stream(encoded_header:, payload_stream:, signature:, verification_key:)
        raise_verify_error!("The given key is a #{verification_key.class}. It has to be an OpenSSL::PKey::RSA instance") unless verification_key.is_a?(::OpenSSL::PKey::RSA)

        digest_instance = digest_for_stream(encoded_header, payload_stream)
        encoded_digest_info = verification_key.public_decrypt(signature, OpenSSL::PKey::RSA::PKCS1_PADDING)
        expected_digest_info = digest_info(digest_instance)
        secure_compare(encoded_digest_info, expected_digest_info)
      rescue OpenSSL::PKey::PKeyError
        raise JWT::VerificationError, 'Signature verification raised'
      end

      register_algorithm(new('RS256'))
      register_algorithm(new('RS384'))
      register_algorithm(new('RS512'))

      private

      attr_reader :digest

      def digest_for_stream(encoded_header, payload_stream)
        OpenSSL::Digest.new(digest).tap do |digest_instance|
          payload_stream.each_signing_chunk(encoded_header) { |chunk| digest_instance.update(chunk) }
        end
      end

      def digest_info(digest_instance)
        DIGEST_INFO_PREFIXES.fetch(digest) + digest_instance.digest
      end

      def secure_compare(actual, expected)
        return false unless actual.bytesize == expected.bytesize

        result = 0
        actual.each_byte.with_index { |byte, index| result |= byte ^ expected.getbyte(index) }
        result.zero?
      end

      DIGEST_INFO_PREFIXES = {
        'SHA256' => ['3031300d060960864801650304020105000420'].pack('H*'),
        'SHA384' => ['3041300d060960864801650304020205000430'].pack('H*'),
        'SHA512' => ['3051300d060960864801650304020305000440'].pack('H*')
      }.freeze
    end
  end
end
