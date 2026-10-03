# frozen_string_literal: true

begin
  require 'openssl'
rescue LoadError
end
require 'securerandom'

class Net::SMTP
  class AuthScramSHA256 < Net::SMTP::Authenticator
    auth_type :scram_sha256
    Net::SMTP::Authenticator.auth_classes[:'SCRAM-SHA-256'] = self
    Net::SMTP::Authenticator.auth_classes.delete(:'SCRAM-SHA256')

    DIGEST_NAME = 'SHA256'
    DIGEST_LENGTH = 32
    MIN_ITERATIONS = 4096
    MAX_ITERATIONS = 1_000_000

    SCRAMError = Class.new(StandardError)

    SERVER_FIRST_ATTRIBUTES = %w[r s i].freeze
    SERVER_FINAL_ATTRIBUTES = %w[v].freeze
    NONCE_SANITIZED = /\A[!-~]+\z/.freeze
    ITERATION_SANITIZED = /\A[1-9][0-9]*\z/.freeze
    STRICT_BASE64 = /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/.freeze

    def auth(user, secret, cnonce: nil)
      raise '"openssl" library is required' unless defined?(OpenSSL::HMAC) && defined?(OpenSSL::Digest)

      client_nonce = cnonce || generate_client_nonce
      validate_client_nonce(client_nonce)
      normalized_secret = normalize_sasl_string(secret)

      client_first_message_bare = "n=#{saslname(user)},r=#{client_nonce}"
      client_first_message = "n,,#{client_first_message_bare}"

      begin
        challenge = continue("AUTH SCRAM-SHA-256 #{base64_encode(client_first_message)}")
        encoded_server_first = challenge if valid_base64_payload?(challenge)
        server_first_message = decode_message(encoded_server_first, 'server first message')
        server_first = parse_server_first(server_first_message, client_nonce)

        server_nonce = server_first['r']
        salt = decode_base64_attribute(server_first['s'], 'salt')
        iterations = parse_iterations(server_first['i'])

        client_final_without_proof = "c=#{base64_encode('n,,')},r=#{server_nonce}"
        auth_message = [
          client_first_message_bare,
          server_first_message,
          client_final_without_proof,
        ].join(',')

        salted_password = derive_salted_password(normalized_secret, salt, iterations)
        client_key = hmac(salted_password, 'Client Key')
        stored_key = digest(client_key)
        client_signature = hmac(stored_key, auth_message)
        client_proof = xor(client_key, client_signature)
        server_key = hmac(salted_password, 'Server Key')

        client_final_message = "#{client_final_without_proof},p=#{base64_encode(client_proof)}"
      rescue SCRAMError => error
        cancellation_acknowledged = cancel_authentication
        raise build_authentication_error(error, cancellation_acknowledged)
      end

      begin
        response = finish(base64_encode(client_final_message))
        encoded_server_final = response_payload(response, base64: true)
        server_final_message = decode_message(encoded_server_final, 'server final message')
        server_final = parse_server_final(server_final_message)
        server_signature = hmac(server_key, auth_message)
        received_server_signature = decode_base64_attribute(server_final['v'], 'server signature', DIGEST_LENGTH)

        unless secure_compare(received_server_signature, server_signature)
          raise SCRAMError, 'server signature verification failed'
        end

        response
      rescue SCRAMError => error
        raise build_authentication_error(error)
      end
    end

    private

    def generate_client_nonce
      SecureRandom.urlsafe_base64(DIGEST_LENGTH, false)
    end

    def validate_client_nonce(nonce)
      unless nonce.is_a?(String) && nonce.ascii_only? &&
             nonce.match?(NONCE_SANITIZED) && !nonce.include?(',')
        raise SCRAMError, 'invalid client nonce'
      end
    end

    def saslname(user)
      user = normalize_sasl_string(user)
      raise ArgumentError, 'user name contains a null byte' if user.include?("\0")
      user.gsub('=', '=3D').gsub(',', '=2C')
    end

    def normalize_sasl_string(string)
      string.encode(Encoding::UTF_8).unicode_normalize(:nfkc)
    end

    def parse_server_first(message, client_nonce)
      attributes = parse_attributes(message, SERVER_FIRST_ATTRIBUTES)
      server_nonce = attributes['r']

      unless server_nonce.start_with?(client_nonce) && server_nonce.length > client_nonce.length
        raise SCRAMError, 'server nonce does not include client nonce'
      end
      unless server_nonce.ascii_only? && server_nonce.match?(NONCE_SANITIZED) &&
             !server_nonce.include?(',')
        raise SCRAMError, 'invalid server nonce'
      end

      attributes
    end

    def parse_server_final(message)
      parse_attributes(message, SERVER_FINAL_ATTRIBUTES)
    end

    def parse_attributes(message, expected_attributes)
      pairs = message.split(',', -1)
      raise SCRAMError, 'invalid SCRAM attributes' unless pairs.size == expected_attributes.size

      pairs.each_with_index.with_object({}) do |(pair, index), attributes|
        key, value = pair.split('=', 2)
        unless key == expected_attributes[index] && !value.nil? && !value.empty?
          raise SCRAMError, 'invalid SCRAM attributes'
        end
        if attributes.key?(key)
          raise SCRAMError, 'duplicate SCRAM attribute'
        end
        attributes[key] = value
      end
    end

    def decode_message(encoded_message, name)
      raise SCRAMError, "missing #{name}" if encoded_message.nil? || encoded_message.empty?
      raise SCRAMError, "invalid Base64 encoding in #{name}" unless encoded_message.match?(STRICT_BASE64)
      decoded = encoded_message.unpack1('m0')
      raise SCRAMError, "invalid Base64 encoding in #{name}" unless valid_base64?(encoded_message, decoded)
      decoded
    end

    def decode_base64_attribute(value, name, expected_length = nil)
      decoded = strict_base64_decode(value)
      if expected_length && decoded.bytesize != expected_length
        raise SCRAMError, "invalid #{name} length"
      end
      raise SCRAMError, "empty #{name}" if decoded.empty?
      decoded
    end

    def strict_base64_decode(value)
      unless value.is_a?(String) && value.match?(STRICT_BASE64)
        raise SCRAMError, 'invalid Base64 encoding'
      end
      value.unpack1('m0')
    end

    def valid_base64?(encoded, decoded)
      encoded.match?(STRICT_BASE64) && base64_encode(decoded) == encoded
    end

    def valid_base64_payload?(payload)
      payload.is_a?(String) && super
    end

    def parse_iterations(value)
      unless value.match?(ITERATION_SANITIZED)
        raise SCRAMError, 'invalid iteration count'
      end

      iterations = Integer(value, 10)
      if iterations < MIN_ITERATIONS
        raise SCRAMError, "iteration count is too small: #{iterations}"
      end
      if iterations > MAX_ITERATIONS
        raise SCRAMError, "iteration count is too large: #{iterations}"
      end

      iterations
    end

    def derive_salted_password(password, salt, iterations)
      if defined?(OpenSSL::KDF)
        OpenSSL::KDF.pbkdf2_hmac(
          password,
          salt: salt,
          iterations: iterations,
          length: DIGEST_LENGTH,
          hash: OpenSSL::Digest.new(DIGEST_NAME),
        )
      else
        pbkdf2_hmac(password, salt, iterations)
      end
    end

    def pbkdf2_hmac(password, salt, iterations)
      block = hmac(password, salt + [1].pack('N'))
      result = block.dup
      (iterations - 1).times do
        block = hmac(password, block)
        result = xor(result, block)
      end
      result
    end

    def digest(data)
      OpenSSL::Digest.digest(DIGEST_NAME, data)
    end

    def hmac(key, data)
      OpenSSL::HMAC.digest(DIGEST_NAME, key, data)
    end

    def xor(left, right)
      left.bytes.zip(right.bytes).map { |left_byte, right_byte| left_byte ^ right_byte }.pack('C*')
    end

    def secure_compare(left, right)
      return false unless left.bytesize == right.bytesize

      if OpenSSL.respond_to?(:fixed_length_secure_compare)
        OpenSSL.fixed_length_secure_compare(left, right)
      else
        left.each_byte.zip(right.each_byte).inject(0) do |result, (left_byte, right_byte)|
          result | (left_byte ^ right_byte)
        end.zero?
      end
    end

    def cancel_authentication
      res = smtp.get_response('*')
      res.success?
    rescue StandardError
      false
    end

    def build_authentication_error(error, cancellation_acknowledged = false)
      message = 'SCRAM-SHA-256 authentication failed: ' \
        "#{error.message}"
      if cancellation_acknowledged
        message << ' (authentication cancellation unexpectedly acknowledged as success)'
      end
      Net::SMTPAuthenticationError.new(message)
    end
  end
end
