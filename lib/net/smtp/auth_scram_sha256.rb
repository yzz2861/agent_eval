require 'securerandom'

class Net::SMTP
  class AuthScramSHA256 < Net::SMTP::Authenticator
    auth_type :scram_sha_256

    MECHANISM = 'SCRAM-SHA-256'
    MIN_ITERATIONS = 4096
    MAX_ITERATIONS = 1_000_000
    CLIENT_NONCE_BYTES = 18

    class ScramError < StandardError; end

    def auth(user, secret)
      raise ScramError, 'OpenSSL is required for SCRAM-SHA-256' unless defined?(OpenSSL::Digest)

      @username = encode_username(user)
      @password = secret.to_s.dup.force_encoding(Encoding::UTF_8)
      @client_nonce ||= generate_client_nonce
      @client_first_bare = "n=#{@username},r=#{@client_nonce}"
      io = smtp.instance_variable_get(:@socket)
      saved_debug_output = io&.debug_output
      io&.debug_output = nil

      server_first = continue_payload("AUTH #{MECHANISM} " + base64_encode("n,,#{@client_first_bare}"))
      process_server_first(server_first)

      @client_final_without_proof = "c=biws,r=#{@server_nonce}"
      client_final = "#{@client_final_without_proof},p=#{base64_encode(client_proof)}"

      server_final = continue_payload(base64_encode(client_final))
      verify_server_final(server_final)
      finish('')
    rescue ScramError
      raise Net::SMTPAuthenticationError, 'SCRAM-SHA-256 authentication failed'
    rescue ::Net::ProtocolError
      raise
    ensure
      io&.debug_output = saved_debug_output
    end

    private

    def continue_payload(command)
      response = smtp.get_response(command)
      raise response.exception_class.new(response) unless response.continue?

      encoded = response.string.split[1]
      raise ScramError, 'missing SCRAM challenge' if encoded.nil?
      strict_base64_decode(encoded)
    end

    def generate_client_nonce
      SecureRandom.urlsafe_base64(CLIENT_NONCE_BYTES, false)
    end

    def process_server_first(message)
      attributes = parse_attributes(message, [%w[r s i]])
      @server_first_message = message

      @server_nonce = attributes['r']
      unless valid_nonce?(@server_nonce) && @server_nonce.start_with?(@client_nonce)
        raise ScramError, 'invalid server nonce'
      end

      @salt = strict_base64_decode(attributes['s'])
      raise ScramError, 'invalid salt' if @salt.empty?

      @iterations = parse_iterations(attributes['i'])
    end

    def verify_server_final(message)
      attributes = parse_attributes(message, [%w[v], %w[e]])
      raise ScramError, 'server rejected authentication' if attributes.key?('e')

      verifier = strict_base64_decode(attributes['v'])
      unless verifier.bytesize == digest.digest_length && secure_compare(verifier, server_signature)
        raise ScramError, 'invalid server signature'
      end
    end

    def parse_attributes(message, allowed_sequences)
      values = {}
      message.split(',', -1).each do |pair|
        match = /\A([A-Za-z])=([\x20-\x2b\x2d-\x7e]*)\z/.match(pair)
        raise ScramError, 'malformed SCRAM message' unless match
        raise ScramError, 'duplicate SCRAM attribute' if values.key?(match[1])
        values[match[1]] = match[2]
      end
      raise ScramError, 'unexpected SCRAM attributes' unless allowed_sequences.include?(values.keys)
      values
    end

    def parse_iterations(value)
      raise ScramError, 'invalid iteration count' unless /\A[1-9][0-9]{0,6}\z/.match?(value)

      iterations = Integer(value, 10)
      unless iterations >= MIN_ITERATIONS && iterations <= MAX_ITERATIONS
        raise ScramError, 'invalid iteration count'
      end
      iterations
    end

    def valid_nonce?(nonce)
      nonce.ascii_only? && !nonce.empty? && !nonce.include?(',')
    end

    def strict_base64_decode(value)
      pattern = /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/
      raise ScramError, 'invalid Base64' unless pattern.match?(value)
      value.unpack1('m0')
    end

    def encode_username(username)
      username.to_str.encode(Encoding::UTF_8).gsub(/[=,]/, '=' => '=3D', ',' => '=2C')
    rescue EncodingError
      raise ScramError, 'invalid username encoding'
    end

    def salted_password
      @salted_password ||= pbkdf2_sha256(@password, @salt, @iterations)
    end

    def client_key
      @client_key ||= hmac_sha256(salted_password, 'Client Key')
    end

    def stored_key
      OpenSSL::Digest.digest('SHA256', client_key)
    end

    def server_key
      @server_key ||= hmac_sha256(salted_password, 'Server Key')
    end

    def client_signature
      hmac_sha256(stored_key, auth_message)
    end

    def server_signature
      hmac_sha256(server_key, auth_message)
    end

    def client_proof
      xor(client_key, client_signature)
    end

    def auth_message
      [
        @client_first_bare,
        @server_first_message,
        @client_final_without_proof
      ].join(',')
    end

    def pbkdf2_sha256(password, salt, iterations)
      OpenSSL::PKCS5.pbkdf2_hmac(
        password,
        salt,
        iterations,
        OpenSSL::Digest.new('SHA256').digest_length,
        OpenSSL::Digest.new('SHA256')
      )
    end

    def hmac_sha256(key, data)
      OpenSSL::HMAC.digest(digest, key.b, data.to_s.dup.force_encoding(Encoding::BINARY))
    end

    def xor(left, right)
      left.bytes.zip(right.bytes).map { |left_byte, right_byte| left_byte ^ right_byte }.pack('C*')
    end

    def digest
      OpenSSL::Digest.new('SHA256')
    end

    def secure_compare(left, right)
      return false unless left.bytesize == right.bytesize

      difference = 0
      left.each_byte.with_index do |byte, index|
        difference |= byte ^ right.getbyte(index)
      end
      difference.zero?
    end
  end
end
