# frozen_string_literal: true

require_relative 'jwe/compact'

module JWT
  # JSON Web Encryption support.
  module JWE
    module_function

    # Encrypts a plaintext String using compact JWE serialization.
    def encrypt(payload:, key:, headers: {}, iv_generator: SecureRandom)
      Compact.encrypt(
        payload: payload,
        key: key,
        headers: headers,
        iv_generator: iv_generator
      )
    end

    # Decrypts and authenticates a compact JWE token.
    def decrypt(jwe:, key:)
      Compact.decrypt(jwe: jwe, key: key)
    end
  end
end
