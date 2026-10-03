# frozen_string_literal: true

require_relative 'streaming/stats'
require_relative 'streaming/body_reader'
require_relative 'streaming/base64url_encoder'
require_relative 'streaming/result'
require_relative 'streaming/signer'
require_relative 'streaming/verifier'

module JWT
  # Streaming creation and verification of detached JWS signatures (RFC 7515
  # Appendix F). The body is read from an object responding to `read(length)`
  # in fixed-size chunks, so arbitrarily large bodies are signed and verified
  # without being loaded into memory.
  #
  # Two payload forms are supported:
  #
  # * the normal JWS/JWT base64url encoded payload (the default, `b64: true`);
  # * the unencoded payload form of RFC 7797 (`b64: false`), where the raw body
  #   bytes are signed directly.
  module Streaming
    DEFAULT_CHUNK_SIZE = 4096

    module_function

    # Signs a streaming body and returns the compact detached JWS.
    #
    # The encoded payload is never returned as one string. With `b64: true`
    # provide `payload_io:` (an object responding to `#write`) or a block; the
    # base64url payload is streamed there chunk by chunk as it is hashed.
    #
    # @param body_io [#read] the raw payload bytes, read in chunks.
    # @param key [String, OpenSSL::PKey, JWT::JWK::KeyBase] the signing key.
    # @param algorithm [String] the JWA algorithm name, e.g. `'HS256'` or `'RS256'`.
    # @param b64 [Boolean] `true` (default) for a base64url payload, `false` for
    #   the RFC 7797 unencoded payload form.
    # @param headers [Hash, nil] additional JWS header fields.
    # @param payload_io [#write, nil] receiver for the encoded payload chunks (`b64: true`).
    # @param chunk_size [Integer] maximum bytes read per `#read` call.
    # @yield [encoded_chunk] each encoded payload chunk when no `payload_io` is given (`b64: true`).
    # @return [SignResult] the detached JWS, header, signature and read statistics.
    # @raise [JWT::StreamingNotSupported] if the algorithm cannot sign incrementally.
    # @raise [JWT::StreamReadError] if reading from `body_io` fails.
    def sign(body_io, key:, algorithm: 'HS256', b64: true, headers: nil, payload_io: nil, chunk_size: DEFAULT_CHUNK_SIZE, &block)
      validate_body_io!(body_io)
      raise ArgumentError, 'Provide either payload_io or a block, not both' if payload_io && block

      sink = payload_io || block
      raise ArgumentError, 'payload_io must respond to #write' if b64 && payload_io && !payload_io.respond_to?(:write)

      Signer.new(
        algorithm: algorithm,
        key: key,
        b64: b64,
        headers: headers,
        chunk_size: chunk_size
      ).call(body_io, sink)
    end

    # Verifies a detached JWS against a streaming body.
    #
    # @param jws [String] the compact detached JWS (`header..signature`).
    # @param body_io [#read] the raw payload bytes, read in chunks.
    # @param key [Object, Array<Object>] verification key(s).
    # @param algorithm [String, Array<String>] allowed algorithm(s).
    # @param chunk_size [Integer] maximum bytes read per `#read` call.
    # @return [VerifyResult] result carrying `#valid?`, the header and read statistics.
    # @raise [JWT::StreamingNotSupported] if the algorithm cannot verify incrementally.
    # @raise [JWT::StreamReadError] if reading from `body_io` fails.
    def verify(jws, body_io, key:, algorithm: 'HS256', chunk_size: DEFAULT_CHUNK_SIZE)
      validate_body_io!(body_io)

      verifier_for(jws: jws, algorithms: Array(algorithm), keys: Array(key), chunk_size: chunk_size).call(body_io)
    end

    # Bang variant of {.verify} that raises instead of returning an invalid result.
    #
    # @return [VerifyResult] when the signature is valid.
    # @raise [JWT::VerificationError] if the signature does not verify.
    def verify!(jws, body_io, key:, algorithm: 'HS256', chunk_size: DEFAULT_CHUNK_SIZE)
      result = verify(jws, body_io, key: key, algorithm: algorithm, chunk_size: chunk_size)
      raise JWT::VerificationError, 'Signature verification failed' unless result.valid?

      result
    end

    # @api private
    def verifier_for(jws:, algorithms:, keys:, chunk_size:)
      Verifier.new(jws: jws, algorithms: algorithms, keys: keys, chunk_size: chunk_size)
    end

    # @api private
    def validate_body_io!(body_io)
      raise ArgumentError, 'Streaming body must respond to #read' unless body_io.respond_to?(:read)
    end
  end
end
