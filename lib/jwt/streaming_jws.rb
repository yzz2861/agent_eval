# frozen_string_literal: true

require 'stringio'
require_relative 'base64'
require_relative 'error'
require_relative 'jwa'
require_relative 'json'

module JWT
  # Signs and verifies JWS payloads without loading the payload into memory.
  class StreamingJWS
    Stats = Struct.new(:bytes_read, :read_count, :max_read_length, keyword_init: true)
    Result = Struct.new(:jws, :stats, keyword_init: true) do
      def to_s
        jws
      end
    end

    DEFAULT_CHUNK_SIZE = 16 * 1024
    SUPPORTED_ALGORITHMS = %w[HS256 RS256].freeze

    private_constant(:DEFAULT_CHUNK_SIZE)

    class << self
      # Creates a detached JWS signature for a readable payload.
      #
      # The payload is encoded and written to +payload_output+ when +base64_payload+
      # is true. The returned compact JWS always has an empty payload segment.
      def sign(payload_io, key:, algorithm:, headers: nil, base64_payload: nil, chunk_size: DEFAULT_CHUNK_SIZE, payload_output: nil)
        validate_single_key!(key)
        jwa, signer = signer_for(key: key, algorithm: algorithm, error_class: EncodeError)
        header = prepared_header(headers: headers, algorithm: jwa.alg, base64_payload: base64_payload)
        base64_payload = header['b64'] != false
        encoded_header = Base64.url_encode(JSON.generate(header))
        stream = PayloadStream.new(
          payload_io,
          chunk_size: chunk_size,
          base64_payload: base64_payload,
          output_io: payload_output
        )
        signature = signer.sign_stream(encoded_header: encoded_header, payload_stream: stream)

        jws = [encoded_header, '', Base64.url_encode(signature)].join('.')

        Result.new(jws: jws, stats: stream.stats.dup)
      end

      # Verifies a detached JWS signature and returns read statistics.
      def verify(jws, payload_io, key:, algorithm: nil, chunk_size: DEFAULT_CHUNK_SIZE)
        validate_single_key!(key)
        encoded_header, encoded_signature, header = parse_jws(jws)
        algorithm ||= header['alg']
        raise IncorrectAlgorithm, 'Token is missing alg header' if algorithm.nil?
        jwa, verifier = verifier_for(key: key, algorithm: algorithm, preferred_algorithm: header['alg'])
        raise IncorrectAlgorithm, 'Expected a different algorithm' unless jwa.valid_alg?(header['alg'])

        signature = Base64.url_decode(encoded_signature)
        stream = PayloadStream.new(
          payload_io,
          chunk_size: chunk_size,
          base64_payload: header['b64'] != false
        )
        verified = verifier.verify_stream(
          encoded_header: encoded_header,
          payload_stream: stream,
          signature: signature
        )
        raise VerificationError, 'Signature verification failed' unless verified

        stream.stats.dup
      end

      # Returns whether a detached JWS signature is valid without raising for a mismatch.
      def valid?(jws, payload_io, key:, algorithm: nil, chunk_size: DEFAULT_CHUNK_SIZE)
        verify(jws, payload_io, key: key, algorithm: algorithm, chunk_size: chunk_size)
        true
      rescue VerificationError => e
        raise if e.is_a?(VerificationKeyError)

        false
      end

      alias verify! verify

      private

      def supported_jwa(algorithm, error_class)
        jwa = JWA.resolve(algorithm)
        return jwa if SUPPORTED_ALGORITHMS.any? { |supported_algorithm| jwa.valid_alg?(supported_algorithm) }

        raise error_class, "Streaming JWS does not support algorithm #{algorithm}"
      end

      def validate_single_key!(key)
        return unless key.is_a?(Array)

        raise ArgumentError, 'Streaming JWS supports a single key because the payload may not be rewindable'
      end

      def signer_for(key:, algorithm:, error_class:)
        if key.is_a?(JWK::KeyBase)
          jwa = supported_jwa(key[:alg], error_class)
          JWA.validate_jwk_algorithms!([key], Array(algorithm), error_class)
          [jwa, key]
        else
          jwa = supported_jwa(algorithm, error_class)
          [jwa, JWA::SignerContext.new(jwa: jwa, key: key)]
        end
      end

      def verifier_for(key:, algorithm:, preferred_algorithm:)
        if key.is_a?(JWK::KeyBase)
          jwa = supported_jwa(key[:alg], VerificationKeyError)
          JWA.validate_jwk_algorithms!([key], Array(algorithm), VerificationKeyError)
          [jwa, key]
        else
          jwa = supported_jwa(algorithm || preferred_algorithm, IncorrectAlgorithm)
          [jwa, JWA::VerifierContext.new(jwa: jwa, keys: [key])]
        end
      end

      def prepared_header(headers:, algorithm:, base64_payload:)
        header = (headers || {}).transform_keys(&:to_s)
        raise EncodeError, 'The alg header does not match the signing algorithm' if header.key?('alg') && header['alg'] != algorithm

        base64_payload = header['b64'] != false if base64_payload.nil?
        if header.key?('b64') && ![true, false].include?(header['b64'])
          raise EncodeError, 'The b64 header must be a Boolean'
        end
        if header.key?('b64') && header['b64'] != base64_payload
          raise EncodeError, 'The b64 header does not match base64_payload'
        end
        if header.key?('crit') && !header['crit'].is_a?(Array)
          raise EncodeError, 'The crit header must be an Array'
        end

        header['alg'] = algorithm
        unless base64_payload
          header['b64'] = false
          header['crit'] = (Array(header['crit']).map(&:to_s) + ['b64']).uniq
        end

        header
      end

      def parse_jws(jws)
        raise MalformedTokenError, 'Provided JWS must be a String' unless jws.is_a?(String)

        parts = jws.split('.')
        raise MalformedTokenError, 'Not enough or too many segments' unless parts.size == 3
        raise MalformedTokenError, 'Streaming JWS only verifies detached payloads' unless parts[1] == ''
        raise MalformedTokenError, 'Encoded header is empty' if parts[0].empty?
        raise MalformedTokenError, 'Encoded signature is empty' if parts[2].empty?

        header = JSON.parse(Base64.url_decode(parts[0]))
        raise MalformedTokenError, 'JWS header not a JSON object' unless header.is_a?(Hash)
        if header.key?('b64') && ![true, false].include?(header['b64'])
          raise MalformedTokenError, 'The b64 header must be a Boolean'
        end
        if header.key?('crit') && !header['crit'].is_a?(Array)
          raise MalformedTokenError, 'The crit header must be an Array'
        end
        if header['b64'] == false && !Array(header['crit']).include?('b64')
          raise MalformedTokenError, "The crit header must include 'b64' when b64 is false"
        end

        [parts[0], parts[2], header]
      rescue ::JSON::ParserError
        raise MalformedTokenError, 'Invalid segment encoding'
      end
    end

    # @api private
    class PayloadStream
      attr_reader :stats

      def initialize(payload_io, chunk_size:, base64_payload:, output_io: nil)
        raise ArgumentError, 'Payload must respond to read' unless payload_io.respond_to?(:read)
        raise ArgumentError, 'Chunk size must be a positive integer' unless chunk_size.is_a?(Integer) && chunk_size > 0
        raise ArgumentError, 'Payload output must respond to write' if output_io && !output_io.respond_to?(:write)

        @payload_io = payload_io
        @chunk_size = chunk_size
        @base64_payload = base64_payload
        @output_io = output_io
        @output_io.set_encoding(Encoding::BINARY) if @output_io.is_a?(::StringIO)
        @encoder = Base64UrlEncoder.new
        @stats = Stats.new(bytes_read: 0, read_count: 0, max_read_length: 0)
      end

      def each_signing_chunk(encoded_header)
        yield String.new("#{encoded_header}.")

        read_payload do |read_chunk|
          chunk = read_chunk.b
          if @base64_payload
            encoded_chunk = @encoder.encode(chunk)
            write_output(encoded_chunk)
            yield encoded_chunk
          else
            write_output(chunk)
            yield chunk
          end
        end

        if @base64_payload
          final_chunk = @encoder.finish
          write_output(final_chunk)
          yield final_chunk
        end

        self
      end

      private

      def read_payload
        loop do
          begin
            chunk = @payload_io.read(@chunk_size)
          rescue StandardError => e
            raise StreamingPayloadError, "Failed to read streaming payload: #{e.message}"
          end
          break if chunk.nil? || chunk.empty?
          raise StreamingPayloadError, 'Streaming payload read returned a non-String value' unless chunk.is_a?(String)

          @stats.bytes_read += chunk.bytesize
          @stats.read_count += 1
          @stats.max_read_length = chunk.bytesize if chunk.bytesize > @stats.max_read_length
          yield chunk
        end
      end

      def write_output(chunk)
        return unless @output_io

        @output_io.write(chunk)
      rescue StandardError => e
        raise StreamingPayloadError, "Failed to write streaming payload: #{e.message}"
      end
    end

    # @api private
    class Base64UrlEncoder
      def initialize
        @remainder = String.new
      end

      def encode(chunk)
        data = @remainder + chunk.b
        encoded_length = (data.bytesize / 3) * 3
        @remainder = data.byteslice(encoded_length, data.bytesize - encoded_length).to_s
        encode_full_chunk(data.byteslice(0, encoded_length).to_s)
      end

      def finish
        final_chunk = encode_full_chunk(@remainder)
        @remainder = String.new
        final_chunk
      end

      private

      def encode_full_chunk(chunk)
        return String.new if chunk.empty?

        ::Base64.urlsafe_encode64(chunk, padding: false)
      end
    end
  end
end
