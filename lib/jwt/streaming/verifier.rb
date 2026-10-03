# frozen_string_literal: true

require_relative 'body_reader'
require_relative 'base64url_encoder'
require_relative 'stats'
require_relative 'result'

module JWT
  module Streaming
    # Verifies a detached JWS against a body read incrementally.
    # @api private
    class Verifier
      def initialize(jws:, algorithms:, keys:, chunk_size:)
        @algorithms = Array(algorithms)
        @keys = keys
        @chunk_size = chunk_size

        @encoded_header, _encoded_payload, encoded_signature = parse(jws)
        @header = decode_header
        @signature = ::JWT::Base64.url_decode(encoded_signature || '')
      end

      attr_reader :header

      def call(body_io)
        validate_header!

        verifiers = build_verifiers
        stats = Stats.new
        reader = BodyReader.new(body_io, chunk_size: @chunk_size, stats: stats)
        encoder = unencoded_payload? ? nil : Base64urlEncoder.new

        feed(verifiers, reader, encoder)

        VerifyResult.new(valid: verifiers.any?(&:valid?), header: @header, stats: stats)
      end

      private

      def unencoded_payload?
        @header['b64'] == false
      end

      def feed(verifiers, reader, encoder)
        update_all(verifiers, @encoded_header)
        update_all(verifiers, '.')

        reader.each do |chunk|
          piece = unencoded_payload? ? chunk : encoder.encode(chunk)
          update_all(verifiers, piece)
        end

        update_all(verifiers, encoder.finish) unless unencoded_payload?
      end

      def update_all(verifiers, piece)
        verifiers.each { |verifier| verifier.update(piece) }
      end

      def parse(jws)
        segments = jws.to_s.split('.', -1)
        unless segments.length == 3 && segments[1] == ''
          raise JWT::MalformedTokenError, 'A detached JWS must have the form header..signature'
        end

        segments
      end

      def decode_header
        header = JWT::JSON.parse(::JWT::Base64.url_decode(@encoded_header))
        raise JWT::MalformedTokenError, 'Token header not a JSON object' unless header.is_a?(Hash)

        header
      rescue ::JSON::ParserError
        raise JWT::MalformedTokenError, 'Invalid segment encoding'
      end

      def validate_header!
        raise JWT::IncorrectAlgorithm, 'Token is missing alg header' unless @header['alg']
        raise JWT::IncorrectAlgorithm, 'Expected a different algorithm' unless allowed_jwas.any? { |jwa| jwa.valid_alg?(@header['alg']) }

        if @header['b64'] == false && !Array(@header['crit']).include?('b64')
          raise JWT::InvalidCritError, "The 'b64' header parameter must be included in the 'crit' header parameter list"
        end
      end

      def build_verifiers
        jwa = header_jwa
        jwk_keys, other_keys = @keys.partition { |key| key.is_a?(JWK::KeyBase) }

        jwk_keys.each do |jwk|
          JWA.validate_jwk_algorithms!([jwk], [@header['alg']], VerificationKeyError)
        end

        jwk_keys.map { |jwk| jwk.stream_verifier(signature: @signature) }
               .concat(other_keys.map { |key| jwa.stream_verifier(verification_key: key, signature: @signature) })
      end

      def allowed_jwas
        @allowed_jwas ||= @algorithms.map { |algorithm| JWA.resolve(algorithm) }
      end

      def header_jwa
        JWA.resolve(@header['alg'])
      end
    end
  end
end
