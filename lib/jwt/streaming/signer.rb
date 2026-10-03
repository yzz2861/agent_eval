# frozen_string_literal: true

require_relative 'body_reader'
require_relative 'base64url_encoder'
require_relative 'stats'
require_relative 'result'

module JWT
  module Streaming
    # Builds a detached JWS signature by reading the body incrementally.
    # @api private
    class Signer
      def initialize(algorithm:, key:, b64:, headers: nil, chunk_size:)
        @algorithm = algorithm
        @key = key
        @b64 = b64
        @headers = headers
        @chunk_size = chunk_size
      end

      def call(body_io, sink)
        validate_sink!(sink)

        header = build_header
        encoded_header = ::JWT::Base64.url_encode(JWT::JSON.generate(header))
        stream = JWA.create_stream_signer(algorithm: header['alg'], key: @key)

        stats = Stats.new
        encoder = Base64urlEncoder.new if @b64
        reader = BodyReader.new(body_io, chunk_size: @chunk_size, stats: stats)

        stream.update(encoded_header)
        stream.update('.')
        feed(reader, stream, encoder, sink)

        SignResult.new(header: header, encoded_header: encoded_header,
                       signature: stream.sign, stats: stats)
      end

      private

      def validate_sink!(sink)
        return if @b64
        return if sink.nil?

        raise ArgumentError, 'A payload sink can only be given for the base64url encoded payload (b64: true)'
      end

      def feed(reader, stream, encoder, sink)
        reader.each do |chunk|
          piece = @b64 ? encoder.encode(chunk) : chunk
          stream.update(piece)
          emit(sink, piece) if @b64
        end

        return unless @b64

        final_chunk = encoder.finish
        stream.update(final_chunk)
        emit(sink, final_chunk)
      end

      def emit(sink, chunk)
        return if sink.nil?

        sink.respond_to?(:write) ? sink.write(chunk) : sink.call(chunk)
      end

      def build_header
        header = (@headers || {}).transform_keys(&:to_s)
        header['alg'] = @algorithm unless header.key?('alg')
        return header if @b64

        if header.key?('b64') && header['b64'] != false
          raise ArgumentError, "Header 'b64' must be false when signing with b64: false, got #{header['b64'].inspect}"
        end

        header['b64'] = false
        crit = header['crit']
        crit = [] unless crit.is_a?(Array)
        header['crit'] = crit.include?('b64') ? crit : (crit + ['b64'])
        header
      end
    end
  end
end
