# frozen_string_literal: true

require 'faraday/grpc_web'

module Faraday
  class Request
    # Encodes and decodes lightweight unary gRPC-Web requests and responses.
    class GRPCWeb < Middleware
      DEFAULT_OPTIONS = {
        mode: :binary,
        max_frame_size: Faraday::GRPCWeb::DEFAULT_MAX_FRAME_SIZE
      }.freeze

      def initialize(app = nil, options = nil, **kwargs)
        super(app, (options || {}).merge(kwargs))

        @mode = @options.fetch(:mode).to_sym
        @max_frame_size = @options.fetch(:max_frame_size)
        validate_options!
      end

      # @return [:binary, :text] configured wire encoding.
      attr_reader :mode

      # @return [Integer] configured maximum frame payload size.
      attr_reader :max_frame_size

      def on_request(env)
        env.method = :post
        message = env.body.nil? ? +'' : env.body
        unless message.respond_to?(:to_str)
          raise ArgumentError, 'gRPC-Web request body must be an encoded protobuf String'
        end

        env.body = Faraday::GRPCWeb.encode_request(
          message,
          mode: @mode,
          max_frame_size: @max_frame_size
        )
        env.request_headers[CONTENT_TYPE] = content_type
        env.request_headers['Accept'] = content_type
        env.request_headers['x-grpc-web'] = '1'
      end

      def on_complete(env)
        raise_http_error!(env) unless env.status == 200

        verify_content_type!(env)
        result = decode_response(env)

        env.body = result.data? ? result.data : nil
        trailers = merge_trailers(env, result)
        code = extract_status!(env, result, trailers)
        decode_status_message!(env, trailers)

        if code.zero?
          raise_missing_data!(env) unless result.data?
          return
        end

        message = trailers['grpc-message'] || env.response_headers['grpc-message']
        formatted_message = message.nil? || message.empty? ? "status #{code}" : message
        raise Faraday::GRPCWeb::StatusError.new(
          "gRPC error #{code}: #{formatted_message}",
          env.response,
          code,
          trailers
        )
      end

      private

      def content_type
        Faraday::GRPCWeb.content_type(@mode)
      end

      def validate_options!
        unless %i[binary text].include?(@mode)
          raise ArgumentError, "unknown gRPC-Web mode: #{@mode.inspect}"
        end
        unless @max_frame_size.is_a?(Integer) && @max_frame_size.positive?
          raise ArgumentError, 'max_frame_size must be a positive Integer'
        end
      end

      def raise_http_error!(env)
        raise Faraday::GRPCWeb::HTTPError.new(
          "gRPC-Web request failed with HTTP status #{env.status}",
          env.response
        )
      end

      def decode_response(env)
        Faraday::GRPCWeb.decode_response(
          env.body,
          mode: @mode,
          max_frame_size: @max_frame_size
        )
      end

      def merge_trailers(env, result)
        trailers = result.trailers || {}
        env.response_headers.update(trailers)
        env[:grpc_web_trailers] = trailers
        trailers
      end

      def extract_status!(env, result, trailers)
        if result.data? && !result.trailers?
          raise Faraday::GRPCWeb::ProtocolError.new(
            'gRPC-Web unary response is missing its trailer frame',
            env.response
          )
        end

        raw_status = trailers['grpc-status'] || env.response_headers['grpc-status']
        status = raw_status.to_s.strip
        return status.to_i if status.match?(/\A[0-9]+\z/) && (0..16).include?(status.to_i)

        raise Faraday::GRPCWeb::ProtocolError.new(
          "invalid gRPC-Web grpc-status: #{raw_status.inspect}",
          env.response
        )
      end

      def decode_status_message!(env, trailers)
        if trailers.key?('grpc-message')
          trailers['grpc-message'] =
            Faraday::GRPCWeb.decode_metadata(trailers['grpc-message'].to_s)
          env.response_headers['grpc-message'] = trailers['grpc-message']
        elsif env.response_headers.key?('grpc-message')
          env.response_headers['grpc-message'] =
            Faraday::GRPCWeb.decode_metadata(env.response_headers['grpc-message'].to_s)
        end
      end

      def raise_missing_data!(env)
        raise Faraday::GRPCWeb::ProtocolError.new(
          'gRPC-Web unary response is missing its data frame',
          env.response
        )
      end

      def verify_content_type!(env)
        response_type = extract_content_type(env)
        return if response_type == content_type

        raise Faraday::GRPCWeb::ProtocolError.new(
          "unexpected gRPC-Web Content-Type: #{response_type.inspect}",
          env.response
        )
      end

      def extract_content_type(env)
        env.response_headers[CONTENT_TYPE].to_s
                          .split(';', 2)
                          .first
                          .strip
                          .downcase
      end
    end
  end
end

Faraday::Request.register_middleware(grpc_web: Faraday::Request::GRPCWeb)
