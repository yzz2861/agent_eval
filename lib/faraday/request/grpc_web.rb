# frozen_string_literal: true

require 'faraday/grpc_web'

module Faraday
  class Request
    # Request middleware that frames an already-encoded protobuf message
    # for a unary gRPC-Web call.
    #
    # The body must be a String of protobuf bytes encoded by the caller;
    # this middleware does not know about protobuf message classes.
    #
    # @example
    #   conn = Faraday.new(url: 'https://api.example.com') do |f|
    #     f.request :grpc_web, mode: :binary
    #     f.response :grpc_web
    #     f.adapter Faraday.default_adapter
    #   end
    #   conn.post('/pkg.Service/Method', MyMessage.encode(msg))
    class GrpcWeb < Middleware
      MIME_TYPE_BINARY = 'application/grpc-web'
      MIME_TYPE_TEXT = 'application/grpc-web-text'

      DEFAULT_OPTIONS = { mode: :binary }.freeze

      def on_request(env)
        return if env[:body].nil?

        mime_type = text_mode? ? MIME_TYPE_TEXT : MIME_TYPE_BINARY
        env[:request_headers][CONTENT_TYPE] ||= mime_type
        env[:request_headers]['Accept'] ||= mime_type
        env[:request_headers]['X-Grpc-Web'] ||= '1'
        env[:request_headers]['TE'] ||= 'trailers'

        frame = Faraday::GrpcWeb.encode_frame(request_message(env))
        env[:body] = text_mode? ? [frame].pack('m0') : frame
      end

      private

      def text_mode?
        case options[:mode]
        when :binary then false
        when :text then true
        else
          raise Faraday::GrpcWeb::Error,
                'invalid gRPC-Web mode: ' + options[:mode].inspect + \
                ' (expected :binary or :text)'
        end
      end

      def request_message(env)
        body = env[:body]
        return body.to_str if body.respond_to?(:to_str)

        raise Faraday::GrpcWeb::Error,
              'gRPC-Web request bodies must be Strings of encoded protobuf ' \
              'bytes, got ' + body.class.to_s
      end
    end
  end
end

Faraday::Request.register_middleware(grpc_web: Faraday::Request::GrpcWeb)
