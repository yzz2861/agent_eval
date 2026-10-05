# frozen_string_literal: true

require 'faraday/grpc_web'

module Faraday
  class Response
    # Response middleware for unary gRPC-Web calls.
    #
    # Parses the data and trailers frames of a gRPC-Web response (binary
    # or base64 text), checks the HTTP status and the grpc-status trailer
    # independently, and replaces the body with the raw protobuf message
    # bytes. Decoding those bytes into a protobuf message is left to the
    # caller.
    #
    # The parsed Faraday::GrpcWeb::Result (message bytes plus trailers) is
    # available as env[:grpc_web].
    class GrpcWeb < Middleware
      MIME_TYPE_REGEX = %r{\Aapplication/grpc-web(-text)?([+.]|\z)}

      DEFAULT_OPTIONS = {
        max_frame_size: Faraday::GrpcWeb::DEFAULT_MAX_FRAME_SIZE
      }.freeze

      def on_complete(env)
        check_http_status(env)
        process_response(env) if process_response?(env)
      end

      private

      # HTTP-level failures are reported independently of grpc-status:
      # a non-2xx response raises a Faraday HTTP error without looking at
      # the gRPC-Web frames.
      def check_http_status(env)
        return if env[:status].is_a?(Integer) && env[:status].between?(200, 299)

        error_class =
          case env[:status]
          when 400...500 then Faraday::ClientError
          when 500...600 then Faraday::ServerError
          else Faraday::GrpcWeb::Error
          end
        raise error_class, response_values(env)
      end

      def process_response(env)
        parser = Faraday::GrpcWeb::FrameParser.new(
          text: text_response?(env),
          max_frame_size: options[:max_frame_size]
        )
        parser << env[:body].to_s
        result = Faraday::GrpcWeb.build_unary_result(parser.finish)

        check_grpc_status(result, env)

        env[:body] = result.message
        env[:grpc_web] = result
      end

      # The grpc-status trailer is checked independently of the HTTP
      # status: a 200 response can still carry a failing grpc-status.
      def check_grpc_status(result, env)
        status = result.grpc_status
        return if status&.zero?

        raise Faraday::GrpcWeb::StatusError.new(
          status, result.grpc_message, response_values(env)
        )
      end

      def process_response?(env)
        env[:response_headers][CONTENT_TYPE].to_s.match?(MIME_TYPE_REGEX)
      end

      def text_response?(env)
        env[:response_headers][CONTENT_TYPE].to_s.include?('grpc-web-text')
      end

      def response_values(env)
        {
          status: env[:status],
          headers: env[:response_headers],
          body: env[:body]
        }
      end
    end
  end
end

Faraday::Response.register_middleware(grpc_web: Faraday::Response::GrpcWeb)
