# frozen_string_literal: true

module Faraday
  # Lightweight unary gRPC-Web support.
  #
  # This module only deals with the gRPC-Web wire framing: callers provide
  # already-encoded protobuf bytes and receive raw protobuf bytes back.
  # It does not generate protobuf classes and does not depend on a gRPC
  # runtime.
  module GrpcWeb
    # Base error for all gRPC-Web related failures.
    class Error < Faraday::Error
    end

    # Raised when the peer sends malformed, truncated, or otherwise
    # unacceptable gRPC-Web frames.
    class ProtocolError < Error
    end

    # Raised when the response trailers carry a non-zero grpc-status.
    class StatusError < Error
      attr_reader :grpc_status, :grpc_message

      def initialize(grpc_status, grpc_message = nil, response = nil)
        @grpc_status = grpc_status
        @grpc_message = grpc_message
        detail = grpc_message && !grpc_message.empty? ? ': ' + grpc_message : ''
        super('gRPC status ' + grpc_status.to_s + detail, response)
      end
    end
  end
end

require 'faraday/grpc_web/framing'
