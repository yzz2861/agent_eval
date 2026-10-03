# frozen_string_literal: true

class Net::HTTP

  # Namespace for structured diagnostics attached to transport-level
  # failures (connection, TLS handshake, request write, response read).
  module TransportFailure

    # Mixed into the original exception raised by a transport failure.
    # The exception's class and its +cause+ chain are preserved; this module
    # only adds a reader for the structured Context.
    module Diagnostics
      attr_accessor :transport_failure_context
    end

    # An immutable, redacted snapshot of how far a request travelled before
    # the transport failed.
    #
    # Quantities that cannot be determined are represented by +nil+ (unknown),
    # never by +0+.
    #
    # This object never contains request or response header values
    # (in particular, no +Authorization+ or +Proxy-Authorization+ headers)
    # and never contains request or response body content.
    class Context

      # Symbol naming the transport stage at the moment of failure.
      # One of:
      # +:tcp_connect+:: TCP connection could not be established.
      # +:proxy_connect+:: Failure while establishing a proxy CONNECT tunnel.
      # +:tls_handshake+:: Failure during the TLS handshake or certificate verification.
      # +:request_header+:: Connection broke while the request header was being written.
      # +:request_body+:: Connection broke while the request body was being written.
      # +:response_header+:: Connection broke while the (final) response status and headers were being read.
      # +:response_body+:: Connection broke while the response body was being read; the final status was received.
      attr_reader :phase

      # The HTTP request method ("GET", "POST", ...), or +nil+ when the
      # failure happened before any request was being sent (connect/TLS).
      attr_reader :request_method

      # Whether writing the request header has started.
      # When +true+, the request (and therefore a payment, for example)
      # may already have reached the server, even though no response came back.
      attr_reader :request_headers_started

      # The number of request body bytes known to have been handed off to
      # the transport, or +nil+ when the number is not known (a write was
      # interrupted partway through). +0+ means it is known that no body
      # bytes were written; +nil+ means unknown.
      attr_reader :request_body_bytes_written

      # Whether the final response status line has been received.
      # +1xx+ informational responses do not count as final responses.
      attr_reader :response_received

      # The integer HTTP status code of the final response, or +nil+ when
      # no final response was received.
      attr_reader :response_status

      # Whether TLS was in use for the connection.
      attr_reader :use_ssl

      # The target host and port (redacted of any credentials).
      attr_reader :address, :port

      def initialize(phase:, request_method:, request_headers_started:,
                     request_body_bytes_written:, response_received:,
                     response_status:, use_ssl:, address:, port:)
        @phase = phase
        @request_method = request_method
        @request_headers_started = request_headers_started
        @request_body_bytes_written = request_body_bytes_written
        @response_received = response_received
        @response_status = response_status
        @use_ssl = use_ssl
        @address = address
        @port = port
        freeze
      end

      # True when the final response status line was received.
      def response_received?
        @response_received
      end

      # True when request header bytes may have left the client.
      def request_headers_started?
        @request_headers_started
      end

      # True when no part of the request is known to have reached the
      # server, so the request can safely be retried as-is. This covers
      # TCP/TLS/proxy establishment failures and failures before the first
      # request header byte was written.
      def safe_to_retry?
        !@request_headers_started && !@response_received
      end

      # True when the request may have been processed by the server but no
      # final response was received. Retrying blindly could double-charge a
      # payment; the payment/request result should be queried first.
      def should_query_result?
        @request_headers_started && !@response_received
      end

      # Structured representation suitable for logging or metrics.
      # Unknown values are emitted as +nil+, never as +0+.
      def to_h
        {
          phase: @phase,
          request_method: @request_method,
          request_headers_started: @request_headers_started,
          request_body_bytes_written: @request_body_bytes_written,
          response_received: @response_received,
          response_status: @response_status,
          use_ssl: @use_ssl,
          address: @address,
          port: @port,
          safe_to_retry: safe_to_retry?,
          should_query_result: should_query_result?,
        }
      end

      def inspect
        "#<#{self.class} #{to_h.map { |k, v| "#{k}=#{v.inspect}" }.join(' ')}>"
      end
    end

  end
end
