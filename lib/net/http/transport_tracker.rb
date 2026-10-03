# frozen_string_literal: true

class Net::HTTP

  # Internal state tracking how far a single transport attempt travelled.
  # One tracker lives on the connection for the lifetime of the session;
  # #begin_request resets the per-request state before every attempt
  # (including automatic retries).
  class TransportTracker # :nodoc: internal use only

    # How the request body, if any, is written. This controls whether raw
    # bytes handed to the socket can be counted as request body bytes.
    # +:none+::      no body, or request headers only.
    # +:raw+::       a single body source written verbatim (Content-Length).
    # +:chunked+::   chunked transfer encoding; framing must not be counted.
    # +:opaque+::    bytes cannot be attributed exactly (multipart chunked).
    BODY_MODES = %i[none raw chunked opaque].freeze

    def initialize(address:, port:, use_ssl:)
      @address = address
      @port = port
      @use_ssl = use_ssl
      @phase = :tcp_connect
      @request_method = nil
      @headers_started = false
      @body_mode = :none
      @body_bytes = 0
      @body_bytes_unknown = false
      @write_failed = false
      @response_received = false
      @response_status = nil
    end

    attr_reader :phase

    def use_ssl!
      @use_ssl = true
    end

    # Called once per transport attempt, before the request is sent.
    def begin_request(method)
      @phase = :request_header
      @request_method = method
      @headers_started = false
      @body_mode = :none
      @body_bytes = 0
      @body_bytes_unknown = false
      @write_failed = false
      @response_received = false
      @response_status = nil
    end

    def phase=(phase)
      @phase = phase
    end

    def request_headers_started!
      @headers_started = true
    end

    def request_headers_started?
      @headers_started
    end

    def body_mode=(mode)
      raise ArgumentError, mode unless BODY_MODES.include?(mode)
      @body_mode = mode
      # Opaque body writers interleave framing with payload, so even on a
      # later failure we can never report a meaningful exact byte count.
      @body_bytes_unknown = true if mode == :opaque
    end

    def raw_body?
      @body_mode == :raw
    end

    # Records +bytes+ payload bytes known to have been handed off.
    def body_bytes_written!(bytes)
      @body_bytes += bytes
    end

    # Marks that a write was interrupted, so the total handed-off body
    # byte count cannot be determined. Unknown, not zero.
    def body_write_interrupted!
      @body_bytes_unknown = true
    end

    # A write of the request (header or body) has failed.
    def request_write_failed!
      @write_failed = true
      body_write_interrupted! if @phase == :request_body && @body_mode != :none
    end

    def write_failed?
      @write_failed
    end

    # Records that the final response status line has been received.
    def final_response!(status)
      @response_received = true
      @response_status = status
    end

    def context
      Net::HTTP::TransportFailure::Context.new(
        phase: @phase,
        request_method: @request_method,
        request_headers_started: @headers_started,
        request_body_bytes_written: request_body_bytes_written,
        response_received: @response_received,
        response_status: @response_status,
        use_ssl: @use_ssl,
        address: @address,
        port: @port,
      )
    end

    private

    def request_body_bytes_written
      return nil if @body_bytes_unknown
      @body_bytes
    end
  end

  # BufferedIO subclass that feeds body-write accounting to the tracker.
  # It only counts during the request body phase, and only when the bytes
  # written are request body bytes (not HTTP framing or proxy traffic).
  class TrackingBufferedIO < Net::BufferedIO # :nodoc: internal use only
    attr_accessor :transport_tracker

    def initialize(io, tracker:, **options)
      super(io, **options)
      @transport_tracker = tracker
    end

    def write(*strs)
      count = count_raw_body_bytes?
      rv = super
      if count
        @transport_tracker.body_bytes_written!(rv)
      end
      rv
    rescue StandardError
      # The underlying write was interrupted. If this was a request body
      # write, the exact amount handed off can no longer be determined.
      @transport_tracker.request_write_failed!
      raise
    end

    private

    # When the request body is written verbatim with a Content-Length
    # (string body or a fixed-length stream), every byte handed to the
    # socket during the body phase is a request body byte.
    def count_raw_body_bytes?
      tracker = @transport_tracker
      tracker && tracker.phase == :request_body && tracker.raw_body?
    end
  end
end
