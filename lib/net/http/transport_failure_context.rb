# frozen_string_literal: true

class Net::HTTP
  class TransportFailureContext
    def initialize(phase: :connect)
      @phase = phase
      @request_headers_started = false
      @request_body_bytes_written = nil
      @final_response_received = false
      @tracking_request_body_writes = true
    end

    attr_reader :phase
    attr_reader :request_body_bytes_written

    def request_headers_started?
      @request_headers_started
    end

    def final_response_received?
      @final_response_received
    end

    def phase=(phase)
      @phase = phase
    end

    def request_headers_started!
      @request_headers_started = true
    end

    def request_body_started!
      @request_body_bytes_written ||= 0
    end

    def request_body_phase!
      @phase = :request_body
      @request_body_bytes_written = nil
    end

    def request_body_written!(bytes)
      request_body_started!
      @request_body_bytes_written += bytes
    end

    def request_body_bytes_unknown!
      @request_body_bytes_written = nil
    end

    def final_response_received!
      @final_response_received = true
    end

    alias connection_phase phase
    alias request_header_started? request_headers_started?

    def without_request_body_write_tracking
      tracking = @tracking_request_body_writes
      @tracking_request_body_writes = false
      yield
    ensure
      @tracking_request_body_writes = tracking
    end

    def tracking_request_body_writes?
      @tracking_request_body_writes
    end
  end

  module TransportFailure
    attr_accessor :http_transport_failure_context
    alias transport_failure http_transport_failure_context
  end
end
