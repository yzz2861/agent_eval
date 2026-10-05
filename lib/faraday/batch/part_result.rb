# frozen_string_literal: true

module Faraday
  module Batch
    # A single decoded response part, or an explicit placeholder for a
    # Content-ID that was requested but not returned.
    class PartResult
      # @return [String] Content-ID this result belongs to.
      attr_reader :content_id
      # @return [Integer, nil] HTTP status of the sub-response, nil when the
      #   part is missing.
      attr_reader :status
      # @return [Faraday::Utils::Headers] Response headers.
      attr_reader :headers
      # @return [String] Raw response body as binary data.
      attr_reader :body
      # @return [Integer, nil] Status of the outer batch response, useful when
      #   the part itself is missing.
      attr_accessor :outer_status

      # @param content_id [String] Correlated Content-ID.
      # @param status [Integer, nil] HTTP status, nil for a missing part.
      # @param headers [Hash{String => String}, nil] Response headers.
      # @param body [String, nil] Raw response body.
      def initialize(content_id, status = nil, headers = nil, body = nil)
        @content_id = content_id
        @status = status
        @headers = Faraday::Utils::Headers.new
        @headers.update(headers) if headers
        @body = body ? body.dup : +''
        @outer_status = nil
        @error = nil
      end

      # Builds the explicit result for a Content-ID absent from the response.
      #
      # @param content_id [String] Missing Content-ID.
      # @param outer_status [Integer, nil] Outer batch response status.
      # @param outer_response [Hash, nil] Outer response data attached to the
      #   error.
      # @return [PartResult]
      def self.missing(content_id, outer_status: nil, outer_response: nil)
        result = new(content_id)
        result.outer_status = outer_status
        result.set_error(MissingPartError.new(
          "no response part returned for Content-ID #{content_id.inspect}",
          outer_response
        ))
        result
      end

      # @return [Boolean] true only when the part was returned with a 2xx
      #   status. The outer 200 is intentionally not considered here.
      def success?
        !status.nil? && Faraday::Env::SuccessfulStatuses.include?(status)
      end

      # @return [Faraday::Error, nil] Error matching a 4xx/5xx part status, or
      #   a {MissingPartError} for a missing part. The error is never raised
      #   here; callers decide what to do with it.
      def error
        @error ||= Coder.error_for_status(status, headers, body)
      end

      # @api private
      # @param error [Faraday::Error] Error to attach to this result.
      # @return [PartResult] self.
      def set_error(error)
        @error = error
        self
      end

      # @return [Hash] Hash representation.
      def to_h
        {
          content_id: content_id,
          status: status,
          headers: headers,
          body: body,
          error: error,
          outer_status: outer_status
        }
      end
    end
  end
end
