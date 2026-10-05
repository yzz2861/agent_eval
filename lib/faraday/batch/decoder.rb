# frozen_string_literal: true

module Faraday
  module Batch
    # Decodes a `multipart/mixed` outer response into a {Batch::Response}.
    #
    # Sub-responses are associated by their envelope Content-ID, so their
    # physical order does not matter. Every requested Content-ID is always
    # represented in the result: missing ones carry a {MissingResponseError}
    # instead of being dropped. An outer HTTP 200 is never treated as evidence
    # that the individual sub-requests succeeded.
    class Decoder
      # @return [String] media type expected for the outer batch response
      MIME_TYPE = 'multipart/mixed'.freeze

      CRLF = "\r\n".freeze
      CRLF_PATTERN = /\r\n/.freeze
      HEADER_SEPARATOR = /\r\n\r\n/.freeze
      STATUS_LINE = %r{\AHTTP/\d(?:\.\d)?[ \t]+(\d{3})(?:[ \t]+[^\r\n]*)?(?=\r\n|\z)}.freeze
      private_constant :CRLF, :CRLF_PATTERN, :HEADER_SEPARATOR, :STATUS_LINE

      # @param expected_ids [Array<String>] Content-IDs of sent sub-requests
      # @param status [Integer, nil] outer HTTP status
      # @param headers [Hash] outer response headers
      # @param body [String, nil] outer response body
      # @return [Batch::Response]
      def self.decode(expected_ids, status, headers, body)
        new(expected_ids, status, headers, body).decode
      end

      # @param expected_ids [Array<String>] Content-IDs of sent sub-requests
      # @param status [Integer, nil] outer HTTP status
      # @param headers [Hash] outer response headers
      # @param body [String, nil] outer response body
      def initialize(expected_ids, status, headers, body)
        @expected_ids = expected_ids.map(&:to_s)
        @outer_status = status
        @outer_headers = Faraday::Utils::Headers.new(headers)
        @body = body.to_s.dup.force_encoding(Encoding::BINARY)
      end

      # @return [Batch::Response]
      def decode
        return failed_batch unless multipart_response?

        result_by_id, unexpected = partition_parts
        Batch::Response.new(@expected_ids, result_by_id,
                            outer_status: @outer_status,
                            outer_headers: @outer_headers,
                            unexpected: unexpected)
      rescue Batch::ParseError => error
        failed_batch(error)
      end

      private

      # Builds the response used when the outer envelope cannot be decoded.
      #
      # @param error [Batch::ParseError, nil] reason the envelope failed
      # @return [Batch::Response]
      def failed_batch(error = nil)
        cause = error || Batch::ParseError.new(
          "outer batch response is not #{MIME_TYPE} (status #{@outer_status.inspect})"
        )
        result_by_id = @expected_ids.each_with_object({}) do |id, memo|
          memo[id] = Result.new(id, nil, {}, nil, cause)
        end
        Batch::Response.new(@expected_ids, result_by_id,
                            outer_status: @outer_status,
                            outer_headers: @outer_headers)
      end

      # Correlates parsed sub-responses with the requested Content-IDs.
      #
      # @return [Array(Hash, Array)] results by ID plus unexpected results
      def partition_parts
        result_by_id = {}
        unexpected = []
        each_part do |raw_part|
          result = parse_part(raw_part)
          if result.id.nil? || !@expected_ids.include?(result.id)
            unexpected << result
          elsif result_by_id.key?(result.id)
            result.error ||= Batch::ParseError.new(
              "duplicate sub-response received for Content-ID #{result.id.inspect}"
            )
            unexpected << result
          else
            result_by_id[result.id] = result
          end
        end
        [result_by_id, unexpected]
      end

      # Yields raw part payloads using the declared boundary. A delimiter is
      # only recognized at the start of a line (start of body or preceded by
      # CRLF), so boundary text occurring mid-line inside a binary part body
      # does not terminate that part.
      #
      # @yield [raw_part] each part as a binary string
      # @return [void]
      def each_part
        occurrences = boundary_occurrences
        raise Batch::ParseError, 'multipart boundary not found in batch response' if occurrences.empty?

        occurrences.each_cons(2) do |(_, delimiter_end), (next_start, _)|
          yield @body.byteslice(delimiter_end + 2, next_start - delimiter_end - 4)
        end
      end

      # Locates every line-start boundary delimiter in the body.
      #
      # @return [Array<Array(Integer, Integer)>] start/end byte offsets
      def boundary_occurrences
        pattern = /(?<=\A|\r\n)--#{Regexp.escape(boundary)}/n
        matches = []
        offset = 0
        while (match = pattern.match(@body, offset))
          matches << [match.begin(0), match.end(0)]
          offset = match.begin(0) + 1
        end
        matches
      end

      # Parses a single raw multipart part into a {Result}.
      #
      # @param raw [String] one raw multipart part
      # @return [Result]
      def parse_part(raw)
        separator = HEADER_SEPARATOR.match(raw)
        unless separator
          return Result.new(nil, nil, {}, raw,
                            Batch::ParseError.new('malformed part headers in batch response'))
        end

        header_blob = raw.byteslice(0, separator.begin(0))
        inner = raw.byteslice(separator.end(0), raw.bytesize - separator.end(0))
        envelope = parse_headers(header_blob)
        id = normalize_id(envelope['Content-ID'])
        status, headers, body = parse_inner_response(inner)
        error = status.nil? ? Batch::ParseError.new('sub-response is missing an HTTP status line') : nil
        Result.new(id, status, headers, body, error)
      end

      # Parses a block of CRLF (or LF) separated header lines.
      #
      # @param blob [String] raw header lines
      # @return [Faraday::Utils::Headers]
      def parse_headers(blob)
        headers = Faraday::Utils::Headers.new
        blob.to_s.split(CRLF_PATTERN).each do |line|
          name, value = line.split(':', 2)
          next if value.nil?

          headers[name.strip] = value.strip
        end
        headers
      end

      # Parses an encapsulated HTTP response message.
      #
      # @param inner [String] encapsulated HTTP response
      # @return [Array(Integer, nil, Faraday::Utils::Headers, String)]
      def parse_inner_response(inner)
        status_match = STATUS_LINE.match(inner)
        return [nil, Faraday::Utils::Headers.new, inner] if status_match.nil?

        after_status = status_match.end(0)
        remainder = inner.byteslice(after_status, inner.bytesize - after_status).to_s
        header_separator = HEADER_SEPARATOR.match(remainder)
        unless header_separator
          return [status_match[1].to_i, Faraday::Utils::Headers.new, '']
        end

        header_blob = remainder.byteslice(CRLF.bytesize,
                                         header_separator.begin(0) - CRLF.bytesize)
        body = remainder.byteslice(header_separator.end(0),
                                   remainder.bytesize - header_separator.end(0))
        [status_match[1].to_i, parse_headers(header_blob), body]
      end

      # Normalizes a Content-ID value, stripping optional angle brackets.
      #
      # @param value [String, nil] raw Content-ID header value
      # @return [String, nil]
      def normalize_id(value)
        value = value.to_s.strip
        return nil if value.empty?

        value.gsub(/\A<+/, '').gsub(/>+\z/, '')
      end

      # @return [Boolean] true when the outer envelope is a usable multipart body
      def multipart_response?
        !boundary.nil? && content_type.to_s.include?(MIME_TYPE) && !@body.empty?
      end

      # @return [String, nil] boundary declared by the outer Content-Type
      def boundary
        return @boundary if defined?(@boundary)

        match = /boundary=(?:"([^"]+)"|([^;]+))/i.match(content_type)
        @boundary = match && (match[1] || match[2].to_s.strip)
      end

      # @return [String]
      def content_type
        @outer_headers[Faraday::CONTENT_TYPE].to_s
      end
    end
  end
end
