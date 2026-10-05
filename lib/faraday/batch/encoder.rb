# frozen_string_literal: true

module Faraday
  module Batch
    # Encodes a {Batch::Request} into a `multipart/mixed` body and the
    # corresponding outer request headers.
    class Encoder
      # @return [String] media type used for the outer request
      MIME_TYPE = 'multipart/mixed'.freeze

      # @return [String] media type used for every encapsulated sub-request
      APPLICATION_HTTP = 'application/http'.freeze

      # @param request [Batch::Request] the sub-requests to encode
      # @param boundary [String, nil] explicit boundary, generated when nil
      # @raise [DuplicateIdError] if two sub-requests share a Content-ID
      # @raise [Faraday::Error] if an explicit boundary occurs in a body
      def initialize(request, boundary: nil)
        @request = request
        @explicit_boundary = boundary
        ensure_unique_ids!
        @boundary = boundary || self.class.generate_boundary(inner_requests.values)
        ensure_safe_boundary!
      end

      # @return [String] the multipart boundary delimiter
      attr_reader :boundary

      # @return [Hash] outer headers to merge into the Faraday request
      def headers
        { Faraday::CONTENT_TYPE => %(#{MIME_TYPE}; boundary="#{boundary}") }
      end

      # @return [String] the binary-safe multipart/mixed request body
      def body
        encoded.dup
      end

      # Generates a boundary guaranteed not to collide with the given payloads.
      #
      # The boundary uses bchars per RFC 2046 and is retried until none of the
      # payloads contain it. A boundary that happens to appear inside a binary
      # sub-request body therefore cannot terminate a part early.
      #
      # @param payloads [Array<String, nil>] encoded sub-request payloads
      # @return [String] a boundary absent from every payload
      # @raise [Faraday::Error] if no unique boundary can be generated
      def self.generate_boundary(payloads = [])
        10.times do
          candidate = "FaradayBatchBoundary#{SecureRandom.hex(16)}"
          return candidate if payloads.none? { |chunk| chunk.to_s.include?(candidate) }
        end
        raise Faraday::Error, 'could not generate a unique multipart boundary'
      end

      private

      attr_reader :request

      CRLF = "\r\n".freeze

      def encoded
        @encoded ||= begin
          output = ::String.new(encoding: Encoding::BINARY)
          inner_requests.each do |part, inner|
            output << "--#{boundary}#{CRLF}"
            output << %(#{Faraday::CONTENT_TYPE}: #{APPLICATION_HTTP}; msgtype="request"#{CRLF})
            output << "Content-ID: #{part.id}#{CRLF}"
            output << CRLF
            output << inner
            output << CRLF
          end
          output << "--#{boundary}--#{CRLF}"
          output
        end
      end

      def inner_requests
        @inner_requests ||= request.parts.each_with_object({}) do |part, memo|
          memo[part] = build_inner_request(part)
        end
      end

      def build_inner_request(part)
        output = ::String.new(encoding: Encoding::BINARY)
        output << part.method.to_s.upcase << ' ' << part.url.to_s << " HTTP/1.1#{CRLF}"
        part.headers.each do |name, value|
          output << name.to_s << ': ' << value.to_s << CRLF
        end
        output << CRLF
        output << read_body(part.body)
        output
      end

      def read_body(body)
        return ::String.new(encoding: Encoding::BINARY) if body.nil?
        if !body.respond_to?(:to_str) && !body.respond_to?(:read)
          raise Faraday::Error, "batch sub-request body must be a String or IO, got #{body.class}"
        end

        payload = body.respond_to?(:read) ? body.read : body.to_str
        payload.to_s.dup.force_encoding(Encoding::BINARY)
      end

      def ensure_unique_ids!
        duplicates = request.ids.group_by(&:itself).select { |_, group| group.size > 1 }.keys
        raise DuplicateIdError, duplicates unless duplicates.empty?
      end

      def ensure_safe_boundary!
        return if @explicit_boundary.nil?
        return if inner_requests.values.none? { |payload| payload.include?(@explicit_boundary) }

        raise Faraday::Error, "multipart boundary #{@explicit_boundary.inspect} occurs in a sub-request body"
      end
    end
  end
end
