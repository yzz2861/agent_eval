# frozen_string_literal: true

require 'securerandom'

module Faraday
  # Namespace for multipart/mixed batch request support.
  #
  # A batch request packs several independent HTTP sub-requests into a single
  # outer multipart/mixed request. Each sub-request keeps its own method,
  # relative target, headers, body and a unique Content-ID. Sub-responses are
  # correlated back to their request by that Content-ID, so their order on the
  # wire is irrelevant.
  module Batch
    # Raised when two sub-requests share the same Content-ID.
    class DuplicateIdError < Faraday::Error
      # @param ids [Array<String>] Content-IDs that occurred more than once
      def initialize(ids)
        @ids = ids
        super("duplicate batch Content-ID#{'s' if ids.size != 1}: #{ids.join(', ')}")
      end

      # @return [Array<String>] the duplicated Content-IDs
      attr_reader :ids
    end

    # Raised when an outer batch response cannot be parsed as multipart/mixed.
    class ParseError < Faraday::ParsingError
    end

    # A single sub-request inside a {Request}.
    #
    # @!attribute id
    #   @return [String] unique Content-ID of the sub-request
    # @!attribute method
    #   @return [Symbol] HTTP verb, e.g. `:get`
    # @!attribute url
    #   @return [String] relative target (path and query) of the sub-request
    # @!attribute headers
    #   @return [Hash] sub-request HTTP headers
    # @!attribute body
    #   @return [String, nil] sub-request body, encoded exactly as sent
    Part = Struct.new(:id, :method, :url, :headers, :body) do
      # @param method [Symbol, String] HTTP verb
      # @param url [String] relative target (path and query)
      # @param body [String, nil] sub-request body
      # @param headers [Hash] sub-request headers
      # @param id [String, nil] explicit Content-ID, auto-generated when nil
      def initialize(method, url, body = nil, headers = {}, id: nil)
        super(id || "item-#{SecureRandom.hex(8)}", method.to_s.downcase.to_sym,
              url, Faraday::Utils::Headers.new(headers), body)
      end
    end

    # An ordered collection of sub-requests to be sent as one outer request.
    class Request
      include Enumerable

      # @return [Array<Part>] the sub-requests in insertion order
      attr_reader :parts

      # @param parts [Array<Part>] initial sub-requests
      def initialize(parts = [])
        @parts = []
        parts.each { |part| add(part) }
      end

      # Adds a sub-request.
      #
      # @param part [Part] the sub-request to add
      # @raise [DuplicateIdError] if the Content-ID is already in the batch
      # @return [void]
      def add(part)
        raise DuplicateIdError, [part.id] if parts.any? { |existing| existing.id == part.id }

        parts << part
      end

      # Builds and adds a sub-request.
      #
      # @return (see Part#initialize)
      # @yield [part] allows further customization of the new part
      # @return [Part] the added sub-request
      def request(method, url, body = nil, headers = {}, id: nil)
        Part.new(method, url, body, headers, id: id).tap do |part|
          yield(part) if block_given?
          add(part)
        end
      end

      # @return [Array<String>] the unique Content-IDs in insertion order
      def ids
        parts.map(&:id)
      end

      # @yield [part] yields each sub-request in insertion order
      # @return [Enumerator]
      def each(&block)
        parts.each(&block)
      end

      # @return [Integer] number of sub-requests
      def size
        parts.size
      end
      alias length size
    end

    # The outcome of a single sub-request, correlated by Content-ID.
    #
    # @!attribute id
    #   @return [String] the Content-ID this result corresponds to
    # @!attribute status
    #   @return [Integer, nil] the inner HTTP status, nil when missing
    # @!attribute headers
    #   @return [Hash] inner response headers
    # @!attribute body
    #   @return [String, nil] inner response body
    # @!attribute error
    #   @return [Exception, nil] error for this item, e.g. a missing response
    Result = Struct.new(:id, :status, :headers, :body, :error) do
      # @return [Boolean] true when no sub-response carried this Content-ID
      def missing?
        status.nil?
      end

      # @return [Boolean] true when the item itself failed (HTTP error status
      #   or a transport/parsing error recorded for it)
      def error?
        return true if error
        return false if status.nil?

        status < 200 || status >= 300
      end

      # @return [Boolean] true only for a 2xx inner status without an error
      def success?
        !error? && !missing?
      end
    end

    # Raised when a requested Content-ID is absent from the batch response.
    class MissingResponseError < Faraday::Error
    end

    # Decoded view of an outer batch response.
    #
    # Results are always presented in the same order as the requested
    # Content-IDs, regardless of the wire order. Missing Content-IDs are
    # represented explicitly rather than dropped.
    class Response
      include Enumerable

      # @return [Integer, nil] outer HTTP status of the batch response
      attr_reader :outer_status
      # @return [Hash] outer HTTP headers of the batch response
      attr_reader :outer_headers
      # @return [Array<Result>] results ordered by the requested Content-IDs
      attr_reader :results

      # @param expected_ids [Array<String>] requested Content-IDs in order
      # @param result_by_id [Hash{String => Result}] decoded sub-responses
      # @param outer_status [Integer, nil] outer HTTP status
      # @param outer_headers [Hash] outer HTTP headers
      # @param unexpected [Array<Result>] sub-responses with unknown Content-IDs
      def initialize(expected_ids, result_by_id, outer_status: nil, outer_headers: {}, unexpected: [])
        @outer_status = outer_status
        @outer_headers = outer_headers
        @results = expected_ids.map do |id|
          result_by_id[id] ||
            Result.new(id, nil, {}, nil,
                       MissingResponseError.new("no sub-response received for Content-ID #{id.inspect}"))
        end
        @unexpected = unexpected
      end

      # @return [Array<Result>] sub-responses with unexpected Content-IDs
      attr_reader :unexpected

      # @yield [result] yields each result in request order
      # @return [Enumerator]
      def each(&block)
        results.each(&block)
      end

      # Looks up a result by Content-ID or request index.
      #
      # @param key [String, Symbol, Integer] Content-ID or zero-based index
      # @return [Result]
      def [](key)
        return results[key] if key.is_a?(Integer)

        results.find { |result| result.id == key.to_s }
      end

      # @return [Array<Result>] results for which no sub-response was received
      def missing
        results.select(&:missing?)
      end

      # @return [Boolean] true when every requested item got a 2xx response
      def success?
        results.any? && results.all?(&:success?)
      end

      # @return [Array<Result>] items with HTTP error statuses or recorded errors
      def failed
        results.select(&:error?)
      end

      # @return [Integer] number of requested items
      def size
        results.size
      end
      alias length size
    end
  end
end

require_relative 'batch/encoder'
require_relative 'batch/decoder'
