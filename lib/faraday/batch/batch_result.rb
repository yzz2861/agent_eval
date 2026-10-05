# frozen_string_literal: true

module Faraday
  module Batch
    # Ordered collection of decoded parts. Results stay in request order and
    # are also addressable by Content-ID.
    class BatchResult
      include Enumerable

      # @return [Array<PartResult>] Results in request order.
      attr_reader :results
      # @return [Integer, nil] Status of the outer batch response.
      attr_reader :outer_status
      # @return [Faraday::Utils::Headers] Headers of the outer batch response.
      attr_reader :outer_headers
      # @return [String] Raw body of the outer batch response.
      attr_reader :outer_body

      # @param results [Array<PartResult>] One result per requested ID.
      # @param outer_status [Integer, nil] Outer batch response status.
      # @param outer_headers [Hash{String => String}, nil] Outer headers.
      # @param outer_body [String, nil] Outer body.
      def initialize(results, outer_status: nil, outer_headers: nil, outer_body: nil)
        @results = results
        @outer_status = outer_status
        @outer_headers = Faraday::Utils::Headers.new
        @outer_headers.update(outer_headers) if outer_headers
        @outer_body = outer_body ? outer_body.dup : +''
      end

      # @yield [PartResult] Each result in request order.
      def each(&block)
        results.each(&block)
      end

      # @param content_id [String, #to_s] Content-ID to look up.
      # @return [PartResult] The matching result.
      # @raise [KeyError] if the ID was not part of the batch request.
      def fetch(content_id)
        by_id.fetch(content_id.to_s) do
          raise KeyError, "Content-ID #{content_id.inspect} was not part of the batch request"
        end
      end

      # @param content_id [String, #to_s] Content-ID to look up.
      # @return [PartResult, nil] The matching result, or nil.
      def [](content_id)
        by_id[content_id.to_s]
      end

      # @return [Array<String>] Requested Content-IDs, in request order.
      def content_ids
        results.map(&:content_id)
      end

      # @return [Array<PartResult>] Parts that failed or were not returned.
      def failed
        results.reject(&:success?)
      end

      # @return [Array<PartResult>] Parts that were not returned at all.
      def missing
        results.select { |result| result.status.nil? }
      end

      # @return [Boolean] true only when every requested part succeeded.
      def all_succeeded?
        results.all?(&:success?)
      end
      alias success? all_succeeded?

      # @return [Array<Hash>] Hash representations of the results.
      def to_a
        results.map(&:to_h)
      end

      private

      def by_id
        @by_id ||= results.each_with_object({}) do |result, hash|
          hash[result.content_id] = result
        end
      end
    end
  end
end
