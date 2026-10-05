# frozen_string_literal: true

require 'faraday/batch'

module Faraday
  class Request
    # Batch encodes an Array of {Faraday::Batch::Part} into a single
    # +multipart/mixed+ request and decodes the batch response into a
    # {Faraday::Batch::BatchResult} keyed by Content-ID.
    #
    # Sub-responses are correlated by their Content-ID, so upstream parts may
    # arrive out of order. Each item keeps its own HTTP status and error; an
    # outer 200 is never treated as success for every item, and requested IDs
    # missing from the response appear as explicit missing results.
    #
    # Duplicate Content-IDs are rejected before sending anything. The
    # middleware performs exactly one request and never retries the batch.
    #
    # @example
    #   conn = Faraday.new do |builder|
    #     builder.request :batch
    #     builder.adapter :test do |stub|
    #       stub.post('/batch') { [200, {}, multipart_body] }
    #     end
    #   end
    #
    #   parts = [
    #     Faraday::Batch::Part.new(method: :get, path: '/users/1', content_id: '1'),
    #     Faraday::Batch::Part.new(method: :get, path: '/users/2', content_id: '2')
    #   ]
    #   result = conn.post('/batch', parts).body
    #   result['1'].status
    #   result.all_succeeded?
    class Batch < Faraday::Middleware
      DEFAULT_OPTIONS = { boundary: nil }.freeze

      BATCH_CONTENT_IDS = :batch_content_ids

      # Encodes the Array of Parts into multipart/mixed.
      #
      # @param env [Faraday::Env]
      # @return [void]
      def on_request(env)
        parts = batch_parts(env.body)
        return unless parts

        encoded = Faraday::Batch::Coder.encode_request(parts, boundary: options[:boundary])
        env.body = encoded.body
        env[BATCH_CONTENT_IDS] = encoded.content_ids
        env.request_headers[Faraday::Batch::CONTENT_TYPE] = encoded.content_type
      end

      # Decodes the multipart/mixed response into one result per requested ID.
      # A non-multipart outer response (e.g. an outer 500 error page) yields
      # explicit missing results carrying the outer response on the error.
      #
      # @param env [Faraday::Env]
      # @return [void]
      def on_complete(env)
        ids = env[BATCH_CONTENT_IDS]
        return unless ids

        content_type = env.response_headers[Faraday::Batch::CONTENT_TYPE]
        env.body = if Faraday::Batch::Coder.multipart?(content_type)
                     Faraday::Batch::Coder.decode_response(
                       env.body, content_type, ids,
                       outer_status: env.status,
                       outer_headers: env.response_headers
                     )
                   else
                     Faraday::Batch::Coder.missing_batch(
                       ids,
                       outer_status: env.status,
                       outer_headers: env.response_headers,
                       outer_body: env.body
                     )
                   end
      end

      private

      # Only Arrays made of batch Parts are considered batches, so an
      # accidental JSON array of hashes is left untouched.
      def batch_parts(body)
        return nil unless body.is_a?(Array) && !body.empty?
        return nil unless body.all? { |item| item.is_a?(Faraday::Batch::Part) }

        body
      end
    end
  end
end

Faraday::Request.register_middleware(batch: Faraday::Request::Batch)
