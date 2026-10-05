# frozen_string_literal: true

module Faraday
  class Request
    # Middleware that encodes a {Faraday::Batch::Request} body as an outer
    # `multipart/mixed` request and decodes the sub-responses back into a
    # {Faraday::Batch::Response}.
    #
    # Sub-responses are matched to their requests by Content-ID, so the server
    # may return them in any order. The outer HTTP status is preserved on the
    # decoded batch response and is never treated as per-item success; items
    # missing from the response are exposed explicitly. The middleware sends
    # the outer request exactly once and never retries it.
    #
    # @example
    #   conn = Faraday.new do |builder|
    #     builder.use Faraday::Request::Batch
    #     builder.adapter Faraday::Adapter::Test do |stub|
    #       stub.post('/batch') { |env| [200, batch_headers, batch_body(env)] }
    #     end
    #   end
    #
    #   batch = Faraday::Batch::Request.new
    #   batch.request(:get, '/articles/1', nil, {}, id: 'one')
    #   batch.request(:post, '/articles', '{"title":"x"}',
    #                 { 'Content-Type' => 'application/json' }, id: 'two')
    #
    #   response = conn.post('/batch', batch)
    #   response.body['one'].status # => 200
    class Batch < Faraday::Middleware
      DEFAULT_OPTIONS = { boundary: nil }.freeze

      # Sends the batch as a single outer request.
      #
      # @param env [Faraday::Env]
      # @return [Faraday::Response]
      def call(env)
        batch = batch_request(env)
        return @app.call(env) unless batch

        encode(env, batch)
        @app.call(env).on_complete { |response_env| decode(response_env, batch.ids) }
      end

      private

      # @param env [Faraday::Env]
      # @return [Faraday::Batch::Request, nil]
      def batch_request(env)
        body = env.body
        return body if body.is_a?(Faraday::Batch::Request)
        if body.is_a?(::Array) && body.all? { |part| part.is_a?(Faraday::Batch::Part) }
          return Faraday::Batch::Request.new(body)
        end

        nil
      end

      # @param env [Faraday::Env]
      # @param batch [Faraday::Batch::Request]
      # @return [void]
      def encode(env, batch)
        encoder = Faraday::Batch::Encoder.new(batch, boundary: options[:boundary])
        env.body = encoder.body
        encoder.headers.each { |name, value| env.request_headers[name] = value }
      end

      # @param env [Faraday::Env]
      # @param expected_ids [Array<String>]
      # @return [void]
      def decode(env, expected_ids)
        env.body = Faraday::Batch::Decoder.decode(
          expected_ids, env.status, env.response_headers, env.body
        )
      end
    end
  end
end

Faraday::Request.register_middleware(batch: Faraday::Request::Batch)
