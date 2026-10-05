# frozen_string_literal: true

module Faraday
  class Response
    # Decodes an Amazon EventStream (application/vnd.amazon.eventstream)
    # response and yields every validated Faraday::EventStream::Message to
    # the given block.
    #
    # When the adapter streams the response, chunks of any size are decoded
    # incrementally; otherwise the buffered body is decoded on completion.
    # A message is only yielded after its prelude CRC, lengths and message
    # CRC have all been verified, and a truncated tail raises
    # Faraday::EventStream::TruncationError.
    #
    # @example
    #   conn = Faraday.new(url: 'https://example.com') do |f|
    #     f.response :event_stream do |message|
    #       puts message.headers.inspect
    #       puts message.payload
    #     end
    #   end
    class EventStream < Middleware
      def initialize(app = nil, &handler)
        super(app)
        unless handler
          raise Faraday::InitializationError,
                'Faraday::Response::EventStream requires a block to receive decoded messages'
        end
        @handler = handler
      end

      def on_request(env)
        @decoder = Faraday::EventStream::Decoder.new
        @streamed = false
        env.request.on_data = proc do |chunk, _received, stream_env|
          @streamed = true
          deliver(@decoder.feed(chunk), stream_env)
        end
      end

      def on_complete(env)
        if @streamed
          @decoder.finish
        elsif env.body.is_a?(String) && !env.body.empty?
          deliver(@decoder.feed(env.body), env)
          @decoder.finish
        end
      end

      private

      def deliver(messages, env)
        messages.each { |message| @handler.call(message, env) }
      end
    end
  end
end

Faraday::Response.register_middleware(event_stream: Faraday::Response::EventStream)
