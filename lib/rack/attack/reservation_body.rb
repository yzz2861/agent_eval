# frozen_string_literal: true

module Rack
  class Attack
    class ReservationBody
      def initialize(body, settlement)
        @body = body
        @settlement = settlement
        @settled = false
      end

      def each(&block)
        @body.each(&block)
      rescue => error
        settle(error)
        raise
      end

      def close
        begin
          @body.close if @body.respond_to?(:close)
        rescue => error
          settle(error)
          raise
        end
        settle(nil)
      end

      def respond_to_missing?(name, include_private = false)
        @body.respond_to?(name, include_private)
      end

      def method_missing(name, *arguments, &block)
        if @body.respond_to?(name)
          @body.public_send(name, *arguments, &block)
        else
          super
        end
      end

      private

      def settle(error)
        return if @settled

        @settled = true
        @settlement.call(error)
      end
    end
  end
end
