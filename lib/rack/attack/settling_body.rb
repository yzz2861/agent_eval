# frozen_string_literal: true

module Rack
  class Attack
    # Wraps a response body so that reservations are settled at the moment
    # the response's billing point is reached:
    #
    # * :delivered - the body was fully enumerated (or closed afterwards).
    # * :error     - the body raised while streaming (deferred body error).
    # * :closed    - the body was closed before being fully delivered,
    #                e.g. the client went away early.
    #
    # The settlement callback runs exactly once, no matter how the body
    # lifecycle plays out.
    class SettlingBody
      def initialize(body, &on_settle)
        @body = body
        @on_settle = on_settle
        @settled = false
        @delivered = false
        @settle_mutex = Mutex.new
      end

      def each(&block)
        @body.each(&block)
        @delivered = true
        settle(:delivered)
      rescue Exception
        settle(:error)
        raise
      end

      def close
        @body.close if @body.respond_to?(:close)
        settle(@delivered ? :delivered : :closed)
      end

      private

      def settle(delivery)
        @settle_mutex.synchronize do
          return if @settled

          @settled = true
        end

        @on_settle.call(delivery)
      end
    end
  end
end
