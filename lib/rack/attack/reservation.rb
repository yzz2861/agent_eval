# frozen_string_literal: true

module Rack
  class Attack
    # A Reservation is the credential handed out when a throttle in
    # reserve-and-settle mode pre-occupies one unit of quota for an
    # in-flight request.
    #
    # Each reservation carries a unique token and is bound to the exact
    # cache-window key that was incremented when it was created. Settling
    # is idempotent: the first call to #settle takes effect, every later
    # call is a no-op returning false. A reservation can therefore never
    # refund (or keep) more than the single unit it reserved.
    class Reservation
      attr_reader :token, :count

      def initialize(cache:, token:, count:)
        @cache = cache
        @token = token
        @count = count
        @settled = false
        @settle_mutex = Mutex.new
      end

      # Settle this reservation. +outcome+ is either :keep (the reserved
      # unit stays counted) or :refund (the reserved unit is returned to
      # the window it was taken from).
      #
      # Returns true when this call was the one that took effect, false
      # when the reservation had already been settled (or its window is
      # long gone).
      def settle(outcome)
        @settle_mutex.synchronize do
          return false if @settled

          @settled = true
        end

        @cache.settle(@token, refund: outcome == :refund)
      end

      def settled?
        @settle_mutex.synchronize { @settled }
      end
    end
  end
end
