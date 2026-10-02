# frozen_string_literal: true

module Rack
  class Attack
    # Smoothed, weighted rate limiter based on a token bucket (GCRA).
    #
    # Unlike Rack::Attack::Throttle, which counts requests inside fixed time
    # windows, WeightedThrottle refills capacity continuously at a sustained
    # +rate+ per +per+ seconds, admits bursts up to +burst+ cost units, and
    # charges each request a +cost+ computed from the request itself. This
    # makes it suitable for endpoints whose cost varies per request (e.g. an
    # export API) where fixed-window counting is too coarse.
    #
    # When a request is rejected, the match data carries a +:retry_after+
    # value: the number of seconds to wait until an equivalent request would
    # be accepted again.
    #
    # Bucket state must be updated atomically, so the configured cache store
    # must implement the Rack::Attack::AtomicStore contract (see
    # Rack::Attack::MemoryStore). Stores that only support read/write raise
    # Rack::Attack::IncompatibleStoreError.
    #
    # Example:
    #
    #   Rack::Attack.weighted_throttle("exports", rate: 10, per: 60, burst: 20,
    #     cost: ->(req) { req.path == "/export" ? 5 : 1 }) do |req|
    #     req.ip
    #   end
    class WeightedThrottle
      MANDATORY_OPTIONS = [:rate, :per, :burst].freeze

      DEFAULT_CLOCK = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

      Decision = Struct.new(:allowed, :retry_after, :new_tat) do
        def allowed?
          allowed
        end
      end

      attr_reader :name, :rate, :per, :burst, :cost, :block, :type, :clock

      def initialize(name, options, &block)
        @name = name
        @block = block
        MANDATORY_OPTIONS.each do |opt|
          raise ArgumentError, "Must pass #{opt.inspect} option" unless options[opt]
        end
        @rate  = options[:rate]
        @per   = options[:per]
        @burst = options[:burst]
        @cost  = options.fetch(:cost, 1)
        @clock = options.fetch(:clock, DEFAULT_CLOCK)
        @type  = options.fetch(:type, :throttle)

        validate_option(:rate, @rate)
        validate_option(:per, @per)
        validate_option(:burst, @burst)
      end

      def cache
        Rack::Attack.cache
      end

      def matched_by?(request)
        discriminator = discriminator_for(request)
        return false unless discriminator

        now = clock.call.to_f
        current_cost = cost_for(request)
        current_rate = rate_for(request)
        current_per = per_for(request)
        current_burst = burst_for(request)
        interval = emission_interval(current_rate, current_per)
        expires_in = (current_burst * interval).ceil + 1

        decision = nil
        cache.atomic_update("#{name}:#{discriminator}", expires_in: expires_in) do |stored_tat|
          decision = decide(stored_tat, now, current_cost, interval, current_burst)
          decision.new_tat
        end

        data = {
          discriminator: discriminator,
          cost: current_cost,
          rate: current_rate,
          per: current_per,
          burst: current_burst,
          retry_after: decision.retry_after
        }

        annotate_request_with_throttle_data(request, data)

        (!decision.allowed?).tap do |throttled|
          if throttled
            annotate_request_with_matched_data(request, data)
            Rack::Attack.instrument(request)
          end
        end
      end

      private

      # Token bucket expressed as GCRA: +stored_tat+ is the theoretical
      # arrival time at which the bucket will have fully drained. A request
      # costing +cost+ units is admitted when the bucket holds at least that
      # much capacity, i.e. when the drained level stays within +burst+.
      def decide(stored_tat, now, cost, interval, burst)
        tat = stored_tat || now
        # A clock moving backwards must not free up extra capacity: keep the
        # furthest known arrival time instead of trusting the wall clock.
        tat = now if tat < now

        headroom = (burst - cost) * interval
        allowed = (tat - now) <= headroom
        retry_after = allowed ? 0.0 : (tat - now) - headroom
        new_tat = allowed ? tat + cost * interval : stored_tat

        Decision.new(allowed, retry_after, new_tat)
      end

      def emission_interval(rate, per)
        interval = per.to_f / rate.to_f
        unless interval.positive? && interval.finite?
          raise ArgumentError, "weighted throttle #{name.inspect} requires a positive, finite rate/per"
        end
        interval
      end

      def discriminator_for(request)
        discriminator = block.call(request)
        if discriminator && Rack::Attack.throttle_discriminator_normalizer
          discriminator = Rack::Attack.throttle_discriminator_normalizer.call(discriminator)
        end
        discriminator
      end

      def cost_for(request)
        value = cost.respond_to?(:call) ? cost.call(request) : cost
        value = Float(value)
        value.negative? ? 0.0 : value
      end

      def rate_for(request)
        (rate.respond_to?(:call) ? rate.call(request) : rate).to_f
      end

      def per_for(request)
        (per.respond_to?(:call) ? per.call(request) : per).to_f
      end

      def burst_for(request)
        (burst.respond_to?(:call) ? burst.call(request) : burst).to_f
      end

      def validate_option(option, value)
        return if value.respond_to?(:call)

        begin
          numeric = Float(value)
        rescue TypeError, ArgumentError
          raise ArgumentError, "Must pass a numeric #{option.inspect} option"
        end

        valid = option == :burst ? numeric >= 0 : numeric.positive?
        raise ArgumentError, "Must pass a positive #{option.inspect} option" unless valid
      end

      def annotate_request_with_throttle_data(request, data)
        (request.env['rack.attack.throttle_data'] ||= {})[name] = data
      end

      def annotate_request_with_matched_data(request, data)
        request.env['rack.attack.matched']             = name
        request.env['rack.attack.match_discriminator'] = data[:discriminator]
        request.env['rack.attack.match_type']          = type
        request.env['rack.attack.match_data']          = data
      end
    end
  end
end
