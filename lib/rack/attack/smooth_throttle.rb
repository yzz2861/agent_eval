# frozen_string_literal: true

module Rack
  class Attack
    # Weighted, smooth rate limiting backed by the Generic Cell Rate
    # Algorithm (virtual scheduling / GCRA).
    #
    # Unlike Throttle's fixed-window counters, the budget is replenished
    # continuously at +rate+ cost units per second, capped by a +burst+
    # allowance. Every request carries a cost computed from the request;
    # a request is admitted when its cost fits the remaining budget.
    #
    # State per discriminator is a single timestamp (the Theoretical
    # Arrival Time). Because admission needs an atomic read-compute-write,
    # the configured store must implement +#update+; see
    # Rack::Attack::Store::Memory. Stores without that primitive raise
    # Rack::Attack::AtomicStoreUnsupportedError instead of risking lost
    # updates.
    class SmoothThrottle
      MANDATORY_OPTIONS = %i[rate burst].freeze
      TIME_EPSILON = 1e-6 # Float tolerance at admission boundaries.

      attr_reader :name, :rate, :burst, :cost_block, :type, :clock

      def initialize(name, options, &block)
        @name = name
        @block = block

        MANDATORY_OPTIONS.each do |opt|
          raise ArgumentError, "Must pass #{opt.inspect} option" unless options.key?(opt)
        end

        @rate = options[:rate].to_f
        @burst = options[:burst].to_f
        @cost_block = options[:cost]
        @clock = options[:clock]
        @type = options.fetch(:type, :smooththrottle)

        if @rate <= 0
          raise ArgumentError, "Must pass a positive :rate, got #{options[:rate].inspect}"
        end
        raise ArgumentError, "Must pass a non-negative :burst, got #{options[:burst].inspect}" if @burst.negative?
      end

      def cache
        Rack::Attack.cache
      end

      def matched_by?(request)
        discriminator, cost = discriminator_and_cost_for(request)
        return false unless discriminator

        now = current_time(request).to_f

        data = {
          discriminator: discriminator,
          cost: cost,
          rate: rate,
          burst: burst,
          epoch_time: now
        }

        allowed, theoretical_arrival_time, retry_after = admit(discriminator, now, cost)

        data[:theoretical_arrival_time] = theoretical_arrival_time
        data[:retry_after] = retry_after

        annotate_request_with_throttle_data(request, data)

        allowed ? false : rejected(request, data)
      end

      private

      def admit(discriminator, now, cost)
        # Zero-cost requests never touch shared state and are always allowed.
        return [true, nil, nil] if cost.zero?

        # A single request can never fit. Don't go into debt: state stays
        # untouched and no finite wait time exists.
        return [false, nil, nil] if cost > burst

        # Keep the key around long enough for the fullest bucket to drain.
        expires_in = (burst / rate) + 1
        key = "#{name}:#{discriminator}"

        outcome = cache.atomic_update(key, expires_in) do |raw_value|
          previous_tat = raw_value ? raw_value.to_f : 0.0

          # Clamping to `now` handles backwards clock jumps fail-closed:
          # budget can never be earned from a timestamp in the future past.
          tat = (previous_tat > now ? previous_tat : now)
          projected_tat = tat + (cost / rate)
          allow_at = projected_tat - burst

          if now + TIME_EPSILON < allow_at
            retry_after = allow_at - now
            # Rejected requests leave state untouched.
            [raw_value, [:rejected, tat, retry_after]]
          else
            [serialize(projected_tat), [:allowed, projected_tat]]
          end
        end

        status, tat, retry_after = outcome
        [status == :allowed, tat, retry_after]
      end

      def rejected(request, data)
        annotate_request_with_matched_data(request, data)
        Rack::Attack.instrument(request)
        true
      end

      def serialize(timestamp)
        timestamp.to_s
      end

      def current_time(request)
        time_source = clock || Rack::Attack.smooth_throttle_clock
        time_source.call(request)
      end

      def discriminator_and_cost_for(request)
        result = @block.call(request)
        return nil unless result

        if result.is_a?(Array) && result.length == 2
          discriminator, raw_cost = result
        else
          discriminator = result
        end

        return nil unless discriminator

        discriminator = normalize_discriminator(discriminator)
        raw_cost = cost_block.call(request) if raw_cost.nil? && cost_block
        [discriminator, normalize_cost(raw_cost.nil? ? 1 : raw_cost)]
      end

      def normalize_discriminator(discriminator)
        if Rack::Attack.throttle_discriminator_normalizer
          Rack::Attack.throttle_discriminator_normalizer.call(discriminator)
        else
          discriminator
        end
      end

      def normalize_cost(cost)
        unless cost.is_a?(Numeric)
          raise ArgumentError, "Smooth throttle cost must be a non-negative number, got #{cost.inspect}"
        end

        cost = cost.to_f
        if cost.negative?
          raise ArgumentError, "Smooth throttle cost must be a non-negative number, got #{cost.inspect}"
        end

        cost
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
