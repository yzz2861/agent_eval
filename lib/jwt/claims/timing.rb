# frozen_string_literal: true

module JWT
  module Claims
    # The Timing class verifies relations between the temporal claims
    # ('iat', 'nbf' and 'exp') of a JWT token.
    #
    # The supported, freely composable relations are:
    # - max_lifetime:    the span between 'iat' and 'exp' must not exceed the given number of seconds.
    # - max_future_iat:  the 'iat' claim must not be more than the given number of seconds ahead of the current time.
    # - order:           the given claims must appear in non-decreasing order, e.g. [:iat, :nbf, :exp].
    #
    # All relations are evaluated against a single, injectable current time ('now').
    # The leeway is applied exactly once, to the relation comparing 'iat' against 'now',
    # and never relaxes the relations between the claims themselves.
    class Timing
      # The temporal claims taking part in the relations.
      CLAIMS = %i[iat nbf exp].freeze

      # Initializes a new Timing instance.
      #
      # @param now [Time, Numeric] the current time all relations are evaluated against. Default: Time.now.
      # @param leeway [Numeric] the clock drift (in seconds) tolerated when comparing 'iat' against the current time. Default: 0.
      # @param required [Array<Symbol, String>] temporal claims that must be present in the payload. Default: none.
      # @param max_lifetime [Numeric] the maximum allowed span (in seconds) between 'iat' and 'exp'. Default: not verified.
      # @param max_future_iat [Numeric] the maximum allowed number of seconds 'iat' may be ahead of the current time. Default: not verified.
      # @param order [Array<Symbol, String>] the claims that must be in non-decreasing order, e.g. [:iat, :nbf, :exp]. Default: not verified.
      def initialize(now: nil, leeway: 0, required: [], max_lifetime: nil, max_future_iat: nil, order: nil)
        @now = now
        @leeway = leeway || 0
        @required = Array(required).map(&:to_s)
        @max_lifetime = max_lifetime
        @max_future_iat = max_future_iat
        @order = order && Array(order).map(&:to_s)

        validate_claim_names!
      end

      # Verifies the configured timing relations for the JWT token.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::MissingRequiredClaim] if a required temporal claim is missing.
      # @raise [JWT::InvalidPayload] if a temporal claim is not a finite numeric time.
      # @raise [JWT::InvalidTimingError] if a timing relation is violated.
      # @return [nil]
      def verify!(context:, **_args)
        return unless context.payload.is_a?(Hash)

        times = resolve_times(context.payload)
        verify_required!(times)

        verify_lifetime!(times)
        verify_future_iat!(times)
        verify_order!(times)
        nil
      end

      private

      attr_reader :leeway, :required, :max_lifetime, :max_future_iat, :order

      def validate_claim_names!
        unknown = (required + (order || [])) - CLAIMS.map(&:to_s)
        return if unknown.empty?

        raise ArgumentError, "Unknown temporal claims in timing policy: #{unknown.join(', ')}"
      end

      def resolve_times(payload)
        CLAIMS.each_with_object({}) do |claim, times|
          key = claim.to_s
          next unless payload.key?(key)

          value = parse_time(payload[key])
          raise JWT::InvalidPayload, "#{key} claim must be a finite numeric value" if value.nil?

          times[key] = value
        end
      end

      def parse_time(value)
        numeric =
          case value
          when ::Numeric then value.to_f
          when ::String then parse_string_time(value)
          end
        numeric if numeric && numeric.finite?
      end

      def parse_string_time(value)
        Float(value)
      rescue ArgumentError, TypeError
        nil
      end

      def current_time
        value = @now || Time.now
        value = value.to_f if value.is_a?(Time)
        time = parse_time(value)
        raise ArgumentError, 'now must be a finite numeric time' if time.nil?

        time
      end

      def verify_required!(times)
        required.each do |claim|
          raise JWT::MissingRequiredClaim, "Missing required claim #{claim}" unless times.key?(claim)
        end
      end

      def verify_lifetime!(times)
        return unless max_lifetime

        iat = times['iat']
        exp = times['exp']
        return unless iat && exp

        lifetime = exp - iat
        return if lifetime <= max_lifetime

        raise JWT::InvalidTimingError,
              "Invalid timing relation exp - iat <= max_lifetime: token lifetime #{lifetime} seconds exceeds the maximum of #{max_lifetime} seconds"
      end

      def verify_future_iat!(times)
        return unless max_future_iat

        iat = times['iat']
        return unless iat

        now = current_time
        return if iat <= now + leeway + max_future_iat

        raise JWT::InvalidTimingError,
              "Invalid timing relation iat - now <= max_future_iat: iat #{iat} is more than #{max_future_iat} seconds (leeway #{leeway}) ahead of the current time #{now}"
      end

      def verify_order!(times)
        return unless order

        present = order.select { |claim| times.key?(claim) }
        present.each_cons(2) do |earlier, later|
          from = times[earlier]
          to = times[later]
          next if from <= to

          raise JWT::InvalidTimingError,
                "Invalid timing relation #{earlier} <= #{later}: #{earlier} #{from} is after #{later} #{to}"
        end
      end
    end
  end
end
