# frozen_string_literal: true

require 'digest'

module Rack
  class Attack
    class Throttle
      MANDATORY_OPTIONS = [:limit, :period].freeze

      FAILURE_POLICIES = { allow: :allow, deny: :deny }.freeze

      DISCRIMINATOR_FINGERPRINT_LENGTH = 12

      # Stable merge precedence when several rules disagree on one request.
      PRECEDENCE_STORE_UNAVAILABLE_DENY = 2
      PRECEDENCE_THROTTLED = 1

      StoreUnavailable = Struct.new(:name, :failure_policy, :discriminator_fingerprint, :error) do
        def deny?
          failure_policy == :deny
        end
      end

      attr_reader :name, :limit, :period, :block, :type, :failure_policy

      def initialize(name, options, &block)
        @name = name
        @block = block
        MANDATORY_OPTIONS.each do |opt|
          raise ArgumentError, "Must pass #{opt.inspect} option" unless options[opt]
        end
        @limit = options[:limit]
        @period = options[:period].respond_to?(:call) ? options[:period] : options[:period].to_i
        @type   = options.fetch(:type, :throttle)
        @failure_policy = options.fetch(:failure_policy, :allow)

        unless FAILURE_POLICIES.key?(@failure_policy)
          raise ArgumentError, "Unknown failure_policy #{@failure_policy.inspect}; " \
            "must be one of #{FAILURE_POLICIES.keys.inspect}"
        end
      end

      def cache
        Rack::Attack.cache
      end

      def matched_by?(request)
        evaluate(request) == :throttled
      end

      # Evaluates the rule without assuming the outcome:
      #   :throttled       - quota exhausted (real counter value)
      #   :allowed         - matched, but quota remains
      #   :unmatched       - rule block did not discriminate the request
      #   StoreUnavailable - a cache store call failed
      def evaluate(request)
        discriminator = discriminator_for(request)
        return :unmatched unless discriminator

        current_period = period_for(request)
        current_limit  = limit_for(request)

        begin
          count = cache.count("#{name}:#{discriminator}", current_period)
        rescue Rack::Attack::StoreError => error
          return store_unavailable(discriminator, error)
        end

        data = {
          discriminator: discriminator,
          count: count,
          period: current_period,
          limit: current_limit,
          epoch_time: cache.last_epoch_time
        }

        annotate_request_with_throttle_data(request, data)

        if count > current_limit
          :throttled
        else
          :allowed
        end
      end

      # Applies the shared "matched" annotation for this rule and notifies.
      # Called by Configuration once the merged winner is known, and by Track
      # which reports the match under the :track type.
      def annotate_match!(request, match_type = type)
        data = request.env['rack.attack.throttle_data'][name]

        request.env['rack.attack.matched']             = name
        request.env['rack.attack.match_discriminator'] = data[:discriminator]
        request.env['rack.attack.match_type']          = match_type
        request.env['rack.attack.match_data']          = data

        Rack::Attack.instrument(request)
      end

      private

      def discriminator_for(request)
        discriminator = block.call(request)
        if discriminator && Rack::Attack.throttle_discriminator_normalizer
          discriminator = Rack::Attack.throttle_discriminator_normalizer.call(discriminator)
        end
        discriminator
      end

      def period_for(request)
        period.respond_to?(:call) ? period.call(request) : period
      end

      def limit_for(request)
        limit.respond_to?(:call) ? limit.call(request) : limit
      end

      def annotate_request_with_throttle_data(request, data)
        (request.env['rack.attack.throttle_data'] ||= {})[name] = data
      end

      def store_unavailable(discriminator, error)
        fingerprint = fingerprint_discriminator(discriminator)

        Rack::Attack.instrument_store_error(
          rule_name: name,
          discriminator_fingerprint: fingerprint,
          error: error
        )

        StoreUnavailable.new(name, failure_policy, fingerprint, error)
      end

      def fingerprint_discriminator(discriminator)
        Digest::SHA256.hexdigest(discriminator.to_s)[0, DISCRIMINATOR_FINGERPRINT_LENGTH]
      end
    end
  end
end
