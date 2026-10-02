# frozen_string_literal: true

require "ipaddr"

module Rack
  class Attack
    class Configuration
      DEFAULT_BLOCKLISTED_RESPONDER = lambda { |_req| [403, { 'content-type' => 'text/plain' }, ["Forbidden\n"]] }

      DEFAULT_THROTTLED_RESPONDER = lambda do |req|
        if Rack::Attack.configuration.throttled_response_retry_after_header
          match_data = req.env['rack.attack.match_data']
          now = match_data[:epoch_time]
          retry_after = match_data[:period] - (now % match_data[:period])

          [429, { 'content-type' => 'text/plain', 'retry-after' => retry_after.to_s }, ["Retry later\n"]]
        else
          [429, { 'content-type' => 'text/plain' }, ["Retry later\n"]]
        end
      end

      DEFAULT_STORE_UNAVAILABLE_RESPONDER = lambda do |_req|
        [503, { 'content-type' => 'text/plain' }, ["Service Unavailable\n"]]
      end

      attr_reader :safelists, :blocklists, :throttles, :tracks, :anonymous_blocklists, :anonymous_safelists
      attr_accessor :blocklisted_responder, :throttled_responder, :store_unavailable_responder,
                    :throttled_response_retry_after_header

      attr_reader :blocklisted_response, :throttled_response # Keeping these for backwards compatibility

      def blocklisted_response=(responder)
        warn "[DEPRECATION] Rack::Attack.blocklisted_response is deprecated. "\
          "Please use Rack::Attack.blocklisted_responder instead."
        @blocklisted_response = responder
      end

      def throttled_response=(responder)
        warn "[DEPRECATION] Rack::Attack.throttled_response is deprecated. "\
          "Please use Rack::Attack.throttled_responder instead"
        @throttled_response = responder
      end

      def initialize
        set_defaults
      end

      def safelist(name = nil, &block)
        safelist = Safelist.new(name, &block)

        if name
          @safelists[name] = safelist
        else
          @anonymous_safelists << safelist
        end
      end

      def blocklist(name = nil, &block)
        blocklist = Blocklist.new(name, &block)

        if name
          @blocklists[name] = blocklist
        else
          @anonymous_blocklists << blocklist
        end
      end

      def blocklist_ip(ip_address)
        @anonymous_blocklists << Blocklist.new do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def safelist_ip(ip_address)
        @anonymous_safelists << Safelist.new do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def throttle(name, options, &block)
        @throttles[name] = Throttle.new(name, options, &block)
      end

      def track(name, options = {}, &block)
        @tracks[name] = Track.new(name, options, &block)
      end

      def safelisted?(request)
        @anonymous_safelists.any? { |safelist| safelist.matched_by?(request) } ||
          @safelists.any? { |_name, safelist| safelist.matched_by?(request) }
      end

      def blocklisted?(request)
        @anonymous_blocklists.any? { |blocklist| blocklist.matched_by?(request) } ||
          @blocklists.any? { |_name, blocklist| blocklist.matched_by?(request) }
      end

      def throttled?(request)
        throttle_outcome(request) == :throttled
      end

      def store_unavailable?(request)
        throttle_outcome(request) == :store_unavailable
      end

      # Evaluates all throttle rules in declaration order and merges their
      # outcomes with a stable precedence: fail-closed (backend unavailable
      # with failure_policy: :deny) beats quota exhaustion, which beats
      # fail-open. Returns :throttled, :store_unavailable or nil.
      def throttle_outcome(request)
        env = request.env
        return env['rack.attack.throttle_outcome'] if env.key?('rack.attack.throttle_outcome')

        outcome = compute_throttle_outcome(request)
        env['rack.attack.throttle_outcome'] = outcome
        outcome
      end

      def tracked?(request)
        @tracks.each_value do |track|
          track.matched_by?(request)
        end
      end

      def clear_configuration
        set_defaults
      end

      private

      def compute_throttle_outcome(request)
        @throttle_outcome_winner = nil

        @throttles.each_value do |throttle|
          consider_outcome(throttle, throttle.evaluate(request))
        end

        finalize_throttle_outcome(request)
      end

      def consider_outcome(throttle, outcome)
        precedence = outcome_precedence(outcome)
        return unless precedence.positive?

        @throttle_outcome_winner ||= { precedence: -1 }
        return unless precedence > @throttle_outcome_winner[:precedence]

        @throttle_outcome_winner =
          if outcome.is_a?(Rack::Attack::Throttle::StoreUnavailable)
            {
              precedence: precedence,
              kind: :store_unavailable,
              throttle: throttle,
              result: outcome
            }
          else
            {
              precedence: precedence,
              kind: outcome,
              throttle: throttle
            }
          end
      end

      def outcome_precedence(outcome)
        case outcome
        when Rack::Attack::Throttle::StoreUnavailable
          outcome.deny? ? Rack::Attack::Throttle::PRECEDENCE_STORE_UNAVAILABLE_DENY : 0
        when :throttled
          Rack::Attack::Throttle::PRECEDENCE_THROTTLED
        else
          0
        end
      end

      def finalize_throttle_outcome(request)
        return nil unless @throttle_outcome_winner

        winner = @throttle_outcome_winner

        if winner[:kind] == :store_unavailable
          annotate_store_unavailable(request, winner[:throttle], winner[:result])
          :store_unavailable
        elsif winner[:kind] == :throttled
          clear_throttle_match_annotation(request)
          winner[:throttle].annotate_match!(request)
          :throttled
        else
          nil
        end
      ensure
        @throttle_outcome_winner = nil
      end

      def clear_throttle_match_annotation(request)
        request.env.delete('rack.attack.matched')
        request.env.delete('rack.attack.match_type')
        request.env.delete('rack.attack.match_data')
        request.env.delete('rack.attack.match_discriminator')
      end

      def annotate_store_unavailable(request, throttle, result)
        clear_throttle_match_annotation(request)
        request.env['rack.attack.matched']    = throttle.name
        request.env['rack.attack.match_type'] = :store_unavailable
        request.env['rack.attack.match_data'] = {
          failure_policy: result.failure_policy,
          discriminator_fingerprint: result.discriminator_fingerprint,
          error: result.error.class.name
        }
      end

      def set_defaults
        @safelists = {}
        @blocklists = {}
        @throttles = {}
        @tracks = {}
        @anonymous_blocklists = []
        @anonymous_safelists = []
        @throttled_response_retry_after_header = false

        @blocklisted_responder = DEFAULT_BLOCKLISTED_RESPONDER
        @throttled_responder = DEFAULT_THROTTLED_RESPONDER
        @store_unavailable_responder = DEFAULT_STORE_UNAVAILABLE_RESPONDER

        # Deprecated: Keeping these for backwards compatibility
        @blocklisted_response = nil
        @throttled_response = nil
      end
    end
  end
end
