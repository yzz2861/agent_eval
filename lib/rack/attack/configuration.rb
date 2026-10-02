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

      DEFAULT_STORAGE_FAILURE_RESPONDER = lambda do |_req|
        [503, { 'content-type' => 'text/plain' }, ["Service unavailable\n"]]
      end

      attr_reader :safelists, :blocklists, :throttles, :tracks, :anonymous_blocklists, :anonymous_safelists
      attr_accessor :blocklisted_responder, :throttled_responder,
        :storage_failure_responder, :throttled_response_retry_after_header

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

      def safelist(name = nil, options = {}, &block)
        safelist = Safelist.new(name, options, &block)

        if name
          @safelists[name] = safelist
        else
          @anonymous_safelists << safelist
        end
      end

      def blocklist(name = nil, options = {}, &block)
        blocklist = Blocklist.new(name, options, &block)

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
        verdict_of(@anonymous_safelists, request) ||
          verdict_of(@safelists.values, request)
      end

      def blocklisted?(request)
        verdict_of(@anonymous_blocklists, request) ||
          verdict_of(@blocklists.values, request)
      end

      def throttled?(request)
        verdict_of(@throttles.values, request)
      end

      def tracked?(request)
        @tracks.each_value do |track|
          return true if Rack::Attack::StoreFailure.denied?(track.matched_by?(request))
        end
        false
      end

      def clear_configuration
        set_defaults
      end

      private

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
        @storage_failure_responder = DEFAULT_STORAGE_FAILURE_RESPONDER

        # Deprecated: Keeping these for backwards compatibility
        @blocklisted_response = nil
        @throttled_response = nil
      end

      # Evaluates every rule in definition order; a regular
      # match never short-circuits remaining rules so a
      # later :deny storage failure always joins the merge.
      # A :deny verdict wins the phase, otherwise any
      # regular match wins. Rule blocks raising non storage
      # errors propagate untouched.
      def verdict_of(rules, request)
        matched = false
        denied = false
        rules.each do |rule|
          verdict = rule.matched_by?(request)
          if Rack::Attack::StoreFailure.denied?(verdict)
            denied = true
          elsif verdict
            matched = true
          end
        end

        denied ? Rack::Attack::StoreFailure::DENY : matched
      end
    end
  end
end
