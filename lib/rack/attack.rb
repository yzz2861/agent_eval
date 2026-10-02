# frozen_string_literal: true

require 'rack'
require 'forwardable'
require 'rack/attack/cache'
require 'rack/attack/configuration'
require 'rack/attack/path_normalizer'
require 'rack/attack/request'
require 'rack/attack/store_proxy/dalli_proxy'
require 'rack/attack/store_proxy/mem_cache_store_proxy'
require 'rack/attack/store_proxy/redis_proxy'
require 'rack/attack/store_proxy/redis_store_proxy'
require 'rack/attack/store_proxy/redis_cache_store_proxy'

require 'rack/attack/railtie' if defined?(::Rails)

module Rack
  class Attack
    class Error < StandardError; end

    class MisconfiguredStoreError < Error; end

    class MissingStoreError < Error; end

    class IncompatibleStoreError < Error; end

    autoload :Check,                'rack/attack/check'
    autoload :Throttle,             'rack/attack/throttle'
    autoload :Safelist,             'rack/attack/safelist'
    autoload :Blocklist,            'rack/attack/blocklist'
    autoload :Track,                'rack/attack/track'
    autoload :Fail2Ban,             'rack/attack/fail2ban'
    autoload :Allow2Ban,            'rack/attack/allow2ban'
    autoload :ShadowThrottle,       'rack/attack/shadow_throttle'

    class << self
      attr_accessor :enabled, :notifier, :throttle_discriminator_normalizer
      attr_reader :configuration

      def instrument(request)
        if notifier
          event_type = request.env["rack.attack.match_type"]
          notifier.instrument("#{event_type}.rack_attack", request: request)

          # Deprecated: Keeping just for backwards compatibility
          notifier.instrument("rack.attack", request: request)
        end
      end

      def instrument_shadow_throttle(throttle, request, data)
        return unless notifier

        notifier.instrument(
          "shadow_throttle.rack_attack",
          request_summary: {
            ip: request.ip,
            path: request.path,
            request_method: request.request_method
          },
          matched: throttle.name,
          match_type: :shadow_throttle,
          match_discriminator: data[:discriminator],
          match_data: data,
          hypothetical: true
        )
      end

      def cache
        @cache ||= Cache.new
      end

      def clear!
        warn "[DEPRECATION] Rack::Attack.clear! is deprecated. Please use Rack::Attack.clear_configuration instead"
        @configuration.clear_configuration
      end

      def reset!
        cache.reset!
      end

      extend Forwardable
      def_delegators(
        :@configuration,
        :safelist,
        :blocklist,
        :blocklist_ip,
        :safelist_ip,
        :throttle,
        :shadow_throttle,
        :track,
        :throttled_responder,
        :throttled_responder=,
        :blocklisted_responder,
        :blocklisted_responder=,
        :blocklisted_response,
        :blocklisted_response=,
        :throttled_response,
        :throttled_response=,
        :throttled_response_retry_after_header,
        :throttled_response_retry_after_header=,
        :clear_configuration,
        :safelists,
        :blocklists,
        :throttles,
        :shadow_throttles,
        :tracks
      )
    end

    # Set defaults
    @enabled = true
    @notifier = ActiveSupport::Notifications if defined?(ActiveSupport::Notifications)
    @throttle_discriminator_normalizer = lambda do |discriminator|
      discriminator.to_s.strip.downcase
    end
    @configuration = Configuration.new

    attr_reader :configuration

    def initialize(app)
      @app = app
      @configuration = self.class.configuration
    end

    def call(env)
      return @app.call(env) if !self.class.enabled || env["rack.attack.called"]

      env["rack.attack.called"] = true
      env['PATH_INFO'] = PathNormalizer.normalize_path(env['PATH_INFO'])
      request = Rack::Attack::Request.new(env)

      formal_result = formal_result_for(request)
      configuration.shadow_throttles?(request)

      if formal_result == :safelisted
        @app.call(env)
      elsif formal_result == :blocklisted
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        if configuration.blocklisted_response
          configuration.blocklisted_response.call(env)
        else
          configuration.blocklisted_responder.call(request)
        end
      elsif formal_result == :throttled
        # Deprecated: Keeping throttled_response for backwards compatibility
        if configuration.throttled_response
          configuration.throttled_response.call(env)
        else
          configuration.throttled_responder.call(request)
        end
      else
        @app.call(env)
      end
    end

    private

    def formal_result_for(request)
      if configuration.safelisted?(request)
        :safelisted
      elsif configuration.blocklisted?(request)
        :blocklisted
      elsif configuration.throttled?(request)
        :throttled
      else
        configuration.tracked?(request)
        :allowed
      end
    end
  end
end
