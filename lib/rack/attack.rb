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

    class << self
      attr_accessor :enabled, :notifier, :throttle_discriminator_normalizer, :storage_failure_policy
      attr_reader :configuration

      def instrument(request)
        if notifier
          event_type = request.env["rack.attack.match_type"]
          notifier.instrument("#{event_type}.rack_attack", request: request)

          # Deprecated: Keeping just for backwards compatibility
          notifier.instrument("rack.attack", request: request)
        end
      end

      def instrument_storage_failure(request, record)
        return unless notifier

        notifier.instrument("storage_failure.rack_attack", request: request, failure: record)
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
        :storage_failure_responder,
        :storage_failure_responder=,
        :clear_configuration,
        :safelists,
        :blocklists,
        :throttles,
        :tracks
      )
    end

    # Set defaults
    @enabled = true
    @notifier = ActiveSupport::Notifications if defined?(ActiveSupport::Notifications)
    @storage_failure_policy = :allow
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

      verdict = match_request(request)

      case verdict
      when StoreFailure::DENY
        configuration.storage_failure_responder.call(request)
      when :safelist
        @app.call(env)
      when :blocklist
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        if configuration.blocklisted_response
          configuration.blocklisted_response.call(env)
        else
          configuration.blocklisted_responder.call(request)
        end
      when :throttle
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

    # Runs all rules in their stable phase order (safelist,
    # blocklist, throttle, track). Within a phase every rule is
    # evaluated in definition order; matches and failures no longer
    # short-circuit each other so a later :deny policy still counts.
    #
    # The merge precedence, highest first, is:
    #   1. an explicit safelist match
    #   2. any storage failure declared with policy :deny
    #   3. an explicit blocklist match
    #   4. an explicit throttle match ("quota exhausted")
    #   5. storage failures with policy :allow (request proceeds)
    def match_request(request)
      safelist = configuration.safelisted?(request)
      return StoreFailure::DENY if StoreFailure.denied?(safelist)
      return :safelist if safelist

      blocklist = configuration.blocklisted?(request)
      return StoreFailure::DENY if StoreFailure.denied?(blocklist)
      return :blocklist if blocklist

      throttle = configuration.throttled?(request)
      return StoreFailure::DENY if StoreFailure.denied?(throttle)
      return :throttle if throttle

      return StoreFailure::DENY if configuration.tracked?(request)

      nil
    end
  end
end

require 'rack/attack/store_failure'
