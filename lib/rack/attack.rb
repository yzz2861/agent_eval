# frozen_string_literal: true

require 'rack'
require 'forwardable'
require 'securerandom'
require 'rack/attack/cache'
require 'rack/attack/configuration'
require 'rack/attack/path_normalizer'
require 'rack/attack/request'
require 'rack/attack/store/memory_store'
require 'rack/attack/reservation_body'
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

    CLIENT_DISCONNECT_ERRORS = [
      EOFError,
      IOError,
      Errno::ECONNABORTED,
      Errno::ECONNRESET,
      Errno::EPIPE
    ].freeze

    autoload :Check,                'rack/attack/check'
    autoload :Throttle,             'rack/attack/throttle'
    autoload :Safelist,             'rack/attack/safelist'
    autoload :Blocklist,            'rack/attack/blocklist'
    autoload :Track,                'rack/attack/track'
    autoload :Fail2Ban,             'rack/attack/fail2ban'
    autoload :Allow2Ban,            'rack/attack/allow2ban'

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

      if configuration.safelisted?(request)
        @app.call(env)
      elsif configuration.blocklisted?(request)
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        if configuration.blocklisted_response
          configuration.blocklisted_response.call(env)
        else
          configuration.blocklisted_responder.call(request)
        end
      elsif configuration.throttled?(request)
        release_reservations(request)
        # Deprecated: Keeping throttled_response for backwards compatibility
        if configuration.throttled_response
          configuration.throttled_response.call(env)
        else
          configuration.throttled_responder.call(request)
        end
      else
        configuration.tracked?(request)
        call_with_reservations(env, request)
      end
    end

    private

    def call_with_reservations(env, request)
      reservations = request.env[Throttle::PENDING_RESERVATIONS_KEY]
      return @app.call(env) if reservations.nil? || reservations.empty?

      begin
        status, headers, body = @app.call(env)
      rescue => error
        settle_reservations(request, nil, error)
        raise
      end

      pending = reservations.select do |throttle, reservation|
        if throttle.charge?(status, nil)
          Rack::Attack.cache.settle(reservation, true)
          false
        else
          true
        end
      end
      request.env[Throttle::PENDING_RESERVATIONS_KEY] = pending
      return [status, headers, body] if pending.empty?

      settlement = ->(error) do
        finalize_reservations(request, pending, status, error)
      end
      [status, headers, ReservationBody.new(body, settlement)]
    end

    def finalize_reservations(request, reservations, status, error)
      remaining = request.env[Throttle::PENDING_RESERVATIONS_KEY] || []
      reservations.each do |throttle, reservation|
        keep = throttle.charge?(status, error)
        Rack::Attack.cache.settle(reservation, keep)
        remaining.delete([throttle, reservation])
      end
      request.env.delete(Throttle::PENDING_RESERVATIONS_KEY) if remaining.empty?
    end

    def settle_reservations(request, status, error)
      reservations = request.env.delete(Throttle::PENDING_RESERVATIONS_KEY) || []
      reservations.each do |throttle, reservation|
        Rack::Attack.cache.settle(reservation, throttle.charge?(status, error))
      end
    end

    def release_reservations(request)
      settle_reservations(request, nil, nil)
    end
  end
end
