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
    autoload :Reservation,          'rack/attack/reservation'
    autoload :SettlingBody,         'rack/attack/settling_body'
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
        # A rejected request never reached the app, so any quota it
        # reserved is returned immediately.
        release_reservations(request)

        # Deprecated: Keeping throttled_response for backwards compatibility
        if configuration.throttled_response
          configuration.throttled_response.call(env)
        else
          configuration.throttled_responder.call(request)
        end
      else
        configuration.tracked?(request)
        call_app_with_settlement(env, request)
      end
    end

    private

    def release_reservations(request)
      reservations = request.env['rack.attack.reservations']
      return if reservations.nil?

      reservations.each_value { |reservation| reservation.settle(:refund) }
    end

    def call_app_with_settlement(env, request)
      reservations = request.env['rack.attack.reservations']
      return @app.call(env) if reservations.nil? || reservations.empty?

      begin
        status, headers, body = @app.call(env)
      rescue Exception
        # The app blew up before responding: the attempt is kept.
        settle_reservations(request, reservations, :error)
        raise
      end

      settling_body = SettlingBody.new(body) do |delivery|
        settle_reservations(request, reservations, delivery, status)
      end

      [status, headers, settling_body]
    end

    # Billing points:
    # * :delivered - response fully delivered; each throttle's refund rule
    #   (default: status < 400) decides keep vs. refund.
    # * :error     - the app raised, or the body raised while streaming;
    #   the reservation is kept.
    # * :closed    - the body was closed before full delivery (e.g. the
    #   client went away early); the reservation is kept.
    def settle_reservations(request, reservations, delivery, status = nil)
      reservations.each do |name, reservation|
        outcome = delivery == :delivered && refundable?(request, name, status) ? :refund : :keep
        reservation.settle(outcome)
      end
    end

    def refundable?(request, throttle_name, status)
      throttle = configuration.throttles[throttle_name]

      if throttle
        throttle.refund?(status, request)
      else
        Throttle::DEFAULT_REFUND_IF.call(status, request)
      end
    end
  end
end
