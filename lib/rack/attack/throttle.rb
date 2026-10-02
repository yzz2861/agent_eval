# frozen_string_literal: true

module Rack
  class Attack
    class Throttle
      MANDATORY_OPTIONS = [:limit, :period].freeze
      PENDING_RESERVATIONS_KEY = 'rack.attack.reservations'.freeze

      attr_reader :name, :limit, :period, :block, :type

      def initialize(name, options, &block)
        @name = name
        @block = block
        MANDATORY_OPTIONS.each do |opt|
          raise ArgumentError, "Must pass #{opt.inspect} option" unless options[opt]
        end
        @limit = options[:limit]
        @period = options[:period].respond_to?(:call) ? options[:period] : options[:period].to_i
        @type   = options.fetch(:type, :throttle)
        @reserve = options.fetch(:reserve, false)
        @failure = options.fetch(:failed_if, method(:failed_attempt?))
      end

      def cache
        Rack::Attack.cache
      end

      def matched_by?(request)
        discriminator = discriminator_for(request)
        return false unless discriminator

        current_period  = period_for(request)
        current_limit   = limit_for(request)
        count, reservation = count_for(
          "#{name}:#{discriminator}",
          current_period,
          current_limit
        )

        data = {
          discriminator: discriminator,
          count: count,
          period: current_period,
          limit: current_limit,
          epoch_time: cache.last_epoch_time
        }

        annotate_request_with_throttle_data(request, data)

        (count > current_limit).tap do |throttled|
          if throttled
            annotate_request_with_matched_data(request, data)
            Rack::Attack.instrument(request)
          elsif reservation&.accepted?
            pending_reservations(request) << [self, reservation]
          end
        end
      end

      def charge?(status, error)
        @failure.call(status, error)
      end

      private

      def count_for(key, current_period, current_limit)
        unless @reserve
          return [cache.count(key, current_period), nil]
        end

        reservation = cache.reserve(key, current_period, current_limit)
        count = reservation.accepted? ? reservation.count : reservation.count + 1
        [count, reservation]
      end

      def pending_reservations(request)
        request.env[PENDING_RESERVATIONS_KEY] ||= []
      end

      def failed_attempt?(status, error)
        return false if client_disconnect_error?(error)
        return true if error
        return status.to_i >= 400 if status

        false
      end

      def client_disconnect_error?(error)
        return false unless error

        Rack::Attack::CLIENT_DISCONNECT_ERRORS.any? { |klass| error.is_a?(klass) }
      end

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

      def annotate_request_with_matched_data(request, data)
        request.env['rack.attack.matched']             = name
        request.env['rack.attack.match_discriminator'] = data[:discriminator]
        request.env['rack.attack.match_type']          = type
        request.env['rack.attack.match_data']          = data
      end
    end
  end
end
