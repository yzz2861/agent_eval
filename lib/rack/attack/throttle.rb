# frozen_string_literal: true

module Rack
  class Attack
    class Throttle
      MANDATORY_OPTIONS = [:limit, :period].freeze

      # Default settlement rule for reserve-and-settle throttles: a
      # delivered response is refunded (not counted) when its status is
      # below 400. Anything else keeps the reserved unit.
      DEFAULT_REFUND_IF = lambda { |status, _request| status.to_i < 400 }

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
        @refund_if = options[:refund_if]
      end

      def cache
        Rack::Attack.cache
      end

      def reserve?
        @reserve
      end

      def refund?(status, request)
        (@refund_if || DEFAULT_REFUND_IF).call(status, request)
      end

      def matched_by?(request)
        discriminator = discriminator_for(request)
        return false unless discriminator

        current_period  = period_for(request)
        current_limit   = limit_for(request)
        count           = count_for(request, "#{name}:#{discriminator}", current_period)

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
          end
        end
      end

      private

      def count_for(request, key, current_period)
        if reserve?
          reservation = cache.reserve(key, current_period)
          (request.env['rack.attack.reservations'] ||= {})[name] = reservation
          reservation.count
        else
          cache.count(key, current_period)
        end
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
