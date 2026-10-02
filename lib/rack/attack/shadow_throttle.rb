# frozen_string_literal: true

module Rack
  class Attack
    class ShadowThrottle < Throttle
      def initialize(name, options, &block)
        super
        @type = :shadow_throttle
      end

      def matched_by?(request)
        shadow_request = request.class.new(request.env.dup)
        data = throttle_data_for(shadow_request)
        return false unless data

        return false unless data[:count] > data[:limit]

        instrument_match(shadow_request, data)
        true
      end

      private

      def count_key(discriminator)
        "shadow:#{name}:#{discriminator}"
      end

      def instrument_match(request, data)
        Rack::Attack.instrument_shadow_throttle(self, request, data)
      end
    end
  end
end
