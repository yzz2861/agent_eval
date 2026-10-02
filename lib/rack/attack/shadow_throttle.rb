# frozen_string_literal: true

module Rack
  class Attack
    # A ShadowThrottle observes traffic without affecting it. It counts and
    # matches like a regular Throttle, but under an isolated cache namespace,
    # and it never changes the response or the real rules' match data.
    class ShadowThrottle < Throttle
      attr_reader :shadow_name

      def initialize(name, options, &block)
        @shadow_name = name
        # Prefixing the throttle name keeps shadow counters isolated from the
        # real rules' counters, even when both use the same rule name.
        super("shadow:#{name}", options.merge(type: :shadow_throttle), &block)
      end

      private

      def annotate_request_with_throttle_data(request, data)
        (request.env['rack.attack.shadow_throttle_data'] ||= {})[shadow_name] = data
      end

      def annotate_request_with_matched_data(request, data)
        (request.env['rack.attack.shadow_matches'] ||= {})[shadow_name] = data
      end

      def instrument_match(request, data)
        Rack::Attack.instrument_shadow(request, shadow_name, data)
      end
    end
  end
end
