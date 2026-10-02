# frozen_string_literal: true

module Rack
  class Attack
    class Track
      attr_reader :filter

      def initialize(name, options = {}, &block)
        options[:type] = :track

        @filter =
          if options[:limit] && options[:period]
            Throttle.new(name, options, &block)
          else
            Check.new(name, options, &block)
          end
      end

      def matched_by?(request)
        if filter.is_a?(Throttle)
          matched_by_throttle?(request)
        else
          filter.matched_by?(request)
        end
      end

      private

      def matched_by_throttle?(request)
        outcome = filter.evaluate(request)
        return false unless outcome == :throttled

        filter.annotate_match!(request, :track)
        true
      end
    end
  end
end
