# frozen_string_literal: true

module Rack
  class Attack
    class Check
      attr_reader :name, :block, :type, :storage_failure_policy

      def initialize(name, options = {}, &block)
        @name = name
        @block = block
        @type = options.fetch(:type, nil)
        @storage_failure_policy = StoreFailure.policy_from(options)
      end

      def matched_by?(request)
        match = block.call(request)
        if match
          annotate_match(request)
          true
        else
          false
        end
      rescue StoreError => e
        # Only storage failures get policy handling; errors raised
        # inside the user rule block propagate as normal program errors.
        StoreFailure.handle(request, self, e)
      end

      private

      def annotate_match(request)
        request.env["rack.attack.matched"] = name
        request.env["rack.attack.match_type"] = type
        Rack::Attack.instrument(request)
      end
    end
  end
end
