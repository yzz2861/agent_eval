# frozen_string_literal: true

module Rack
  class Cors
    # Structured result of matching an incoming Origin against the rules
    # declared with {Resources#origins}.
    #
    # String and Regexp rules produce a plain match with no per-origin
    # overrides, while a block rule may additionally return a Hash to decide
    # +credentials+ and +max_age+ for that specific source:
    #
    #   origins do |source, env|
    #     if TRUSTED_SITES.include?(source)
    #       { credentials: true, max_age: 600 }
    #     else
    #       true
    #     end
    #   end
    class OriginResult
      attr_reader :origin, :credentials, :max_age, :public_resource

      def initialize(origin, options = {})
        @origin = origin
        @credentials = options[:credentials]
        @max_age = options[:max_age]
        @public_resource = options.fetch(:public, false) == true
      end

      def public_resource?
        @public_resource
      end

      # A wildcard (public) match can never carry credentials. Returning a
      # result with both flags enabled is treated as a configuration error so
      # that Access-Control-Allow-Origin: * is never emitted together with
      # Access-Control-Allow-Credentials: true.
      def validate!
        return unless @public_resource && @credentials == true

        raise Resource::CorsMisconfigurationError
      end
    end
  end
end
