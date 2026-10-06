# frozen_string_literal: true

module Dry
  module Configurable
    # A provider-specific reference to a secret value.
    #
    # @api public
    class SecretRef
      include Dry::Equalizer(:key, inspect: false)

      # @api public
      attr_reader :key

      # @api public
      def initialize(key)
        @key = key
        freeze
      end

      # @api public
      def inspect
        "#<#{self.class} #{key.inspect}>"
      end

      # @api public
      alias_method :to_s, :inspect
    end
  end
end
