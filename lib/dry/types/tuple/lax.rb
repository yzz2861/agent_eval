# frozen_string_literal: true

module Dry
  module Types
    class Tuple < Array
      # Lax tuple keeps values at invalid positions and coerces the rest.
      #
      # @api private
      class Lax < ::Dry::Types::Lax
        def call(input, &) = type.call_lax(input)
        alias_method :call_safe, :call
        alias_method :call_unsafe, :call

        def lax = self
      end
    end
  end
end
