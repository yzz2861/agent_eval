# frozen_string_literal: true

module Dry
  module Types
    class Tuple < Array
      # @api private
      class Constructor < ::Dry::Types::Constructor
        def constructor_type = ::Dry::Types::Tuple::Constructor

        # @return [Tuple::Lax]
        #
        # @api public
        def lax = type.lax.constructor(fn, meta: meta)
      end
    end
  end
end
