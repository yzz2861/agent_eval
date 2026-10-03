# frozen_string_literal: true

module Dry
  module Types
    class Stream < Nominal
      # @api private
      class Constructor < ::Dry::Types::Constructor
        # @api private
        def constructor_type = ::Dry::Types::Stream::Constructor

        # @return [Lax]
        #
        # @api public
        def lax = Lax.new(type.lax.constructor(fn, meta: meta))

        # @see Dry::Types::Stream#of
        #
        # @api public
        def of(member, **options)
          type.of(member, **options).constructor(fn, meta: meta)
        end
      end
    end
  end
end
