# frozen_string_literal: true

module Dry
  module Types
    class Stream < Nominal
      # Member streams apply their member type to each element lazily, as
      # the resulting {Stream::Result} is being consumed
      #
      # @api public
      class Member < Stream
        # @return [Type]
        attr_reader :member

        # @return [Symbol] error strategy, :halt or :collect
        attr_reader :on_error

        # @param [Class] primitive
        # @param [Hash] options
        #
        # @option options [Type] :member
        # @option options [Symbol] :on_error
        #
        # @api private
        def initialize(primitive, **options)
          @member = options.fetch(:member)
          @on_error = options.fetch(:on_error, :halt)
          super
        end

        # Wraps the input into a lazy result without consuming it
        #
        # @param [#each] input
        #
        # @return [Stream::Result]
        #
        # @api private
        def call_unsafe(input)
          if primitive?(input)
            wrap(input)
          else
            raise CoercionError, "#{input.inspect} cannot be streamed: " \
              "it does not respond to #each"
          end
        end

        # @param [Object] input
        #
        # @return [Stream::Result]
        #
        # @api private
        def call_safe(input)
          if primitive?(input)
            wrap(input)
          else
            yield
          end
        end

        # @param [#each, Object] input
        # @param [#call,nil] block
        #
        # @yieldparam [Failure] failure
        # @yieldreturn [Result]
        #
        # @return [Result,Logic::Result]
        #
        # @api public
        def try(input, &block)
          if primitive?(input)
            success(wrap(input))
          else
            failure = failure(
              input,
              CoercionError.new(
                "#{input.inspect} cannot be streamed: it does not respond to #each"
              )
            )
            block ? yield(failure) : failure
          end
        end

        # Build a lax type
        #
        # @return [Lax]
        #
        # @api public
        def lax = Lax.new(Member.new(primitive, **options, member: member.lax, meta: meta))

        # @see Nominal#to_ast
        #
        # @api public
        def to_ast(meta: true)
          member_ast =
            if member.respond_to?(:to_ast)
              member.to_ast(meta: meta)
            else
              member
            end

          [:stream, [member_ast, {on_error: on_error}, meta_ast(meta)]]
        end

        private

        # @api private
        def wrap(input) = Result.new(input, member: member, on_error: on_error)
      end
    end
  end
end
