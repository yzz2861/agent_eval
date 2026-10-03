# frozen_string_literal: true

module Dry
  module Types
    class Stream < Nominal
      # Member streams apply a type to every yielded element
      #
      # @api public
      class Member < Stream
        # @return [Type]
        attr_reader :member

        # @param [Class] primitive
        # @param [Hash] options
        #
        # @option options [Type] :member
        # @option options [Symbol] :on_error either +:raise+ or +:continue+
        #
        # @api private
        def initialize(primitive, member:, on_error: :raise, error_mode: Undefined, **options)
          @member = member
          @on_error = self.class.error_mode(Undefined.default(error_mode, on_error))
          super(primitive, **options, member: member, on_error: @on_error)
        end

        # @param [Enumerator] input
        #
        # @return [Stream::Result]
        #
        # @api private
        def call_unsafe(input)
          if primitive?(input)
            build_result(input)
          else
            raise CoercionError, "#{input.inspect} must be an instance of #{primitive}"
          end
        end

        # @param [Enumerator] input
        #
        # @return [Stream::Result]
        #
        # @api private
        def call_safe(input, &block)
          if primitive?(input)
            build_result(input)
          else
            block.call
          end
        end

        # @param [Enumerator] input
        #
        # @return [Stream::Result, Result::Failure]
        #
        # @api public
        def try(input, &block)
          if primitive?(input)
            build_result(input)
          else
            failure = failure(
              input,
              CoercionError.new("#{input.inspect} must be an instance of #{primitive}")
            )
            block ? block.call(failure) : failure
          end
        end

        # @return [Symbol]
        #
        # @api public
        def on_error = @on_error

        # @return [Boolean]
        #
        # @api public
        def continue_on_error? = @on_error.equal?(:continue)

        # Build a lax type
        #
        # @return [Lax]
        #
        # @api public
        def lax
          Lax.new(
            Member.new(
              primitive,
              **options,
              member: member.lax,
              on_error: @on_error,
              meta: meta
            )
          )
        end

        # @see Nominal#to_ast
        #
        # @api public
        def to_ast(meta: true)
          member_ast = member.respond_to?(:to_ast) ? member.to_ast(meta: meta) : member
          [:stream, [member_ast, {on_error: @on_error}, meta_ast(meta)]]
        end

        # @api private
        def self.error_mode(value)
          ERROR_MODES.fetch(value) do
            raise ::ArgumentError,
                  "unknown stream error mode #{value.inspect}, use :raise or :continue"
          end
        end

        private

        # @api private
        def build_result(input)
          Result.new(input, member, on_error: @on_error)
        end

        # @api private
        def options_for_member
          options.except(:namespace, :member, :on_error)
        end
      end
    end
  end
end
