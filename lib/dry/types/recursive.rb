# frozen_string_literal: true

require "dry/core/equalizer"

module Dry
  module Types
    # A formally recursive type.
    #
    # A recursive type is a named, lazy reference into a {Recursive::Scope}.
    # Its underlying type is not built at definition time: the scope's
    # definition block is evaluated on the first application and the result
    # is cached afterwards.
    #
    # @example a self-referential type
    #   tree = Dry::Types::Recursive.define(:tree) do |rec|
    #     Dry::Types["nominal.hash"].schema(
    #       value: Dry::Types["nominal.integer"],
    #       children: Dry::Types["nominal.array"].of(rec)
    #     )
    #   end
    #
    # @example mutually recursive types
    #   tree = Dry::Types::Recursive::Scope.new do |scope|
    #     scope.register(:a) { Dry::Types["nominal.hash"].schema(b: scope[:b]) }
    #     scope.register(:b) { Dry::Types["nominal.hash"].schema(a: scope[:a]) }
    #   end[:a]
    #
    # @api public
    class Recursive
      include Type
      include Options
      include Meta
      include Builder
      include Printable
      include ::Dry::Equalizer(:name, :scope, :options, :meta, inspect: false, immutable: true)

      # Thread-local state used while dumping recursive types to AST
      #
      # @api private
      class DumpState
        attr_reader :expanded

        def initialize
          # Recursive types already expanded at least once in this dump
          @expanded = {}
        end

        # @param [Recursive] reference
        #
        # @return [Symbol] :expanded, :reference, :first
        #
        # @api private
        def visit!(reference)
          key = [reference.scope.scope_id, reference.ref_name]

          if @expanded.key?(key)
            :reference
          else
            @expanded[key] = true
            :first
          end
        end
      end

      # Define a self-referential type with a single named entry point
      #
      # @param [Symbol] name Name of the recursive entry
      # @param [#call] block Receives the lazy reference to the type itself
      #
      # @return [Recursive]
      #
      # @api public
      def self.define(name = :recursive, &block)
        raise ::ArgumentError, "a block is required" unless block

        scope = Scope.new
        scope.register(name) { block.call(scope[name]) }
        scope[name]
      end

      AST_STATE_KEY = :"dry-types.recursive-ast"

      # @api private
      def self.ast_stack
        ::Thread.current[AST_STATE_KEY] ||= []
      end

      # @return [Recursive::Scope] Scope this reference belongs to
      attr_reader :scope

      # @param [Symbol] name
      # @param [Recursive::Scope] scope
      # @param [Hash] options
      #
      # @api private
      def initialize(name, scope, **options)
        @name = name
        @scope = scope
        super(name, scope, **options)
        freeze
      end

      # Resolve and cache the underlying type
      #
      # @return [Type]
      #
      # @raise [AliasCycleError] when the name is part of an alias-only cycle
      #
      # @api private
      def resolve
        scope.resolve(@name)
      end

      # @return [String]
      #
      # @api public
      def name = @name.to_s

      # @return [Symbol]
      #
      # @api private
      def ref_name = @name

      # @return [Boolean]
      #
      # @api public
      def default?
        resolve.default?
      rescue AliasCycleError
        false
      end

      # @return [Boolean]
      #
      # @api public
      def constrained? = false

      # @return [Boolean]
      #
      # @api public
      def optional? = false

      # @param [Object] value
      #
      # @return [Boolean]
      #
      # @api private
      def primitive?(value)
        resolve.primitive?(value)
      rescue AliasCycleError
        false
      end

      # @param [Object] input
      #
      # @return [Object]
      #
      # @api private
      def call_unsafe(input)
        run(input) { |type, value| type.call_unsafe(value) }
      end

      # @param [Object] input
      #
      # @return [Object]
      #
      # @api private
      def call_safe(input, &)
        run(input) { |type, value| type.call_safe(value, &) }
      rescue CyclicDataError
        raise if Traversal.current
        raise unless block_given?

        yield(input)
      end

      # @param [Object] input
      #
      # @return [Result]
      #
      # @api public
      def try(input, &block)
        run(input) { |type, value| type.try(value, &block) }
      rescue CyclicDataError => exception
        raise if Traversal.current

        result = failure(input, exception)
        block ? block.(result) : result
      end

      # @return [Lax]
      #
      # @api public
      def lax = Lax.new(self)

      # @return [Proc]
      #
      # @api public
      def to_proc = proc { |value| call(value) }

      # @return [Array]
      #
      # @api public
      def to_ast(meta: true)
        stack = self.class.ast_stack
        top_level = stack.empty?
        state = stack.last || DumpState.new

        stack << state if top_level

        begin
          dump_ast(state, meta)
        ensure
          stack.pop if top_level
        end
      end

      # @api private
      def dump_ast(state, meta)
        case state.visit!(self)
        when :first
          [:recursive,
           [scope.scope_id, @name,
            resolve.to_ast(meta: meta),
            meta ? @meta : EMPTY_HASH]]
        when :reference
          [:recursive_ref, [scope.scope_id, @name, meta ? @meta : EMPTY_HASH]]
        end
      end

      # @return [Result::Failure]
      #
      # @api private
      def failure(input, error) = Result::Failure.new(input, error)

      private

      # Open a traversal on the outermost recursive application,
      # check the input is not already on the traversal path and
      # apply the resolved type.
      #
      # @api private
      def run(input)
        tracker = Traversal.current

        if tracker.nil?
          Traversal.open do
            apply(input) { |type, value| yield(type, value) }
          end
        else
          apply(input) { |type, value| yield(type, value) }
        end
      end

      # @api private
      def apply(input)
        tracker = Traversal.current
        tracker.enter(input)

        begin
          yield(resolve, input)
        ensure
          tracker.leave(input)
        end
      end
    end
  end
end
