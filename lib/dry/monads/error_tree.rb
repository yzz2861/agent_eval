# frozen_string_literal: true

module Dry
  module Monads
    # ErrorTree is an optional error carrier for {Validated}.
    #
    # Unlike a plain array of errors it keeps the information about the
    # location of every error inside a nested structure. Object keys and
    # array indices are encoded as path segments so the two never collide:
    # a key is kept as given while an index is always wrapped with {Index}.
    #
    # Several errors may share the same path, they are preserved as a list
    # in the order they were added. The carrier is a semigroup: trees are
    # merged with `+`, the merge keeps the stable order of both paths and
    # errors and never mutates the operands or the original error objects.
    #
    # @example building a tree
    #   tree = Dry::Monads::ErrorTree.new do |t|
    #     t.add(%i[addresses city], :blank)
    #     t.add([:addresses, ErrorTree::Index[0], :street], :blank)
    #   end
    #
    #   tree.errors
    #   # => {[:addresses, :city] => [:blank],
    #   #     [:addresses, ErrorTree::Index[0], :street] => [:blank]}
    #
    class ErrorTree
      include Dry::Equalizer(:errors)

      # Wraps an array index so it can be told apart from an object key.
      #
      class Index
        include Dry::Equalizer(:value)

        # @return [Integer]
        attr_reader :value

        # @param value [Integer]
        def initialize(value)
          @value = Integer(value)
        end

        class << self
          # Coerces the value to an {Index}.
          #
          # @param value [Integer, Index]
          # @return [Index]
          def [](value)
            value.is_a?(self) ? value : new(value)
          end
        end

        # @return [String]
        def inspect = "Index[#{@value.inspect}]"
        alias_method :to_s, :inspect
      end

      # @return [Hash{Array<Object> => Array<Object>}]
      attr_reader :errors

      # Builds a tree.
      #
      # @overload new(errors = {})
      #   @param errors [Hash{Array<Object> => Object, Array<Object>}]
      #     errors keyed by paths; a single value is wrapped with an array
      #
      # @overload new
      #   @yieldparam tree [ErrorTree::Builder] mutable builder, use {Builder#add}
      #   @return [ErrorTree]
      #
      def initialize(errors = nil)
        @errors = {}

        import(@errors, errors) if errors

        yield(Builder.new(@errors)) if block_given?

        @errors.freeze
        freeze
      end

      class << self
        # Builds a tree, see {#initialize}.
        #
        # @return [ErrorTree]
        def build(errors = nil, &block) = new(errors, &block)

        # @api private
        def wrap(value)
          value.is_a?(ErrorTree) ? value : new({ [] => value })
        end

        # @api private
        def normalize_path(path)
          Array(path).map do |segment|
            segment.is_a?(::Integer) ? Index.new(segment) : segment
          end
        end
      end

      # Registers one or more errors at the given path.
      #
      # @param path [Array<Object>] location of the error, integers are
      #   treated as array indices automatically
      # @param values [Object, Array<Object>] one or many error objects;
      #   the objects themselves are never copied or wrapped
      # @return [ErrorTree] a new tree
      #
      def add(path, *values)
        values = values.first if values.size == 1 && values[0].is_a?(::Array)

        merged = @errors.dup
        key = self.class.normalize_path(path)
        merged[key] = ((merged[key] || []) + values).freeze

        self.class.new(merged)
      end

      # Prepends every path with the given segments.
      #
      # @param prefix [Array<Object>] object keys and/or {Index} values
      # @return [ErrorTree] a new tree
      #
      def prepend(*prefix)
        return self if prefix.empty?

        head = self.class.normalize_path(prefix)

        self.class.new(
          @errors.transform_keys { |path| head + path }
        )
      end

      # Merges two trees keeping the order of paths and errors.
      # Neither tree nor the original error objects are mutated.
      #
      # @param other [ErrorTree]
      # @return [ErrorTree]
      #
      def +(other)
        other = self.class.wrap(other)

        merged = @errors.dup

        other.errors.each do |path, value|
          merged[path] = ((merged[path] || []) + value).freeze
        end

        self.class.new(merged)
      end

      # Whether the tree holds no errors.
      #
      # @return [Boolean]
      def empty? = @errors.empty?

      # Returns errors registered at the path.
      #
      # @param path [Array<Object>]
      # @return [Array<Object>]
      def [](path)
        @errors.fetch(self.class.normalize_path(path), EMPTY_ERRORS)
      end

      # @return [String]
      def inspect
        "ErrorTree(#{@errors.inspect})"
      end
      alias_method :to_s, :inspect

      # Mutable builder yielded by {ErrorTree.new} when a block is given.
      #
      class Builder
        # @api private
        def initialize(errors)
          @errors = errors
        end

        # Registers one or more errors at the given path.
        #
        # @param path [Array<Object>] integers are treated as array indices
        # @param values [Object, Array<Object>] error objects
        # @return [self]
        #
        def add(path, *values)
          values = values.first if values.size == 1 && values[0].is_a?(::Array)

          key = ErrorTree.normalize_path(path)
          @errors[key] = ((@errors[key] || []) + values).freeze

          self
        end
      end

      private

      def import(target, errors)
        errors.each do |path, value|
          values = value.is_a?(::Array) ? value : [value]
          key = self.class.normalize_path(path)
          target[key] = ((target[key] || []) + values).freeze
        end
      end

      EMPTY_ERRORS = [].freeze

      # Mixin with the {ErrorTree} constructor.
      #
      module Mixin
        # @see Dry::Monads::ErrorTree
        ErrorTree = ErrorTree

        # Actual constructor methods.
        #
        module Constructors
          # ErrorTree constructor
          #
          # @overload ErrorTree(errors = {})
          #   @param errors [Hash]
          #   @return [ErrorTree]
          #
          # @overload ErrorTree
          #   @yieldparam tree [ErrorTree]
          #   @return [ErrorTree]
          #
          def ErrorTree(errors = nil, &block)
            ErrorTree.new(errors, &block)
          end
        end

        include Constructors
      end
    end

    require "dry/monads/registry"
    register_mixin(:error_tree, ErrorTree::Mixin)
  end
end
