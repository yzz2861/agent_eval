# frozen_string_literal: true

module Dry
  module Types
    # A sum type that selects one branch directly from a tag value.
    #
    # Unlike Sum, the tag is read before a branch is called. Consequently,
    # branch constructors and default values only run for the selected branch.
    #
    # @api public
    class DiscriminatedUnion
      include Type
      include Options
      include Meta
      include Printable
      include ::Dry::Equalizer(
        :tag_path, :branches, :options, :meta,
        inspect: false,
        immutable: true
      )

      # @return [Array<Symbol, String>]
      attr_reader :tag_path

      # @return [Hash{Object => Type}]
      attr_reader :branches

      # @param [Symbol, String, Array<Symbol, String>] tag_or_path
      # @param [Hash{Object => Type}, Array<Array>] branches
      # @param [Hash] options
      #
      # @option options [Symbol, #call] :tag_transform
      #
      # @return [DiscriminatedUnion]
      #
      # @api public
      def self.new(tag_or_path, branches = Undefined, **options)
        tag_path = Array(tag_or_path)

        unless tag_path.any? && tag_path.all? { |key| key.is_a?(::Symbol) || key.is_a?(::String) }
          raise ::ArgumentError, "tag path must contain only Symbol or String keys"
        end

        if Undefined.equal?(branches)
          branch_input = options.dup
          branch_input.delete(:meta)
          branch_input.delete(:tag_transform)
        else
          branch_input = branches
        end

        pairs = normalize_branches(branch_input)
        transform = options[:tag_transform]

        unless transform.nil? || transform.is_a?(::Symbol) || transform.respond_to?(:call)
          raise ::ArgumentError, "tag_transform must be a Symbol or callable"
        end

        super(tag_path.freeze, pairs.to_h.freeze, **options)
      end

      # @api private
      def self.normalize_branches(branches)
        pairs =
          case branches
          when ::Hash
            branches.to_a
          when ::Array
            branches
          else
            raise ::ArgumentError, "branches must be a Hash or an Array of [tag, type] pairs"
          end

        unless pairs.any? && pairs.all? { |pair| pair.is_a?(::Array) && pair.length == 2 }
          raise ::ArgumentError, "branches must be a non-empty collection of [tag, type] pairs"
        end

        pairs.each do |tag, type|
          unless type.is_a?(Type)
            raise ::ArgumentError, "branch for #{tag.inspect} must be a Dry::Types type"
          end
        end

        pairs.each_with_object({}) do |(tag, _), seen|
          if seen.key?(tag)
            raise ::ArgumentError, "duplicate tag #{tag.inspect}"
          end

          seen[tag] = true
        end

        pairs
      end

      # @api private
      def self.build(
        first = Undefined,
        second = Undefined,
        branches: nil,
        tag: Undefined,
        path: nil,
        tag_transform: nil,
        &transform_block
      )
        branch_map = branches

        if branch_map
          unless Undefined.equal?(first) && Undefined.equal?(second)
            raise ::ArgumentError, "do not pass branches both positionally and as a keyword"
          end
          if !Undefined.equal?(tag) && path
            raise ::ArgumentError, "do not pass both tag and path"
          end

          tag_or_path = path || Undefined.default(tag, :kind)
        elsif second.nil? && (first.is_a?(::Hash) || first.is_a?(::Array))
          branch_map = first
          if !Undefined.equal?(tag) && path
            raise ::ArgumentError, "do not pass both tag and path"
          end

          tag_or_path = path || Undefined.default(tag, :kind)
        elsif !Undefined.equal?(first) && !Undefined.equal?(second)
          unless Undefined.equal?(tag)
            raise ::ArgumentError, "do not pass both a positional tag and tag:"
          end
          raise ::ArgumentError, "do not pass both a positional tag and path:" if path

          tag_or_path = first
          branch_map = second
        else
          raise ::ArgumentError, "branches must be provided as a Hash or [tag, type] pairs"
        end

        transform = tag_transform || transform_block
        new(tag_or_path, branch_map, tag_transform: transform)
      end

      # @api private
      def initialize(tag_path, branches, **options)
        super
        @tag_path = tag_path
        @branches = branches
        freeze
      end

      # @return [false]
      #
      # @api public
      def default? = false

      # @return [false]
      #
      # @api public
      def constrained? = false

      # @return [false]
      #
      # @api public
      def optional? = false

      # @param [Object] input
      #
      # @return [Object]
      #
      # @api private
      def call_unsafe(input)
        _tag, branch = resolve_branch(input)
        branch.call_unsafe(input)
      end

      # @param [Object] input
      #
      # @return [Object]
      #
      # @api private
      def call_safe(input, &block)
        _tag, branch = resolve_branch(input)
        branch.call_safe(input, &block)
      rescue TagValueError, MissingTagError => exception
        block ? block.call(build_failure(input, exception)) : raise
      end

      # @param [Object] input
      #
      # @return [Result::Success, Result::Failure]
      #
      # @api public
      def try(input)
        _tag, branch = resolve_branch(input)
        branch.try(input) do |failure|
          block_given? ? yield(failure) : failure
        end
      rescue MissingTagError, TagValueError => exception
        result = build_failure(input, exception)
        block_given? ? yield(result) : result
      end

      # @param [Object] value
      #
      # @return [Boolean]
      #
      # @api private
      def primitive?(value)
        _tag, branch = resolve_branch(value)
        branch.primitive?(value)
      rescue CoercionError
        false
      end

      # @api private
      def success(input) = Result::Success.new(input)

      # @api private
      def build_failure(input, error) = Result::Failure.new(input, error)

      # @param [Boolean] meta
      #
      # @return [Array]
      #
      # @api public
      def to_ast(meta: true)
        branch_nodes = branches.map { |tag, type| [tag, type.to_ast(meta: meta)] }
        options_ast = {}
        options_ast[:tag_transform] = transform_ast unless options[:tag_transform].nil?

        [
          :discriminated_union,
          [
            tag_path,
            branch_nodes,
            options_ast,
            meta ? self.meta : EMPTY_HASH
          ]
        ]
      end

      private

      # @return [Array(Object, Type)]
      #
      # @api private
      def resolve_branch(input)
        tag = read_tag(input)
        tag = transform_tag(tag)
        branch = branches[tag]

        if branch.nil?
          tag_classes = branches.keys.map(&:class).uniq

          if tag_classes.include?(tag.class)
            raise UnknownTagError.new(tag_path, tag, branches.keys)
          else
            raise InvalidTagError.new(tag_path, tag)
          end
        end

        [tag, branch]
      end

      # @api private
      def read_tag(input)
        current = input

        tag_path.each do |key|
          unless current.is_a?(::Hash)
            raise InvalidTagError.new(tag_path, current)
          end

          unless current.key?(key)
            raise MissingTagError.new(tag_path)
          end

          current = current.fetch(key)
        end

        current
      end

      # @api private
      def transform_tag(tag)
        case options[:tag_transform]
        when nil
          tag
        when ::Symbol
          tag.public_send(options[:tag_transform])
        else
          options[:tag_transform].call(tag)
        end
      rescue ::StandardError
        raise InvalidTagError.new(tag_path, tag)
      end

      # @api private
      def transform_ast
        case options[:tag_transform]
        when ::Symbol
          [:method, options[:tag_transform]]
        else
          [:callable, options[:tag_transform]]
        end
      end
    end
  end
end
