# frozen_string_literal: true

require "dry/core/equalizer"

module Dry
  module Types
    # Discriminated (tagged) union type
    #
    # Picks exactly one branch based on the value of a tag read from the
    # input. Unlike {Sum}, branches are never tried in turn: the tag is read
    # first, so default values and constructors of non-selected (and even
    # selected-but-not-yet-applied) branches are not evaluated.
    #
    # @see BuilderMethods#DiscriminatedUnion
    #
    # @api public
    class DiscriminatedUnion
      include Type
      include Builder
      include Options
      include Meta
      include Printable
      include ::Dry::Core::Equalizer(
        :mapping, :options, :meta,
        inspect: false,
        immutable: true
      )

      # @return [Hash{Object => Type}] tag value to branch type
      #
      # @api public
      attr_reader :mapping

      # @param [Hash{Object => Type}] mapping tag value to branch type
      # @param [Array<Symbol, String>] tag_path path to the tag in the input
      # @param [#call, nil] tag_transform optional explicit tag coercion
      # @param [Hash] options
      #
      # @api private
      def initialize(mapping, tag_path:, tag_transform: nil, **options)
        validate_mapping(mapping)

        @mapping = mapping.freeze
        @tag_path = tag_path.freeze
        @tag_transform = tag_transform

        super(mapping, **options)
        freeze
      end

      # Rebuild the union with new options/meta while preserving the
      # discriminator configuration
      #
      # @return [DiscriminatedUnion]
      #
      # @api private
      def with(**new_options)
        if new_options.empty?
          self
        else
          self.class.new(
            mapping,
            tag_path: @tag_path,
            tag_transform: @tag_transform,
            **options,
            **new_options
          )
        end
      end

      # @return [Array<Symbol, String>]
      #
      # @api public
      def tag_path = @tag_path

      # @return [#call, nil]
      #
      # @api public
      def tag_transform = @tag_transform

      # @return [Array<Type>]
      #
      # @api public
      def branches = mapping.values

      # @return [Array<Object>]
      #
      # @api public
      def tags = mapping.keys

      # Wrap the union with a proc
      #
      # @return [Proc]
      #
      # @api public
      def to_proc = proc { |input| call(input) }

      # @return [String]
      #
      # @api public
      def name
        "DiscriminatedUnion(#{@tag_path.map(&:inspect).join(" -> ")})"
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

      # Look up the branch matching the tag without applying it
      #
      # @param [Object] input
      #
      # @return [Type]
      #
      # @raise [MissingTagError, UnknownTagError, InvalidTagError]
      #
      # @api public
      def branch_for(input)
        tag = extract_tag(input)

        mapping.fetch(tag) do
          raise UnknownTagError.new(tag, mapping.keys, @tag_path)
        end
      end

      # @param [Object] input
      #
      # @return [Object]
      #
      # @api private
      def call_unsafe(input) = branch_for(input).call_unsafe(input)

      # @param [Object] input
      #
      # @return [Object]
      #
      # @api private
      def call_safe(input, &block)
        branch_for(input).call_safe(input, &block)
      rescue DiscriminatorError
        raise unless block

        yield(input)
      end

      # @param [Object] input
      #
      # @return [Result]
      #
      # @api public
      def try(input)
        branch_for(input).try(input)
      rescue DiscriminatorError => error
        result = failure(input, error)
        block_given? ? yield(result) : result
      end

      # @param [Object] input
      #
      # @return [Result::Success]
      #
      # @api public
      def success(input) = Result::Success.new(input)

      # @param [Object] input
      # @param [CoercionError] error
      #
      # @return [Result::Failure]
      #
      # @api public
      def failure(input, error) = Result::Failure.new(input, error)

      # @param [Object] value
      #
      # @return [Boolean]
      #
      # @api private
      def primitive?(value)
        branch_for(value).primitive?(value)
      rescue DiscriminatorError
        false
      end

      # @see Nominal#to_ast
      #
      # @return [Array]
      #
      # @api public
      def to_ast(meta: true)
        branches = mapping.map { |tag, type| [tag, type.to_ast(meta: meta)] }

        [:discriminated_union, [
          @tag_path,
          branches,
          tag_transform_ast,
          meta ? self.meta : EMPTY_HASH
        ]]
      end

      private

      # @api private
      def validate_mapping(mapping)
        unless mapping.is_a?(::Hash)
          raise ::ArgumentError,
                "branch mapping must be a Hash, #{mapping.class} given"
        end

        if mapping.empty?
          raise ::ArgumentError, "a discriminated union needs at least one branch"
        end

        mapping.each do |tag, type|
          unless tag.is_a?(::Symbol) || tag.is_a?(::String)
            raise ::ArgumentError,
                  "tag values must be Symbols or Strings, #{tag.inspect} is a #{tag.class}"
          end

          unless type.is_a?(Type)
            raise ::ArgumentError,
                  "branch for #{tag.inspect} must be a Dry::Types type, #{type.inspect} given"
          end
        end
      end

      # @api private
      def extract_tag(input)
        raw_tag = read_raw_tag(input)
        return raw_tag if raw_tag.is_a?(::Symbol) || raw_tag.is_a?(::String)

        raise InvalidTagError.new(raw_tag, @tag_path)
      end

      # @api private
      def read_raw_tag(input)
        value = input

        @tag_path.each do |segment|
          unless value.is_a?(::Hash)
            raise MissingTagError.new(@tag_path)
          end

          unless value.key?(segment)
            raise MissingTagError.new(@tag_path)
          end

          value = value.fetch(segment)
        end

        if @tag_transform
          @tag_transform.call(value)
        else
          value
        end
      end

      # @api private
      def tag_transform_ast
        return nil unless @tag_transform

        if @tag_transform.is_a?(::Proc)
          [:id, FnContainer.register(@tag_transform)]
        elsif @tag_transform.is_a?(::Method)
          [:method, @tag_transform.receiver, @tag_transform.name]
        else
          [:callable, @tag_transform]
        end
      end
    end
  end
end
