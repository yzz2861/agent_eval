# frozen_string_literal: true

module Dry
  module Types
    # Common API for building type objects in a convenient way
    #
    #
    # @api public
    module BuilderMethods
      # @api private
      def included(base)
        super
        base.extend(BuilderMethods)
      end

      # Build an array type.
      #
      # Shortcut for Array#of.
      #
      # @example
      #   Types::Strings = Types.Array(Types::String)
      #
      # @param [Dry::Types::Type] type
      #
      # @return [Dry::Types::Array]
      def Array(type) = Strict(::Array).of(type)

      # Build a hash schema
      #
      # @param [Hash{Symbol => Dry::Types::Type}] type_map
      #
      # @return [Dry::Types::Array]
      def Hash(type_map) = Strict(::Hash).schema(type_map)

      # Build a type which values are instances of a given class
      # Values are checked using `is_a?` call
      #
      # @example
      #   Types::Error = Types.Instance(StandardError)
      #   Types::Error = Types.Strict(StandardError)
      #   Types.Strict(Integer) == Types::Strict::Int # => true
      #
      # @param [Class,Module] klass Class or module
      #
      # @return [Dry::Types::Type]
      def Instance(klass)
        unless klass.is_a?(::Module)
          raise ::ArgumentError, "Expected a class or module, got #{klass.inspect}"
        end

        Nominal(klass).constrained(type: klass)
      end

      alias_method :Strict, :Instance

      # Build a type with a single value
      # The equality check done with `eql?`
      #
      # @param [Object] value
      #
      # @return [Dry::Types::Type]
      def Value(value) = Nominal(value.class).constrained(eql: value)

      # Build a type with a single value
      # The equality check done with `equal?`
      #
      # @param [Object] object
      #
      # @return [Dry::Types::Type]
      def Constant(object) = Nominal(object.class).constrained(is: object)

      # Build a constructor type
      # If no constructor block given it uses .new method
      #
      # @param [Class] klass
      # @param [#call,nil] cons Value constructor
      # @param [#call,nil] block Value constructor
      #
      # @return [Dry::Types::Type]
      def Constructor(klass, cons = nil, &block) # rubocop:disable Metrics/PerceivedComplexity
        if klass.is_a?(Type)
          if cons || block
            klass.constructor(cons || block)
          else
            klass
          end
        else
          Nominal(klass).constructor(cons || block || klass.method(:new))
        end
      end

      # Build a nominal type
      #
      # @param [Class] klass
      #
      # @return [Dry::Types::Type]
      def Nominal(klass)
        if klass <= ::Array
          Array.new(klass)
        elsif klass <= ::Hash
          Hash.new(klass)
        else
          Nominal.new(klass)
        end
      end

      # Build a map type
      #
      # @example
      #   Types::IntMap = Types.Map(Types::Strict::Integer, 'any')
      #   Types::IntStringMap = Types.Map(Types::Strict::Integer, Types::Strict::String)
      #
      # @param [Type] key_type Key type
      # @param [Type] value_type Value type
      #
      # @return [Dry::Types::Map]
      def Map(key_type, value_type)
        Nominal(::Hash).map(key_type, value_type)
      end

      # Builds a constrained nominal type accepting any value that
      # responds to given methods
      #
      # @example
      #   Types::Callable = Types.Interface(:call)
      #   Types::Contact = Types.Interface(:name, :address)
      #
      # @param methods [Array<String, Symbol>] Method names
      #
      # @return [Dry::Types::Contrained]
      def Interface(*methods)
        methods.reduce(Types["nominal.any"]) do |type, method|
          type.constrained(respond_to: method)
        end
      end

      # Build a discriminated (tagged) union type
      #
      # The branch is chosen from the tag value found in the input; no other
      # branch is tried and no branch default value or constructor is run
      # before the branch is selected.
      #
      # @example tag at the top level
      #   Event = Types.DiscriminatedUnion(
      #     :kind,
      #     "created" => CreatedEvent,
      #     "updated" => UpdatedEvent
      #   )
      #
      # @example tag at a fixed nested path
      #   Event = Types.DiscriminatedUnion(
      #     [:metadata, :type],
      #     created: CreatedEvent
      #   )
      #
      # @example explicit tag conversion (must be provided explicitly)
      #   Event = Types.DiscriminatedUnion(
      #     :kind,
      #     {created: CreatedEvent},
      #     tag_transform: :to_sym.to_proc
      #   )
      #
      # @param [Symbol, String, Array<Symbol, String>] tag key or path to the tag
      # @param [Hash{Symbol, String => Dry::Types::Type}] mapping tag values to branches
      # @param [#call, nil] tag_transform explicit callable applied to the raw
      #   tag value before branch lookup
      #
      # @raise [ArgumentError] when tags are duplicated, not symbols/strings
      #   or branches are not types
      #
      # @return [DiscriminatedUnion]
      #
      # @api public
      def DiscriminatedUnion(tag, mapping, tag_transform: nil)
        path = ::Kernel.Array(tag)

        if path.empty?
          raise ::ArgumentError, "tag path must not be empty"
        end

        unless path.all? { |segment| segment.is_a?(::Symbol) || segment.is_a?(::String) }
          raise ::ArgumentError,
                  "tag path segments must be Symbols or Strings, #{path.inspect} given"
        end

        unless mapping.is_a?(::Hash) && !mapping.empty?
          raise ::ArgumentError,
                "branch mapping must be a non-empty Hash, #{mapping.inspect} given"
        end

        original_tags = mapping.keys

        unless original_tags.all? { |key| key.is_a?(::Symbol) || key.is_a?(::String) }
          bad = original_tags.find { |key| !key.is_a?(::Symbol) && !key.is_a?(::String) }
          raise ::ArgumentError,
                "tag values must be Symbols or Strings, #{bad.inspect} is a #{bad.class}"
        end

        normalized = {}

        mapping.each do |key, branch|
          converted =
            if tag_transform
              converted_tag = tag_transform.call(key)

              unless converted_tag.is_a?(::Symbol) || converted_tag.is_a?(::String)
                raise ::ArgumentError,
                      "tag_transform must return a Symbol or a String, " \
                      "got #{converted_tag.inspect} (#{converted_tag.class}) for #{key.inspect}"
              end

              converted_tag
            else
              key
            end

          if normalized.key?(converted)
            raise ::ArgumentError,
                  "duplicate discriminator tag #{converted.inspect} " \
                  "(also produced from #{key.inspect})"
          end

          normalized[converted] = branch
        end

        DiscriminatedUnion.new(
          normalized,
          tag_path: path,
          tag_transform: tag_transform
        )
      end
    end
  end
end
