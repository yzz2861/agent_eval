# frozen_string_literal: true

module Dry
  module Configurable
    # Builds a deeply frozen, Ractor-shareable snapshot of a config's values.
    #
    # Basic containers (Array, Hash, Set) and scalars (nil, true, false, Integer,
    # Float, Rational, Symbol, String) are converted by default: containers are
    # copied into new frozen containers and strings are frozen, so the original
    # config values are never frozen or otherwise modified. Values of any other
    # type require an explicit converter (keyed by class) supplied by the caller;
    # arbitrary objects are never silently serialized.
    #
    # Repeated references within the value graph are preserved (the same source
    # object maps to the same snapshot object), and cyclic structures are
    # supported. When conversion fails, the raised {SnapshotError} identifies the
    # exact setting path.
    #
    # @api private
    class SharedSnapshot
      # @api private
      def self.call(config, converters: {})
        new(converters: converters).call(config)
      end

      # @api private
      def initialize(converters: {})
        @converters = converters
        @memo = {}.compare_by_identity
        @converting = {}.compare_by_identity
      end

      # @api private
      def call(config)
        Ractor.make_shareable(convert_config(config, EMPTY_ARRAY))
      end

      private

      def convert_config(config, path)
        return @memo[config] if @memo.key?(config)

        snapshot = {}
        @memo[config] = snapshot

        config.values.each do |name, value|
          snapshot[name] =
            if value.is_a?(Config)
              convert_config(value, path + [name])
            else
              convert(value, path + [name])
            end
        end

        snapshot.freeze
      end

      def convert(value, path)
        case value
        when nil, true, false, Integer, Float, Rational, Symbol
          value
        when String
          convert_string(value)
        when Array
          convert_array(value, path)
        when Hash
          convert_hash(value, path)
        when Set
          convert_set(value, path)
        else
          convert_custom(value, path)
        end
      end

      def convert_string(value)
        @memo.fetch(value) {
          @memo[value] = value.frozen? ? value : value.dup.freeze
        }
      end

      def convert_array(value, path)
        return @memo[value] if @memo.key?(value)

        copy = []
        @memo[value] = copy
        value.each_with_index do |element, index|
          copy << convert(element, path + [index])
        end
        copy.freeze
      end

      def convert_hash(value, path)
        return @memo[value] if @memo.key?(value)

        copy = {}
        @memo[value] = copy
        value.each do |key, element|
          copy[convert(key, path)] = convert(element, path + [key])
        end
        copy.freeze
      end

      def convert_set(value, path)
        return @memo[value] if @memo.key?(value)

        copy = Set.new
        @memo[value] = copy
        value.each do |element|
          copy << convert(element, path + [element])
        end
        copy.freeze
      end

      def convert_custom(value, path)
        return @memo[value] if @memo.key?(value)

        _, converter = @converters.find { |type, _| value.is_a?(type) }

        unless converter
          raise SnapshotError,
                "cannot build shared snapshot: no converter registered for " +                "#{value.class} at #{format_path(path)} " +                "(pass one via to_shared_snapshot(converters:))"
        end

        if @converting.key?(value)
          raise SnapshotError,
                "cannot build shared snapshot: converter for #{value.class} at " +                "#{format_path(path)} produces output containing the original object"
        end

        @converting[value] = true
        begin
          converted = converter.call(value)

          if converted.equal?(value)
            raise SnapshotError,
                  "cannot build shared snapshot: converter for #{value.class} at " +                  "#{format_path(path)} returned the object itself"
          end

          @memo[value] = convert(converted, path)
        ensure
          @converting.delete(value)
        end
      end

      def format_path(path)
        return "(root)" if path.empty?

        path.each_with_object(+"") do |segment, str|
          case segment
          when Integer
            str << "[#{segment}]"
          when Symbol
            str << "." unless str.empty?
            str << segment.to_s
          else
            str << "[#{segment.inspect}]"
          end
        end
      end
    end
  end
end
