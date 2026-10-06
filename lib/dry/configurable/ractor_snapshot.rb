# frozen_string_literal: true

module Dry
  module Configurable
    # Builds an immutable value graph that can be shared across Ractors
    #
    # @api private
    class RactorSnapshot
      BASIC_SCALAR_TYPES = [NilClass, Symbol, Integer, Float, Rational, Complex].freeze

      def self.call(config, converters = {})
        new(converters).build(config)
      end

      def initialize(converters)
        @converters = converters
        @memo = {}
        @in_progress = {}
      end

      def build(config)
        snapshot = build_data(config, [])
        ensure_shareable!(snapshot, [])
        snapshot
      end

      def build_data(config, path)
        if (memoized = @memo[config.object_id])
          return memoized
        end

        if @in_progress.key?(config.object_id)
          raise RactorSnapshotError,
            "Cyclic reference at #{format_path(path)} (#{config.class})"
        end

        @in_progress[config.object_id] = config
        attrs = config.values.each_with_object({}) do |(name, value), hsh|
          hsh[name] = convert_graph(value, path + [name])
        end
        @in_progress.delete(config.object_id)

        @memo[config.object_id] = config._settings.data_class.new(**attrs).freeze
      end

      def build_value(value, path)
        return @in_progress[value.object_id] if @in_progress.key?(value.object_id)
        return memoized_value(value) if @memo.key?(value.object_id)

        converted = convert(value, path)
        ensure_shareable!(converted, path)
        @memo[value.object_id] = converted
      end

      def convert(value, path)
        return value if value.equal?(Undefined)
        return value if basic_scalar?(value)
        return value.dup.freeze if value.is_a?(String)

        if (converter = converter_for(value))
          return call_converter(converter, value, path)
        end

        return build_hash(value, path) if value.instance_of?(Hash)
        return build_array(value, path) if value.instance_of?(Array)
        return build_set(value, path) if defined?(::Set) && value.instance_of?(::Set)

        raise RactorSnapshotError,
          "Cannot convert #{value.class} at #{format_path(path)}: provide an explicit converter"
      end

      def basic_scalar?(value)
        BASIC_SCALAR_TYPES.any? { |type| value.is_a?(type) } ||
          value.equal?(true) ||
          value.equal?(false)
      end

      def converter_for(value)
        converter_class = @converters.keys.find { |klass| value.is_a?(klass) }
        @converters[converter_class] if converter_class
      end

      def call_converter(converter, value, path)
        converter.arity == 1 ? converter.call(value) : converter.call(value, path)
      rescue StandardError => error
        raise RactorSnapshotError,
          "Converter failed at #{format_path(path)}: #{error.class}: #{error.message}"
      end

      def build_hash(value, path)
        build_container(value, path) do |object|
          value.each_pair do |key, item|
            object[convert_key(key, path)] = convert_graph(item, path + [key])
          end
        end
      end

      def build_array(value, path)
        build_container(value, path) do |object|
          value.each_with_index do |item, index|
            object[index] = convert_graph(item, path + [index])
          end
        end
      end

      def build_set(value, path)
        build_container(value, path) do |object|
          value.each_with_index do |item, index|
            object.add(convert_graph(item, path + [index]))
          end
        end
      end

      def build_container(value, path)
        if (memoized = @memo[value.object_id])
          return memoized
        end

        return @in_progress[value.object_id] if @in_progress.key?(value.object_id)

        object = allocate_container(value)
        @in_progress[value.object_id] = object
        yield(object)
        @in_progress.delete(value.object_id)
        object.freeze
        ensure_shareable!(object, path)
        @memo[value.object_id] = object
      end

      def convert_graph(value, path)
        if value.is_a?(Config)
          build_data(value, path)
        else
          build_value(value, path)
        end
      end

      def convert_key(key, path)
        convert(key, path + [key])
      rescue RactorSnapshotError
        raise RactorSnapshotError,
          "Cannot convert hash key at #{format_path(path + [key])}: #{key.class}; provide an explicit converter"
      end

      def ensure_shareable!(value, path)
        return if value.frozen? && Ractor.shareable?(value)

        raise RactorSnapshotError,
          "Converter for #{format_path(path)} returned a non-shareable value: #{value.class}"
      end

      def allocate_container(value)
        case value
        when Hash then {}
        when Array then []
        when ::Set then ::Set.new
        end
      end

      def format_path(path)
        "settings." + path.map {
          _1.is_a?(Integer) ? "[#{_1}]" : _1.to_s
        }.join(".").gsub(".[", "[")
      end

      def memoized_value(value)
        @memo[value.object_id]
      end
    end
  end
end
