require "flipper/adapter"
require "flipper/adapters/read_only"
require "flipper/typecast"

module Flipper
  module Adapters
    # Public: Adapter for storing everything in memory.
    # Useful for tests/specs.
    class Memory
      include ::Flipper::Adapter

      # Private: Shared frozen config for unknown features. Gate values
      # returned by get are treated as read-only.
      DEFAULT_CONFIG = default_config.each_value(&:freeze).freeze

      # Public
      def initialize(source = nil, threadsafe: true, frozen: false)
        @source = Typecast.features_hash(source)
        @lock = Mutex.new if threadsafe
        freeze_snapshot if frozen
      end

      # Public: The set of known features.
      def features
        synchronize { @source.keys }.to_set
      end

      # Public: Adds a feature to the set of known features.
      def add(feature)
        synchronize { @source[feature.key] ||= default_config }
        true
      end

      # Public: Removes a feature from the set of known features and clears
      # all the values for the feature.
      def remove(feature)
        synchronize { @source.delete(feature.key) }
        true
      end

      # Public: Clears all the gate values for a feature.
      def clear(feature)
        synchronize { @source[feature.key] = default_config }
        true
      end

      # Public
      def get(feature)
        synchronize { @source[feature.key] } || DEFAULT_CONFIG
      end

      def get_multi(features)
        synchronize do
          result = {}
          features.each do |feature|
            result[feature.key] = @source[feature.key] || DEFAULT_CONFIG
          end
          result
        end
      end

      def get_all(**kwargs)
        synchronize { Typecast.features_hash(@source) }
      end

      # Public: Returns a read-only, immutable snapshot of all feature
      # configuration. The source hash and gate values are copied while the
      # adapter lock is held, so a concurrent publication cannot leave the
      # snapshot half old and half new.
      def snapshot
        source = synchronize { copy_snapshot_source(@source) }
        Adapters::ReadOnly.new(self.class.new(source, threadsafe: false, frozen: true))
      end

      def supports_snapshot?
        true
      end

      # Public
      def enable(feature, gate, thing)
        synchronize do
          @source[feature.key] ||= default_config

          case gate.data_type
          when :boolean
            @source[feature.key] = default_config
            @source[feature.key][gate.key] = thing.value.to_s
          when :integer
            @source[feature.key][gate.key] = thing.value.to_s
          when :set
            @source[feature.key][gate.key] << thing.value.to_s
          when :json
            @source[feature.key][gate.key] = thing.value
          else
            raise "#{gate} is not supported by this adapter yet"
          end

          true
        end
      end

      # Public
      def disable(feature, gate, thing)
        synchronize do
          @source[feature.key] ||= default_config

          case gate.data_type
          when :boolean
            @source[feature.key] = default_config
          when :integer
            @source[feature.key][gate.key] = thing.value.to_s
          when :set
            @source[feature.key][gate.key].delete thing.value.to_s
          when :json
            @source[feature.key].delete(gate.key)
          else
            raise "#{gate} is not supported by this adapter yet"
          end

          true
        end
      end

      # Public
      def inspect
        attributes = [
          'name=:memory',
          "source=#{@source.inspect}",
        ]
        "#<#{self.class.name}:#{object_id} #{attributes.join(', ')}>"
      end

      # Public: a more efficient implementation of import for this adapter
      def import(source)
        adapter = self.class.from(source)
        get_all = Typecast.features_hash(adapter.get_all)
        synchronize { @source.replace(get_all) }
        true
      end

      private

      def freeze_snapshot
        @source.each do |feature_key, gates|
          gates.each do |gate_key, value|
            gates[gate_key] = freeze_snapshot_value(value)
          end
          gates.freeze
        end
        @source.freeze
      end

      def copy_snapshot_source(source)
        source.each_with_object({}) do |(feature_key, gates), result|
          copied_gates = gates.each_with_object({}) do |(gate_key, value), gate_result|
            gate_result[gate_key] = copy_snapshot_value(value)
          end
          result[feature_key.is_a?(String) ? feature_key.dup : feature_key] = copied_gates
        end
      end

      def copy_snapshot_value(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested_value), result|
            result[key.is_a?(String) ? key.dup : key] = copy_snapshot_value(nested_value)
          end
        when Array
          value.map { |element| copy_snapshot_value(element) }
        when Set
          value.each_with_object(Set.new) do |element, result|
            result << copy_snapshot_value(element)
          end
        when String
          value.dup
        else
          value
        end
      end

      def freeze_snapshot_value(value)
        case value
        when Hash
          value.each { |key, nested_value| value[key] = freeze_snapshot_value(nested_value) }.freeze
        when Array
          value.each_with_index { |element, index| value[index] = freeze_snapshot_value(element) }.freeze
        when Set
          value.each { |element| freeze_snapshot_value(element) }
          value.freeze
        when String
          value.freeze
        else
          value.freeze
        end
      end

      def synchronize(&block)
        if @lock
          @lock.synchronize(&block)
        else
          block.call
        end
      end
    end
  end
end
