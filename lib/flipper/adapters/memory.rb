require "flipper/adapter"
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
      def initialize(source = nil, threadsafe: true)
        @source = Typecast.features_hash(source)
        @lock = Mutex.new if threadsafe
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

      # Public: Atomically apply a resolved Flipper::PromotionPlan. The target
      # version is rechecked and every write is performed under the same lock,
      # so concurrent readers and writers can never observe a partially applied
      # plan or a plan applied against a stale configuration.
      #
      # expected_version - target version captured when the plan was built.
      # operations        - Array of :write/:remove primitive operations.
      #
      # Raises Flipper::PromotionPlan::TargetVersionMismatch when the target
      # changed since the plan was built.
      # Returns true when applied.
      def apply_promotion(expected_version, operations)
        synchronize do
          current = Typecast.features_hash(@source)
          actual_version = Flipper::PromotionPlan::Snapshot.new(current).version
          if actual_version != expected_version
            raise Flipper::PromotionPlan::TargetVersionMismatch.new(expected_version, actual_version)
          end

          operations.each do |operation|
            case operation[:op]
            when :remove
              @source.delete(operation[:feature])
            when :write
              @source[operation[:feature]] = promotion_config(operation[:config])
            else
              raise ArgumentError, "Unknown promotion operation: #{operation[:op].inspect}"
            end
          end
        end

        true
      end

      private

      def synchronize(&block)
        if @lock
          @lock.synchronize(&block)
        else
          block.call
        end
      end

      # Internal: Deep-copy a plan config so the stored state never shares
      # mutable Sets with the plan or snapshots.
      def promotion_config(config)
        copied = default_config.dup
        config.each do |gate_key, value|
          copied[gate_key] = value.is_a?(::Set) ? value.dup : value
        end
        copied
      end
    end
  end
end
