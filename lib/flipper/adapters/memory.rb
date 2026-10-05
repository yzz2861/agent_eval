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
        @evaluation_snapshot_key = "flipper_evaluation_snapshot_#{object_id}".freeze
      end

      # Public: The set of known features.
      def features
        return current_evaluation_snapshot.features if current_evaluation_snapshot

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
        return current_evaluation_snapshot.get(feature) if current_evaluation_snapshot

        synchronize { @source[feature.key] } || DEFAULT_CONFIG
      end

      def get_multi(features)
        return current_evaluation_snapshot.get_multi(features) if current_evaluation_snapshot

        synchronize do
          result = {}
          features.each do |feature|
            result[feature.key] = @source[feature.key] || DEFAULT_CONFIG
          end
          result
        end
      end

      def get_all(**kwargs)
        return current_evaluation_snapshot.get_all(**kwargs) if current_evaluation_snapshot

        synchronize { Typecast.features_hash(@source) }
      end

      def supports_evaluation_snapshots?
        true
      end

      if RUBY_VERSION >= '3.0'
        def evaluation_snapshot(consistency: :strong)
          raise ArgumentError, "unsupported consistency: #{consistency.inspect}" unless consistency == :strong

          EvaluationSnapshot.new(synchronize { Typecast.features_hash(@source) })
        end
      else
        def evaluation_snapshot(consistency = :strong)
          raise ArgumentError, "unsupported consistency: #{consistency.inspect}" unless consistency == :strong

          EvaluationSnapshot.new(synchronize { Typecast.features_hash(@source) })
        end
      end

      if RUBY_VERSION >= '3.0'
        def with_evaluation_snapshot(consistency: :strong)
          raise ArgumentError, "a block is required" unless block_given?
          return yield(current_evaluation_snapshot) if current_evaluation_snapshot

          snapshot = evaluation_snapshot(consistency: consistency)
          previous_snapshot = Thread.current[@evaluation_snapshot_key]
          Thread.current[@evaluation_snapshot_key] = snapshot
          yield snapshot
        ensure
          Thread.current[@evaluation_snapshot_key] = previous_snapshot
        end
      else
        def with_evaluation_snapshot(consistency = :strong)
          raise ArgumentError, "a block is required" unless block_given?
          return yield(current_evaluation_snapshot) if current_evaluation_snapshot

          snapshot = evaluation_snapshot(consistency)
          previous_snapshot = Thread.current[@evaluation_snapshot_key]
          Thread.current[@evaluation_snapshot_key] = snapshot
          yield snapshot
        ensure
          Thread.current[@evaluation_snapshot_key] = previous_snapshot
        end
      end

      def current_evaluation_snapshot
        Thread.current[@evaluation_snapshot_key]
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
