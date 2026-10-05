module Flipper
  module Adapters
    class EvaluationSnapshot
      include ::Flipper::Adapter

      def initialize(features)
        @features = deep_freeze(deep_copy(Typecast.features_hash(features)))
        @default_config = deep_freeze(self.class.default_config)
      end

      def features
        @features.keys.to_set
      end

      def add(feature)
        raise EvaluationSnapshotReadOnly
      end

      def remove(feature)
        raise EvaluationSnapshotReadOnly
      end

      def clear(feature)
        raise EvaluationSnapshotReadOnly
      end

      def get(feature)
        @features[feature.key] || @default_config
      end

      def get_multi(features)
        features.each_with_object({}) do |feature, result|
          result[feature.key] = get(feature)
        end
      end

      def get_all(**_kwargs)
        @features
      end

      def enable(feature, gate, thing)
        raise EvaluationSnapshotReadOnly
      end

      def disable(feature, gate, thing)
        raise EvaluationSnapshotReadOnly
      end

      def read_only?
        true
      end

      def supports_evaluation_snapshots?
        false
      end

      def evaluation_snapshot(consistency: :strong)
        raise Flipper::Adapters::EvaluationSnapshotNotSupported.new(self, consistency)
      end

      private

      def deep_copy(value)
        case value
        when Set
          Set.new(value) { |element| deep_copy(element) }
        when Hash
          value.each_with_object({}) do |(key, element), result|
            result[deep_copy(key)] = deep_copy(element)
          end
        when Array
          value.map { |element| deep_copy(element) }
        when String
          value.dup
        else
          value
        end
      end

      def deep_freeze(value)
        case value
        when Set
          value.each { |element| deep_freeze(element) }
        when Hash
          value.each { |key, element| deep_freeze(key); deep_freeze(element) }
        when Array
          value.each { |element| deep_freeze(element) }
        end

        value.freeze
      end
    end
  end
end

require "flipper/typecast"
