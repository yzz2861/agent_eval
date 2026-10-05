require "digest"
require "json"
require "set"
require "flipper/typecast"

module Flipper
  class PromotionPlan
    # Internal: Immutable, normalized view of an adapter's feature/gate data.
    #
    # Accepts an adapter (via #get_all), a Flipper::Export, a DSL instance or a
    # raw Hash of feature_key => gates hash. Normalized values use:
    #
    #   boolean                 => String ("true") or nil
    #   actors/groups           => Set of Strings
    #   percentage_of_*         => String or nil
    #   expression              => Array/Hash/Scalar or nil
    class Snapshot
      GATE_KEYS = %i[boolean groups actors expression percentage_of_actors percentage_of_time].freeze
      SET_GATES = %i[actors groups].freeze
      SCALAR_GATES = (%i[boolean expression percentage_of_actors percentage_of_time]).freeze

      DEFAULT_CONFIG = {
        boolean: nil,
        groups: Set.new,
        actors: Set.new,
        expression: nil,
        percentage_of_actors: nil,
        percentage_of_time: nil,
      }.each_value(&:freeze).freeze

      attr_reader :features

      def initialize(source)
        if source.respond_to?(:get_all)
          source = source.get_all
        elsif source.respond_to?(:adapter)
          # Flipper DSL instance.
          source = source.adapter.get_all
        end
        @features = normalize(Typecast.features_hash(source))
        @features.freeze
      end

      # Public: The gate hash for a feature, or the default config.
      def [](feature_key)
        @features[feature_key.to_s] || default_config.dup
      end

      def feature?(feature_key)
        @features.key?(feature_key.to_s)
      end

      # Public: Stable fingerprint of the snapshot, used as the target
      # optimistic-concurrency version.
      def version
        @version ||= Digest::SHA256.hexdigest(canonical_json(@features))
      end

      def default_config
        DEFAULT_CONFIG
      end

      # Internal: Deterministic JSON for a normalized snapshot. Feature and
      # gate keys are sorted and actor/group sets are sorted arrays so that
      # equal configurations always produce the same digest.
      def canonical_json(features = @features)
        JSON.generate(canonical_value(features))
      end

      private

      def normalize(source)
        normalized = {}
        source.each do |feature_key, gates|
          config = {}
          gates.each do |gate_key, value|
            gate_key = gate_key.to_sym
            next unless GATE_KEYS.include?(gate_key)
            config[gate_key] = normalize_gate(gate_key, value)
          end
          GATE_KEYS.each do |gate_key|
            config[gate_key] = normalize_gate(gate_key, config[gate_key]) unless config.key?(gate_key)
          end
          normalized[feature_key.to_s] = config
        end
        normalized
      end

      def normalize_gate(gate_key, value)
        if SET_GATES.include?(gate_key)
          Typecast.to_set(value).map { |item| item.to_s }.to_set
        elsif gate_key == :expression
          value
        elsif gate_key == :percentage_of_actors || gate_key == :percentage_of_time
          # A never-enabled percentage is nil while a disabled one is "0";
          # GateValues treats both as 0 so canonicalize them for diffing.
          value.nil? || value.to_i.zero? ? "0" : value.to_s
        elsif value.nil?
          nil
        else
          value.to_s
        end
      end

      def canonical_value(value)
        case value
        when Hash
          value.keys.sort.each_with_object({}) do |key, memo|
            memo[key.to_s] = canonical_value(value[key])
          end
        when Set
          value.map { |item| canonical_value(item) }.sort
        else
          value
        end
      end
    end
  end
end
