module Flipper
  # Adding a module include so we have some hooks for stuff down the road
  module Adapter
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      # Public: Default config for a feature's gate values.
      def default_config
        {
          boolean: nil,
          groups: Set.new,
          actors: Set.new,
          expression: nil,
          percentage_of_actors: nil,
          percentage_of_time: nil,
        }
      end

      def from(source)
        return source if source.is_a?(Flipper::Adapter)
        source.adapter
      end
    end

    def read_only?
      false
    end

    # Public: Get all features and gate values in one call. Defaults to one call
    # to features and another to get_multi. Feel free to override per adapter to
    # make this more efficient.
    def get_all(**kwargs)
      instances = features.map { |key| Flipper::Feature.new(key, self) }
      get_multi(instances)
    end

    # Public: Get multiple features in one call. Defaults to one get per
    # feature. Feel free to override per adapter to make this more efficient and
    # reduce network calls.
    def get_multi(features)
      result = {}
      features.each do |feature|
        result[feature.key] = get(feature)
      end
      result
    end

    # Public: Ensure that adapter is in sync with source adapter provided.
    #
    # source - The source dsl, adapter or export to import.
    #
    # Returns true if successful.
    def import(source)
      Adapters::Sync::Synchronizer.new(self, self.class.from(source), raise: true).call
      true
    end

    # Public: Exports the adapter in a given format for a given format version.
    #
    # Returns a Flipper::Export instance.
    def export(format: :json, version: 1)
      Flipper::Exporter.build(format: format, version: version).call(self)
    end

    # Public: Apply a resolved Flipper::PromotionPlan to this adapter.
    #
    # expected_version - the target version captured when the plan was built.
    # operations        - the Array of primitive write operations.
    #
    # This is a best-effort, non-atomic fallback for adapters that do not
    # provide their own implementation. The version is rechecked up front and
    # operations are applied via the public Feature API. Flipper::Adapters::Memory
    # overrides this to apply the whole plan atomically under its lock.
    #
    # Raises Flipper::PromotionPlan::TargetVersionMismatch on stale versions.
    # Returns true when applied.
    def apply_promotion(expected_version, operations)
      actual = Flipper::PromotionPlan::Snapshot.new(get_all)
      if actual.version != expected_version
        raise Flipper::PromotionPlan::TargetVersionMismatch.new(expected_version, actual.version)
      end

      operations.each do |operation|
        feature = Flipper::Feature.new(operation[:feature], self)
        case operation[:op]
        when :remove
          feature.remove
        when :write
          apply_promotion_config(feature, operation[:config])
        end
      end

      true
    end

    # Public: Default config for a feature's gate values.
    def default_config
      self.class.default_config
    end

    # Public: default name of the adapter
    def name
      @name ||= self.class.name.split('::').last.split(/(?=[A-Z])/).join('_').downcase.to_sym
    end

    # Public: Returns a string representation of the adapter stack for debugging.
    # Shows the full chain of wrapped adapters.
    #
    # Examples:
    #   "memoizable -> active_support_cache_store -> active_record"
    #   "memoizable -> failover(primary: redis, secondary: memory)"
    #
    # Returns a String.
    def adapter_stack
      if respond_to?(:adapter) && adapter
        "#{name} -> #{adapter.adapter_stack}"
      else
        name.to_s
      end
    end

    private

    # Internal: Best-effort mirroring of a full gate config via Feature calls.
    def apply_promotion_config(feature, config)
      feature.add

      values = Flipper::GateValues.new(config)

      if values.boolean
        feature.enable
        return
      end

      feature.disable if feature.gate_values.boolean

      current = feature.gate_values

      (values.actors - current.actors).each { |id| feature.enable_actor Flipper::Actor.new(id) }
      (current.actors - values.actors).each { |id| feature.disable_actor Flipper::Actor.new(id) }

      (values.groups - current.groups).each { |name| feature.enable_group name }
      (current.groups - values.groups).each { |name| feature.disable_group name }

      if values.expression.nil?
        feature.disable_expression unless current.expression.nil?
      elsif values.expression != current.expression
        feature.send(:enable_thing, Flipper::Expression.build(values.expression), validate_expression: false)
      end

      if values.percentage_of_actors != current.percentage_of_actors
        feature.enable_percentage_of_actors values.percentage_of_actors
      end

      if values.percentage_of_time != current.percentage_of_time
        feature.enable_percentage_of_time values.percentage_of_time
      end
    end
  end
end

require "set"
require "flipper/exporter"
require "flipper/feature"
require "flipper/adapters/sync/synchronizer"
