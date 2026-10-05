require "flipper/adapter"
require "flipper/promotion/errors"
require "flipper/promotion/snapshot"
require "flipper/promotion/conflict"
require "flipper/promotion/gate_change"
require "flipper/promotion/feature_plan"

module Flipper
  # Public: A three-way promotion plan for moving feature flag configuration
  # from one environment (e.g. test/staging) to another (e.g. production).
  #
  # Instead of overwriting the target with the source, the plan performs a
  # three-way merge against a common baseline:
  #
  #   base   - configuration shared by both environments before they diverged
  #   source - the environment being promoted from
  #   target - the environment being promoted to (may have temp adjustments)
  #
  # Actor/group set gates merge additions and deletions independently, while
  # scalar gates (boolean, expression, percentages) that changed on both sides
  # are reported as conflicts. Conflicts must be resolved explicitly before
  # applying, and application is conditional on the target version captured
  # when the plan was built: if production changed in the meantime, application
  # raises TargetVersionMismatch and the plan must be rebuilt.
  class PromotionPlan
    # Public: Build a reviewable promotion plan.
    #
    # base   - adapter, DSL, Export or features Hash used as common baseline.
    # source - adapter, DSL, Export or features Hash being promoted from.
    # target - adapter, DSL or Export being promoted to.
    #
    # Returns a Flipper::PromotionPlan.
    def self.build(base, source, target)
      new(base: base, source: source, target: target)
    end

    def initialize(base:, source:, target:)
      @target_adapter = adapter_from(target)
      @base_snapshot = Snapshot.new(base)
      @source_snapshot = Snapshot.new(source)
      @target_snapshot = Snapshot.new(@target_adapter.get_all)
      @target_version = @target_snapshot.version
      @applied = false

      build_feature_plans
    end

    # Public: All per-feature plans, sorted by feature name.
    attr_reader :feature_plans

    # Public: Only per-feature plans that change the target.
    def changes
      @feature_plans.select(&:changed?)
    end

    # Public: Optimistic version of the target captured when the plan was built.
    attr_reader :target_version

    # Public: All conflicts (presence and scalar gate), resolved or not.
    def conflicts
      @feature_plans.flat_map(&:conflicts)
    end

    # Public: Conflicts that still need an explicit decision.
    def unresolved_conflicts
      conflicts.select(&:unresolved?)
    end

    def resolved?
      unresolved_conflicts.empty?
    end

    # Public: Resolve a conflict for a feature.
    #
    # feature - the String/Symbol feature name.
    # choice  - :source (adopt source side) or :target (keep target side).
    # gate    - optional gate key for a scalar gate conflict.
    #
    # Returns self so calls can be chained.
    def resolve!(feature, choice, gate: nil)
      feature_plan = plan_for(feature)
      if gate
        feature_plan.resolve_gate!(gate, choice)
      else
        feature_plan.resolve_presence!(choice)
      end
      self
    end

    # Public: Hash representation suitable for rendering/review.
    def to_h
      {
        target_version: target_version,
        changes: changes.map(&:to_h),
        conflicts: conflicts.map(&:to_h),
      }
    end

    # Public: Apply the resolved plan to the target adapter.
    #
    # Raises UnresolvedConflicts if any conflict is still unresolved.
    # Raises TargetVersionMismatch if the target changed since plan build.
    # Returns true when the plan was applied.
    def apply(target = nil)
      raise UnresolvedConflicts.new(unresolved_conflicts) unless resolved?
      raise Error, "Promotion plan can only be applied once." if @applied

      adapter = target ? adapter_from(target) : @target_adapter
      adapter.apply_promotion(target_version, operations)
      @applied = true
      true
    end

    def inspect
      "#<#{self.class.name} changes=#{changes.size} " \
        "conflicts=#{conflicts.size} unresolved=#{unresolved_conflicts.size} " \
        "target_version=#{target_version[0, 12]}>"
    end

    private

    def build_feature_plans
      feature_keys = [
        @base_snapshot.features.keys,
        @source_snapshot.features.keys,
        @target_snapshot.features.keys,
      ].flatten.uniq.sort

      @feature_plans = feature_keys.map do |feature|
        FeaturePlan.new(
          feature: feature,
          base: @base_snapshot,
          source: @source_snapshot,
          target: @target_snapshot,
        )
      end
    end

    def plan_for(feature)
      @feature_plans.find { |plan| plan.feature == feature.to_s } ||
        raise(ConflictNotFound.new(feature))
    end

    # Internal: The primitive write operations produced by the resolved plan.
    def operations
      changes.map do |feature_plan|
        case feature_plan.action
        when :add, :modify
          {
            op: :write,
            feature: feature_plan.feature,
            config: feature_plan.merged_config,
          }
        when :remove
          { op: :remove, feature: feature_plan.feature }
        end
      end
    end

    def adapter_from(source)
      if source.respond_to?(:apply_promotion) || source.respond_to?(:get_all)
        source
      elsif source.respond_to?(:adapter)
        source.adapter
      else
        raise ArgumentError, "Expected an adapter, Flipper DSL or Export, got #{source.inspect}"
      end
    end
  end
end
