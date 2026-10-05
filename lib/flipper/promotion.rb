require "digest"
require "forwardable"
require "set"

require "flipper/errors"
require "flipper/typecast"
require "flipper/gate"
require "flipper/type"
require "flipper/types/boolean"
require "flipper/types/percentage"
require "flipper/types/percentage_of_actors"
require "flipper/types/percentage_of_time"
require "flipper/expression"
require "flipper/gate_values"

module Flipper
  InstrumentationNamespace = :flipper unless const_defined?(:InstrumentationNamespace)
end

require "flipper/feature"
require "flipper/adapter"
require "flipper/adapters/memory"

module Flipper
  class PromotionPlan
    SET_GATES = [:actors, :groups].freeze
    SCALAR_GATES = [:boolean, :expression, :percentage_of_actors, :percentage_of_time].freeze
    GATES = (SET_GATES + SCALAR_GATES).freeze

    SOURCE_RESOLUTIONS = [:source, :use_source].freeze
    TARGET_RESOLUTIONS = [:target, :keep_target].freeze
    CUSTOM_RESOLUTION = :custom

    FeatureChange = Struct.new(:feature, :action, :baseline, :source, :target, :gates, keyword_init: true) do
      def to_h
        {
          feature: feature,
          action: action,
          baseline: baseline,
          source: source,
          target: target,
          gates: gates.transform_values(&:to_h),
        }
      end
    end

    GateChange = Struct.new(:feature, :gate, :baseline, :source, :target, :added, :removed, :target_added, :target_removed, :action, :desired, keyword_init: true) do
      def to_h
        {
          feature: feature,
          gate: gate,
          baseline: viewable_value(gate, baseline),
          source: viewable_value(gate, source),
          target: viewable_value(gate, target),
          added: added.to_a,
          removed: removed.to_a,
          target_added: target_added.to_a,
          target_removed: target_removed.to_a,
          action: action,
          desired: viewable_value(gate, desired),
        }
      end

      private

      def viewable_value(gate, value)
        return value.to_a if value.is_a?(Set)
        return Typecast.to_number(value) if percentage_gate?(gate) && !value.nil?
        value
      end

      def percentage_gate?(gate)
        gate == :percentage_of_actors || gate == :percentage_of_time
      end
    end

    Conflict = Struct.new(:feature, :gate, :kind, :baseline, :source, :target, :resolution, :desired, keyword_init: true) do
      def path
        if gate && [:added, :removed].include?(kind)
          [feature, gate, kind, source || target]
        elsif gate
          [feature, gate]
        else
          [feature]
        end
      end

      def resolved?
        !resolution.nil?
      end

      def to_h
        {
          feature: feature,
          gate: gate,
          kind: kind,
          baseline: baseline,
          source: source,
          target: target,
          resolution: resolution,
          desired: desired,
        }
      end
    end

    class UnresolvedConflictError < Error; end
    UnresolvedConflict = UnresolvedConflictError
    ConflictError = UnresolvedConflictError
    class StaleTarget < Error
      def initialize(expected_version, actual_version)
        super "Target has changed since promotion plan was generated (expected #{expected_version.inspect}, got #{actual_version.inspect}). Recalculate the plan."
      end
    end
    StaleTargetError = StaleTarget
    VersionMismatch = StaleTarget
    class UnsupportedTarget < Error
      def initialize(target)
        super "#{target.inspect} cannot atomically apply a promotion plan. Use a memory adapter or implement apply_promotion_plan."
      end
    end
    UnsupportedTargetError = UnsupportedTarget

    def self.version_for(features)
      Flipper::PromotionPlan.new({}, {}, features).target_version
    end

    def initialize(baseline, source, target)
      @baseline = normalize_features(baseline)
      @source = normalize_features(source)
      @target_snapshot = normalize_features(target)
      @target_adapter = source_for(target) if target.respond_to?(:get_all) || target.respond_to?(:adapter)
      @target_version = version_for_features(@target_snapshot)
      @resolutions = {}
      build
    end

    attr_reader :target_version
    alias_method :version, :target_version

    def changes
      @changes
    end

    def to_h
      {
        target_version: target_version,
        resolved: resolved?,
        changes: changes.transform_values(&:to_h),
        conflicts: conflicts.map(&:to_h),
      }
    end

    def conflicts
      @conflicts
    end

    def resolved?
      conflicts.all?(&:resolved?)
    end

    def resolve!(*args, **options)
      @resolutions = @resolutions.dup
      feature = args[0] || options[:feature]
      gate = args[1] || options[:gate]
      third_argument = args[2]
      value = third_argument
      value = options[:value] if options.key?(:value)
      value = options[:desired] if options.key?(:desired)

      if options.key?(:resolution)
        resolution = options[:resolution]
      elsif SOURCE_RESOLUTIONS.include?(third_argument) || TARGET_RESOLUTIONS.include?(third_argument)
        resolution = third_argument
        value = nil
      elsif value.nil? && !options.key?(:value) && !options.key?(:desired)
        resolution = options.fetch(:side, :target)
      else
        resolution = CUSTOM_RESOLUTION
      end

      raise ArgumentError, "feature is required" if feature.nil?
      feature = feature.to_s
      gate = gate.to_sym if gate
      conflict = find_conflict(feature, gate)
      raise ArgumentError, "no conflict for #{gate ? [feature, gate] : [feature].inspect}" unless conflict

      normalized = normalize_resolution(conflict, resolution, value)
      matching_conflicts(feature, gate).each do |matching_conflict|
        @resolutions[matching_conflict.path] = normalized
      end
      @resolutions[[feature]] = normalized if gate.nil?
      build
      self
    end

    def resolve(*args, **options)
      dup.tap { |plan| plan.resolve!(*args, **options) }
    end

    def result
      ensure_resolved!
      @result
    end

    def apply(target = nil)
      ensure_resolved!

      target_adapter = target ? source_for(target) : @target_adapter
      unless target_adapter.respond_to?(:apply_promotion_plan)
        raise UnsupportedTarget, target_adapter
      end

      target_adapter.apply_promotion_plan(self)
    end
    alias_method :apply!, :apply
    alias_method :apply_to, :apply
    alias_method :resolve_conflict!, :resolve!

    private

    def build
      @changes = {}
      @conflicts = []
      @result = {}

      feature_keys.each do |feature|
        baseline_feature = @baseline[feature]
        source_feature = @source[feature]
        target_feature = @target_snapshot[feature]
        feature_conflict = build_feature_change(feature, baseline_feature, source_feature, target_feature)
        desired_feature = resolve_feature_conflict(feature, feature_conflict, baseline_feature, source_feature, target_feature)

        gate_changes = if desired_feature
          merge_gates(feature, baseline_feature, source_feature, target_feature, desired_feature, feature_conflict)
        else
          {}
        end
        add_feature_change(feature, baseline_feature, source_feature, target_feature, desired_feature, feature_conflict, gate_changes)
      end
    end

    def feature_keys
      (@baseline.keys | @source.keys | @target_snapshot.keys).sort
    end

    def build_feature_change(feature, baseline, source, target)
      source_present = !source.nil?
      target_present = !target.nil?
      baseline_present = !baseline.nil?
      return :remove if !source_present && !target_present && baseline_present
      return nil unless source_present || target_present

      if source_present && target_present
        return nil if baseline_present || source == target
        add_conflict(feature, nil, :added, baseline, source, target)
      elsif source_present
        if !baseline_present || source == baseline
          nil
        else
          add_conflict(feature, nil, :removed, baseline, source, target)
        end
      elsif target_present && baseline_present
        if target == baseline
          :remove
        else
          add_conflict(feature, nil, :removed, baseline, source, target)
        end
      end
    end

    def resolve_feature_conflict(feature, conflict, baseline, source, target)
      return nil if conflict == :remove

      unless conflict.nil?
        resolution = @resolutions[[feature]]
        return nil unless resolution
        return apply_resolution(conflict, resolution)
      end

      return nil if source && target.nil? && baseline && source == baseline
      source || target
    end

    def merge_gates(feature, baseline, source, target, desired, feature_conflict = nil)
      gate_changes = {}
      @result[feature] = normalize_gate_values(desired)
      source_gates = source || default_gate_values
      target_gates = target || default_gate_values
      baseline_gates = baseline || default_gate_values

      GATES.each do |gate|
        gate_change = merge_gate(feature, gate, baseline_gates, source_gates, target_gates, feature_conflict)
        gate_changes[gate] = gate_change if gate_change
      end

      gate_changes
    end

    def add_feature_change(feature, baseline, source, target, desired, conflict, gate_changes)
      action = feature_action(baseline, source, target, desired, conflict)
      return if action.nil? && conflict.nil? && gate_changes.empty?

      @changes[feature] = FeatureChange.new(
        feature: feature,
        action: action,
        baseline: !baseline.nil?,
        source: !source.nil?,
        target: !target.nil?,
        gates: gate_changes
      )
    end

    def feature_action(baseline, source, target, desired, conflict)
      baseline_present = !baseline.nil?
      source_present = !source.nil?
      target_present = !target.nil?

      if desired.nil?
        return :remove if source.nil? && baseline_present
        return nil
      end

      if baseline_present
        target == desired ? nil : :update
      elsif source_present && !target_present
        :add
      elsif source_present && target_present
        target == desired ? nil : :update
      else
        nil
      end
    end

    def merge_gate(feature, gate, baseline, source, target, feature_conflict = nil)
      if SET_GATES.include?(gate)
        merge_set_gate(feature, gate, baseline, source, target)
      else
        merge_scalar_gate(feature, gate, baseline, source, target, feature_conflict)
      end
    end

    def merge_set_gate(feature, gate, baseline, source, target)
      baseline_values = baseline.fetch(gate, Set.new)
      source_values = source.fetch(gate, Set.new)
      target_values = target.fetch(gate, Set.new)

      added = source_values - baseline_values
      removed = baseline_values - source_values
      target_added = target_values - baseline_values
      target_removed = baseline_values - target_values

      return if added.empty? && removed.empty? && target_added.empty? && target_removed.empty?

      desired_values = (target_values | added) - removed
      @result[feature][gate] = desired_values

      GateChange.new(
        feature: feature,
        gate: gate,
        baseline: baseline_values,
        source: source_values,
        target: target_values,
        added: added,
        removed: removed,
        target_added: target_added,
        target_removed: target_removed,
        action: (added.any? || removed.any?) ? :update : nil,
        desired: desired_values
      )
    end

    def merge_scalar_gate(feature, gate, baseline, source, target, feature_conflict = nil)
      baseline_value = scalar_value(gate, baseline[gate])
      source_value = scalar_value(gate, source[gate])
      target_value = scalar_value(gate, target[gate])

      source_changed = baseline_value != source_value
      target_changed = baseline_value != target_value
      return unless source_changed || target_changed

      desired_value = if source_changed && target_changed && source_value != target_value && feature_conflict
        source_value
      elsif source_changed
        source_value
      else
        target_value
      end

      if source_changed && target_changed && source_value != target_value && feature_conflict.nil?
        conflict = add_conflict(feature, gate, :updated, baseline_value, source_value, target_value)
        desired_value = resolve_gate(conflict)
      end

      @result[feature][gate] = normalize_gate_value(gate, desired_value)

      GateChange.new(
        feature: feature,
        gate: gate,
        baseline: baseline_value,
        source: source_value,
        target: target_value,
        added: Set.new,
        removed: Set.new,
        target_added: Set.new,
        target_removed: Set.new,
        action: source_changed ? :update : nil,
        desired: desired_value
      )
    end

    def resolve_gate(conflict)
      resolution = gate_resolution(conflict)
      return unless resolution
      apply_resolution(conflict, resolution)
    end

    def gate_resolution(conflict)
      @resolutions[conflict.path]
    end

    def apply_resolution(conflict, resolution)
      kind, value = resolution
      conflict.resolution = kind
      conflict.desired = value

      case kind
      when :source
        conflict.gate ? conflict.source : @source[conflict.feature]
      when :target
        conflict.gate ? conflict.target : @target_snapshot[conflict.feature]
      else
        value
      end
    end

    def find_conflict(feature, gate)
      @conflicts.detect { |conflict| conflict.feature == feature && conflict.gate == gate }
    end

    def matching_conflicts(feature, gate)
      @conflicts.select do |conflict|
        conflict.feature == feature && (!gate || conflict.gate == gate)
      end
    end

    def add_conflict(feature, gate, kind, baseline, source, target)
      Conflict.new(
        feature: feature,
        gate: gate,
        kind: kind,
        baseline: baseline,
        source: source,
        target: target
      ).tap { |conflict| @conflicts << conflict }
    end

    def normalize_resolution(conflict, resolution, value)
      resolution = resolution.to_sym if resolution.respond_to?(:to_sym)

      if SOURCE_RESOLUTIONS.include?(resolution)
        [:source, nil]
      elsif TARGET_RESOLUTIONS.include?(resolution)
        [:target, nil]
      elsif resolution == CUSTOM_RESOLUTION || (!value.nil? && resolution.nil?)
        desired = value || resolution
        desired = if conflict.gate
          normalize_gate_value(conflict.gate, desired)
        else
          normalize_gate_values(desired)
        end
        [:custom, desired]
      else
        raise ArgumentError, "invalid resolution #{resolution.inspect}"
      end
    end

    def ensure_resolved!
      build
      conflict = conflicts.detect { |item| !item.resolved? }
      raise UnresolvedConflict, "unresolved conflict #{conflict.path.inspect}" if conflict
      true
    end

    def normalize_features(source)
      source = source_for(source)
      adapter_source = source.respond_to?(:get_all) ? source.get_all : source
      Typecast.features_hash(adapter_source).each_with_object({}) do |(feature, gates), result|
        result[feature.to_s] = normalize_gate_values(gates)
      end
    end

    def source_for(source)
      if source.is_a?(Export)
        source.adapter
      elsif source.respond_to?(:get_all)
        source
      elsif source.respond_to?(:adapter)
        source.adapter
      else
        source
      end
    end

    def normalize_gate_values(gates)
      normalized = default_gate_values
      (gates || {}).each do |gate, value|
        gate = gate.to_sym
        normalized[gate] = normalize_gate_value(gate, value)
      end
      normalized
    end

    def normalize_gate_value(gate, value)
      if SET_GATES.include?(gate)
        Typecast.to_set(value).dup
      elsif gate == :boolean
        value.nil? ? nil : Typecast.to_boolean(value).to_s
      elsif gate == :expression
        normalize_expression(value)
      elsif SCALAR_GATES.include?(gate)
        number = Typecast.to_number(value)
        number.zero? ? nil : number.to_s
      else
        value
      end
    end

    def normalize_expression(value)
      return if value.nil?
      Expression.build(value).value
    rescue ArgumentError
      value
    end

    def scalar_value(gate, value)
      if percentage_gate?(gate)
        value.nil? ? 0 : Typecast.to_number(value)
      else
        value
      end
    end

    def percentage_gate?(gate)
      gate == :percentage_of_actors || gate == :percentage_of_time
    end

    def default_gate_values
      Adapters::Memory.default_config.transform_values(&:dup)
    end

    def version_for_features(features)
      Digest::SHA256.hexdigest(Typecast.to_json(canonical(features)))
    end

    def canonical(value)
      case value
      when Hash
        value.keys.sort.each_with_object({}) do |key, result|
          result[key.to_s] = canonical(value[key])
        end
      when Set
        value.map { |item| canonical(item) }.sort
      when Array
        value.map { |item| canonical(item) }
      else
        value
      end
    end
  end

  module Promotion
    Plan = PromotionPlan

    def self.plan(baseline, source, target)
      PromotionPlan.new(baseline, source, target)
    end
  end

  def self.promotion_plan(baseline, source, target)
    PromotionPlan.new(baseline, source, target)
  end
end
