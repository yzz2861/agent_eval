require "set"

module Flipper
  class PromotionPlan
    # Internal: Reviewable three-way merge result for a single feature.
    class FeaturePlan
      ACTIONS = %i[add modify remove keep].freeze
      GATE_KEYS = Snapshot::GATE_KEYS

      attr_reader :feature
      attr_reader :action
      attr_reader :gate_changes
      attr_reader :conflict

      def initialize(feature:, base:, source:, target:)
        @feature = feature
        @in_base = base.feature?(feature)
        @in_source = source.feature?(feature)
        @in_target = target.feature?(feature)
        @presence_choice = nil
        @base = base[feature]
        @source = source[feature]
        @target = target[feature]
        @gate_changes = []
        @conflict = nil
        @previous_presence_conflict = nil

        build
      end

      def conflicts
        list = gate_changes.select(&:conflict?).map(&:conflict)
        list << @conflict if @conflict
        list
      end

      def changed?
        @action != :keep
      end

      # Public: Resolves the feature-presence conflict (:source or :target)
      # and rebuilds the derived action and gate changes.
      def resolve_presence!(choice)
        raise ConflictNotFound.new(feature) unless @conflict&.kind == :presence
        @conflict.resolve!(choice)
        @presence_choice = choice.to_sym
        build
        self
      end

      # Internal: Resolves a scalar gate conflict and recomputes the merge.
      def resolve_gate!(gate, choice)
        gate_change = @gate_changes.find { |change| change.gate == gate.to_sym }
        raise ConflictNotFound.new(feature, gate) unless gate_change&.conflict?
        gate_change.conflict.resolve!(choice)
        gate_change.resolve!(choice)
        @merged_config = build_merged_config
        self
      end

      # Public: The full config the target should have after applying the
      # resolved plan.
      def merged_config
        @merged_config
      end

      def to_h
        {
          feature: feature,
          action: action,
          gate_changes: gate_changes.select(&:changed?).map(&:to_h),
          merged_config: presentable_config(merged_config),
          conflict: conflict&.to_h,
        }
      end

      private

      def build
        @retained_presence_conflict = @previous_presence_conflict if @previous_presence_conflict&.resolved?
        @gate_changes = []
        @conflict = @retained_presence_conflict
        @merged_config = nil

        determine_presence
        return if @action == :keep

        case @action
        when :add
          @gate_changes = GATE_KEYS.map { |gate| gate_change_for(gate) }
          @merged_config = copy_config(@source)
        when :remove
          @merged_config = nil
        when :modify
          @gate_changes = GATE_KEYS.map { |gate| gate_change_for(gate) }
          @gate_changes.each do |change|
            change.conflict.feature = feature if change.conflict?
          end
          @merged_config = build_merged_config
        end
      end

      # Presence truth table over (in_base, in_source, in_target):
      #
      #   0 0 0  keep    feature exists nowhere
      #   0 0 1  keep    target-only feature, promotion must not touch it
      #   0 1 0  add     new feature coming from source
      #   0 1 1  modify  independently added on both sides, merge gates
      #   1 0 0  keep    already removed on both sides
      #   1 0 1  remove  source removed it; conflict if target also changed it
      #   1 1 0  add     target removed a feature source still keeps
      #   1 1 1  modify  exists everywhere, merge per gate
      #
      # The 1 1 0 row is a presence conflict on first build only when the
      # target side actually deleted it relative to the baseline; resolving it
      # :source re-adds, :target keeps it gone.
      def determine_presence
        table = [@in_base ? 1 : 0, @in_source ? 1 : 0, @in_target ? 1 : 0].join

        case table
        when "000", "001", "100"
          @action = :keep
        when "010"
          @action = :add
        when "011"
          @action = :modify
        when "101"
          # Source deleted; :source removes, :target keeps. Unchanged target
          # removes cleanly, a target-side modification needs a decision.
          if @presence_choice == :target
            @action = :keep
          elsif @presence_choice == :source || @target == @base
            @action = :remove
          else
            @action = :remove
            @conflict = @retained_presence_conflict || presence_conflict
          end
        when "110"
          if @presence_choice == :source
            @action = :add
          elsif @presence_choice == :target
            @action = :keep
          else
            @action = :add
            @conflict = @retained_presence_conflict || presence_conflict
          end
        when "111"
          @action = @source == @target && @source == @base ? :keep : :modify
        end

        @previous_presence_conflict = @conflict&.kind == :presence ? @conflict : @retained_presence_conflict
      end

      def presence_conflict
        Conflict.new(
          feature: feature,
          kind: :presence,
          base_value: presentable_config(@base),
          source_value: @in_source ? presentable_config(@source) : nil,
          target_value: @in_target ? presentable_config(@target) : nil,
        )
      end

      def gate_change_for(gate)
        GateChange.new(
          gate: gate,
          base: @base[gate],
          source: @source[gate],
          target: @target[gate],
        )
      end

      def build_merged_config
        config = copy_config(@target)
        @gate_changes.each do |change|
          next if change.conflict?
          config[change.gate] = copy_value(change.merged_value)
        end
        config
      end

      def copy_config(config)
        copy = Snapshot::DEFAULT_CONFIG.dup
        GATE_KEYS.each { |gate| copy[gate] = copy_value(config[gate]) }
        copy
      end

      def copy_value(value)
        value.is_a?(Set) ? value.dup : value
      end

      def presentable_config(config)
        return nil if config.nil?
        result = {}
        GATE_KEYS.each do |gate|
          value = config[gate]
          result[gate] = value.is_a?(Set) ? value.to_a.sort : value
        end
        result
      end
    end
  end
end
