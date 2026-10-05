require "set"

module Flipper
  class PromotionPlan
    # Internal: Three-way diff and merged result for one gate of one feature.
    #
    # For set gates (actors/groups) additions and deletions are computed
    # independently against the baseline so a target-side temporary change is
    # never wiped by a source overwrite:
    #
    #   merged = (target | (source - base)) - (base - source)
    #
    # For scalar gates (boolean, expression, percentages) a value changed on
    # both sides in different ways is reported as a conflict.
    class GateChange
      SET_GATES = Snapshot::SET_GATES

      attr_reader :gate
      attr_reader :base_value
      attr_reader :source_value
      attr_reader :target_value
      attr_reader :merged_value
      attr_reader :added
      attr_reader :removed

      def initialize(gate:, base:, source:, target:)
        @gate = gate.to_sym
        @base_value = base
        @source_value = source
        @target_value = target
        @added = Set.new
        @removed = Set.new

        if set_gate?
          merge_set(base, source, target)
        else
          merge_scalar(base, source, target)
        end
      end

      def set_gate?
        SET_GATES.include?(@gate)
      end

      def conflict?
        !!@conflict
      end

      attr_accessor :conflict

      def changed?
        return true if conflict?
        return !@added.empty? || !@removed.empty? if set_gate?
        @merged_value != target_value
      end

      # Internal: Recompute the merged value after the associated conflict was
      # resolved. :source takes the source value, :target keeps the target side.
      def resolve!(choice)
        @merged_value = choice == :source ? source_value : target_value
        @added = @merged_value - target_value if set_gate?
        @removed = target_value - @merged_value if set_gate?
        @conflict = nil
      end

      # Public: Values this change will add to (:add) or remove from (:remove)
      # the target, and the :target resulting value.
      def to_h
        result = {
          gate: gate,
          type: set_gate? ? :set : :scalar,
          added: set_gate? ? added.to_a.sort : nil,
          removed: set_gate? ? removed.to_a.sort : nil,
          base_value: presentable(base_value),
          source_value: presentable(source_value),
          target_value: presentable(target_value),
          merged_value: presentable(merged_value),
        }
        result[:conflict] = conflict.to_h if conflict?
        result
      end

      private

      def merge_set(base, source, target)
        @added = source - base
        @removed = base - source
        @merged_value = (target | @added) - @removed

        # Surface the operations relative to the target as they will actually
        # be applied.
        @added = @merged_value - target
        @removed = target - @merged_value
      end

      def merge_scalar(base, source, target)
        if source == target
          @merged_value = target
        elsif source == base
          @merged_value = target
        elsif target == base
          @merged_value = source
        else
          @merged_value = nil
          @conflict = Conflict.new(
            feature: nil,
            kind: :gate_value,
            gate: @gate,
            base_value: presentable(base),
            source_value: presentable(source),
            target_value: presentable(target),
          )
        end
      end

      def presentable(value)
        value.is_a?(Set) ? value.to_a.sort : value
      end
    end
  end
end
