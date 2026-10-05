module Flipper
  class PromotionPlan
    # Internal: A gate value or feature presence that changed on both the
    # source and target sides relative to the common baseline and therefore
    # cannot be merged automatically.
    class Conflict
      CHOICES = %i[source target].freeze

      attr_reader :feature
      attr_reader :gate
      attr_reader :kind
      attr_reader :base_value
      attr_reader :source_value
      attr_reader :target_value

      def initialize(feature:, kind:, gate: nil, base_value: nil, source_value: nil, target_value: nil)
        @feature = feature
        @gate = gate
        @kind = kind
        @base_value = base_value
        @source_value = source_value
        @target_value = target_value
        @resolution = nil
      end

      # Public: Resolve the conflict.
      #
      # choice - :source adopts the source side, :target keeps the target side.
      #
      # Returns the chosen resolution.
      def resolve!(choice)
        choice = choice.to_sym
        raise InvalidResolution.new(choice, CHOICES) unless CHOICES.include?(choice)
        @resolution = choice
      end

      # Internal: Gate conflicts are built before their feature is known; the
      # owning FeaturePlan fills this in during construction.
      attr_writer :feature

      def resolved?
        !@resolution.nil?
      end

      def unresolved?
        !resolved?
      end

      def resolution
        @resolution
      end

      def to_h
        {
          feature: feature,
          gate: gate,
          kind: kind,
          base_value: base_value,
          source_value: source_value,
          target_value: target_value,
          resolution: resolution,
        }
      end

      def inspect
        attributes = {
          feature: feature,
          gate: gate,
          kind: kind,
          resolution: resolution,
        }.map { |key, value| "#{key}=#{value.inspect}" }.join(", ")
        "#<#{self.class.name} #{attributes}>"
      end
    end
  end
end
