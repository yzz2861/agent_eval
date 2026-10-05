module Flipper
  class PromotionPlan
    # Raised when applying a plan that still has unresolved conflicts.
    class UnresolvedConflicts < Flipper::Error
      def initialize(conflicts)
        @conflicts = conflicts
        super("Cannot apply promotion plan with #{conflicts.size} unresolved conflict(s). " \
              "Resolve them with Flipper::PromotionPlan#resolve! first.")
      end

      attr_reader :conflicts
    end

    # Raised when the target adapter changed after the plan was built.
    class TargetVersionMismatch < Flipper::Error
      def initialize(expected_version, actual_version)
        @expected_version = expected_version
        @actual_version = actual_version
        super("Target configuration changed since the promotion plan was built " \
              "(expected #{expected_version}, got #{actual_version}). Rebuild the plan and re-review.")
      end

      attr_reader :expected_version, :actual_version
    end

    # Raised when a referenced feature or conflict does not exist.
    class ConflictNotFound < Flipper::Error
      def initialize(feature, gate = nil)
        suffix = gate ? " gate #{gate.inspect}" : ""
        super("No unresolved conflict found for feature #{feature.inspect}#{suffix}.")
      end
    end

    # Raised when a conflict is resolved with an unsupported choice.
    class InvalidResolution < Flipper::Error
      def initialize(choice, valid_choices)
        super("Invalid resolution #{choice.inspect}. Valid choices are #{valid_choices.inspect}.")
      end
    end
  end
end
