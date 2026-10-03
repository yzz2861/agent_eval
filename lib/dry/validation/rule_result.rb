# frozen_string_literal: true

require "dry/validation/constants"

module Dry
  module Validation
    # Outcome of a single rule execution
    #
    # Every rule that a contract knows about produces exactly one outcome when
    # the contract is called. A rule is either:
    #
    # - passed: it was executed and produced no failures
    # - failed: it was executed and produced failures
    # - skipped: it was not executed, and the reason explains why
    #
    # @see Result#rule_results
    #
    # @api public
    class RuleResult
      include ::Dry::Equalizer(:rule, :status, :reason, inspect: false)

      # The rule was executed and produced no failures
      PASSED = :passed

      # The rule was executed and produced failures
      FAILED = :failed

      # The rule was not executed
      SKIPPED = :skipped

      # All possible statuses
      STATUSES = [PASSED, FAILED, SKIPPED].freeze

      # Reason used when a rule was not executed because its keys did not
      # pass schema checks
      SCHEMA_ERROR = :schema_error

      # Reason used when a rule was not executed because at least one of its
      # dependencies did not pass
      UNMET_DEPENDENCIES = :unmet_dependencies

      # @!attribute [r] rule
      #   @return [Rule] The rule this outcome belongs to
      #   @api public
      attr_reader :rule

      # @!attribute [r] status
      #   @return [Symbol] One of :passed, :failed or :skipped
      #   @api public
      attr_reader :status

      # @!attribute [r] reason
      #   @return [Hash, nil] For skipped rules, a hash explaining why the rule
      #     was not executed. Its :type is either :schema_error (with :keys
      #     that did not pass schema checks) or :unmet_dependencies (with
      #     :dependencies that did not pass). Nil for executed rules.
      #   @api public
      attr_reader :reason

      # @api private
      def initialize(rule, status:, reason: nil)
        @rule = rule
        @status = status
        @reason = reason
      end

      # Name of the rule (if it has one)
      #
      # @return [Symbol, nil]
      #
      # @api public
      def name
        rule.name
      end

      # @return [Boolean]
      #
      # @api public
      def passed?
        status.equal?(PASSED)
      end

      # @return [Boolean]
      #
      # @api public
      def failed?
        status.equal?(FAILED)
      end

      # @return [Boolean]
      #
      # @api public
      def skipped?
        status.equal?(SKIPPED)
      end

      # Return a nice string representation
      #
      # @return [String]
      #
      # @api public
      def inspect
        details = +"name=#{name.inspect} status=#{status.inspect}"
        details << " reason=#{reason.inspect}" if reason
        %(#<#{self.class} #{details}>)
      end
    end
  end
end
