# frozen_string_literal: true

require "dry/validation/constants"

module Dry
  module Validation
    # Outcome of applying a single named rule during a contract call
    #
    # A rule can be:
    #
    # - +:passed+ - the rule was applied and added no failures
    # - +:failed+ - the rule was applied and added failures
    # - +:skipped+ - the rule was not applied, either because of a schema
    #   error on one of its keys or because one of its prerequisite rules
    #   did not pass
    #
    # @api public
    class RuleResult
      include ::Dry::Equalizer(:name, :status, :unmet_dependencies)

      STATUSES = %i[passed failed skipped].freeze

      # @!attribute [r] name
      #   @return [Symbol] Name of the rule
      #   @api public
      attr_reader :name

      # @!attribute [r] status
      #   @return [Symbol] One of +:passed+, +:failed+ or +:skipped+
      #   @api public
      attr_reader :status

      # @!attribute [r] unmet_dependencies
      #   @return [Hash<Symbol => Symbol>] Prerequisite rule name => its status
      #   @api public
      attr_reader :unmet_dependencies

      # @api private
      def self.skipped(name, schema_error: false, unmet_dependencies: EMPTY_HASH)
        new(
          name: name,
          status: :skipped,
          schema_error: schema_error,
          unmet_dependencies: unmet_dependencies
        )
      end

      # @api private
      def initialize(name:, status:, schema_error: false, unmet_dependencies: EMPTY_HASH)
        unless STATUSES.include?(status)
          raise ::ArgumentError, "status must be one of #{STATUSES.inspect}, #{status.inspect} given"
        end

        @name = name
        @status = status
        @schema_error = schema_error
        @unmet_dependencies = unmet_dependencies.dup.freeze
        freeze
      end

      # Return whether the rule was applied and passed
      #
      # @return [Boolean]
      #
      # @api public
      def passed?
        status.equal?(:passed)
      end

      # Return whether the rule was applied and failed
      #
      # @return [Boolean]
      #
      # @api public
      def failed?
        status.equal?(:failed)
      end

      # Return whether the rule was not applied
      #
      # @return [Boolean]
      #
      # @api public
      def skipped?
        status.equal?(:skipped)
      end

      # Return whether the rule was skipped because its keys failed the schema
      #
      # @return [Boolean]
      #
      # @api public
      def schema_error?
        @schema_error
      end

      # Return the names of prerequisite rules that prevented execution
      #
      # @return [Array<Symbol>]
      #
      # @api public
      def failed_dependencies
        unmet_dependencies.keys
      end

      # Return a human-readable explanation of why the rule was not applied
      #
      # @return [String, nil] +nil+ when the rule was applied
      #
      # @api public
      def reason
        return unless skipped?

        if schema_error?
          "skipped due to a schema error"
        else
          descriptions = unmet_dependencies.map {
            |dep, dep_status| "#{dep.inspect} was #{dep_status}"
          }.join(" and ")
          label = unmet_dependencies.size == 1 ? "prerequisite" : "prerequisites"
          "skipped because #{label} #{descriptions}"
        end
      end

      # Return a string representation
      #
      # @return [String]
      #
      # @api public
      def inspect
        "#<#{self.class} name=#{name.inspect} status=#{status.inspect}>"
      end
    end
  end
end
