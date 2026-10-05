# frozen_string_literal: true

require "dry/initializer"
require "dry/validation/constants"

module Dry
  module Validation
    # External checks query an external system (such as a database or an API)
    # to verify that a value refers to a record that exists and satisfies a
    # business condition.
    #
    # When contracts are validated within a {Batch::Session}, checks declared
    # with the same query definition and context partition are merged: their
    # normalized keys are collected first, the querier is called once with the
    # deduplicated keys, and the outcome is backfilled into each result.
    #
    # Three distinct outcomes are reported:
    #
    # - the querier itself failed (eg. the service is unavailable) - a base
    #   error using the +:unavailable+ message
    # - no record was found for the key - a key error using the +:not_found+
    #   message
    # - the record was found but doesn't satisfy the +:condition+ - a key
    #   error using the +:rejected+ message
    #
    # @example
    #   class ImportContract < Dry::Validation::Contract
    #     params do
    #       required(:department_code).filled(:string)
    #     end
    #
    #     external_check :department,
    #                    on: :department_code,
    #                    normalize: ->(code) { code.to_s.strip.upcase },
    #                    partition: ->(context) { context[:tenant_id] },
    #                    query: ->(codes, tenant) { department_repo.fetch_all(codes, tenant) },
    #                    condition: ->(department) { department.active? }
    #   end
    #
    # @see Batch::Session
    #
    # @api public
    class ExternalCheck
      include ::Dry::Equalizer(:name, :keys, inspect: false)

      extend ::Dry::Initializer

      # Default message used when no record was found for a key
      DEFAULT_NOT_FOUND = "does not exist"

      # Default message used when a record doesn't satisfy the condition
      DEFAULT_REJECTED = "is not valid"

      # Default message used when the querier itself failed
      DEFAULT_UNAVAILABLE = "could not be verified"

      # @!attribute [r] name
      #   @return [Symbol] Check identifier
      #   @api private
      option :name

      # @!attribute [r] keys
      #   @return [Array] Key specs the check depends on (the first one feeds the querier)
      #   @api private
      option :keys

      # @!attribute [r] query
      #   @return [#call] Querier called with (normalized keys, partition),
      #     expected to return a key => record mapping (nil means "not found")
      #   @api private
      option :query

      # @!attribute [r] normalize
      #   @return [#call] Turns the checked value into a canonical key
      #   @api private
      option :normalize, default: proc { ->(value) { value } }

      # @!attribute [r] partition
      #   @return [#call] Extracts the context partition; only keys from the
      #     same partition are merged into one querier call
      #   @api private
      option :partition, default: proc { ->(_context) { nil } }

      # @!attribute [r] condition
      #   @return [#call, nil] Business condition verified against found records
      #   @api private
      option :condition, default: proc { nil }

      # @!attribute [r] not_found
      #   @return [String, Symbol] Message used when no record was found
      #   @api private
      option :not_found, default: proc { DEFAULT_NOT_FOUND }

      # @!attribute [r] rejected
      #   @return [String, Symbol] Message used when the condition is not met
      #   @api private
      option :rejected, default: proc { DEFAULT_REJECTED }

      # @!attribute [r] unavailable
      #   @return [String, Symbol] Message used when the querier failed
      #   @api private
      option :unavailable, default: proc { DEFAULT_UNAVAILABLE }

      # Evaluate the check against a result
      #
      # In a batch session the check is deferred and resolved once the session
      # is finalized, otherwise the querier is called immediately.
      #
      # @param [Contract] contract
      # @param [Result] result
      # @param [Batch::Session, nil] batch
      #
      # @api private
      def call(contract, result, batch = nil)
        return unless result.key?(keys.first)

        key = normalize.(result.values[keys.first])
        context_partition = partition.(result.context)

        entry = Batch::Entry.new(
          check: self, contract: contract, result: result, key: key, partition: context_partition
        )

        if batch
          batch.defer(entry)
        else
          begin
            entry.resolve(query.([key], context_partition))
          rescue StandardError
            entry.apply_unavailable
          end
        end
      end

      # The path of the checked value, used for key errors
      #
      # @return [Dry::Schema::Path]
      #
      # @api private
      def path
        @path ||= Schema::Path[keys.first]
      end

      # Whether a business condition was configured
      #
      # @return [Boolean]
      #
      # @api private
      def condition?
        !condition.nil?
      end

      # Return a nice string representation
      #
      # @return [String]
      #
      # @api public
      def inspect
        %(#<#{self.class} name=#{name.inspect} keys=#{keys.inspect}>)
      end
    end
  end
end
