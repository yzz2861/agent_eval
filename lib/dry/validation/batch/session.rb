# frozen_string_literal: true

require "dry/validation/constants"

module Dry
  module Validation
    module Batch
      # A batch validation session
      #
      # Contracts are validated one by one via {#call}, but their external
      # checks are only collected (using normalized keys) instead of being
      # executed. When the session is finalized, the collected keys are
      # grouped by query definition and context partition, each querier is
      # called once with the deduplicated keys (in the order they were first
      # seen) and the outcomes are backfilled into each result.
      #
      # Rules and external checks that are not part of a batch session keep
      # their original behavior.
      #
      # @example
      #   session = Dry::Validation::Batch::Session.new
      #   results = inputs.map { |input| session.call(contract, input) }
      #   session.finalize
      #
      # @see ExternalCheck
      #
      # @api public
      class Session
        # @return [Array<Entry>] Deferred checks in registration order
        #
        # @api private
        attr_reader :entries

        # @return [Array<Result>] Results in the order they were validated
        #
        # @api public
        attr_reader :results

        # @api private
        def initialize
          @entries = []
          @results = []
          @finalized = false
        end

        # Validate input against a contract within this session
        #
        # The returned result stays mutable until the session is finalized,
        # when backfilled errors are added and the result is frozen.
        #
        # @param [Contract] contract
        # @param [Hash] input
        # @param [Hash] context
        #
        # @return [Result]
        #
        # @api public
        def call(contract, input, context = EMPTY_HASH)
          if finalized?
            raise FinalizedError, "cannot validate more input once the session is finalized"
          end

          contract.call(input, context, self).tap do |result|
            results << result
          end
        end

        # Defer an external check entry for later resolution
        #
        # @param [Entry] entry
        #
        # @return [Session]
        #
        # @api private
        def defer(entry)
          entries << entry
          self
        end

        # Resolve all deferred checks and freeze their results
        #
        # @return [Session]
        #
        # @api public
        def finalize
          return self if finalized?

          @finalized = true

          entries.group_by { |entry| [entry.check.query, entry.partition] }.each_value do |group|
            resolve(group)
          end

          results.each(&:freeze)

          self
        end

        # Whether the session has been finalized
        #
        # @return [Boolean]
        #
        # @api public
        def finalized?
          @finalized
        end

        private

        # Call the querier once for a group of entries and backfill outcomes
        #
        # @api private
        def resolve(group)
          keys = group.map(&:key).uniq

          begin
            records = group.first.check.query.(keys, group.first.partition)
          rescue StandardError
            return group.each(&:apply_unavailable)
          end

          group.each { |entry| entry.resolve(records) }
        end
      end
    end
  end
end
