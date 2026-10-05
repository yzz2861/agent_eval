# frozen_string_literal: true

require "dry/initializer"
require "dry/validation/constants"

module Dry
  module Validation
    module Batch
      # A single deferred external check, resolved once its batch session
      # is finalized
      #
      # @api private
      class Entry
        include ::Dry::Equalizer(:check, :key, :partition, inspect: false)

        extend ::Dry::Initializer

        # @!attribute [r] check
        #   @return [ExternalCheck]
        #   @api private
        option :check

        # @!attribute [r] contract
        #   @return [Contract]
        #   @api private
        option :contract

        # @!attribute [r] result
        #   @return [Result]
        #   @api private
        option :result

        # @!attribute [r] key
        #   @return [Object] Normalized key passed to the querier
        #   @api private
        option :key

        # @!attribute [r] partition
        #   @return [Object] Context partition the key belongs to
        #   @api private
        option :partition

        # Backfill the outcome of a successful querier call into the result
        #
        # @param [#[]] records Key => record mapping returned by the querier
        #
        # @api private
        def resolve(records)
          record = records[key] if records

          if record.nil?
            add_error(check.not_found, check.path)
          elsif check.condition? && !check.condition.(record)
            add_error(check.rejected, check.path)
          end
        end

        # Backfill a querier failure into the result
        #
        # This is reported as a base error so that an unavailable service is
        # never mistaken for a missing record
        #
        # @api private
        def apply_unavailable
          add_error(check.unavailable, ROOT_PATH)
        end

        private

        # @api private
        def add_error(message, path)
          result.add_error(
            contract.message_resolver.(message: message, tokens: EMPTY_HASH, path: path)
          )
        end
      end
    end
  end
end
