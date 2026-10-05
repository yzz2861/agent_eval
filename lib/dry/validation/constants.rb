# frozen_string_literal: true

require "pathname"
require "dry/core/constants"

module Dry
  module Validation
    include ::Dry::Core::Constants

    DOT = "."

    # Context key used to carry the active {Batch} session during a contract call
    #
    # @see Batch
    #
    # @api private
    BATCH_CONTEXT_KEY = :__dry_validation_batch__

    # Root path is used for base errors in hash representation of error messages
    ROOT_PATH = [nil].freeze

    # Path to the default errors locale file
    DEFAULT_ERRORS_NAMESPACE = "dry_validation"

    # Path to the default errors locale file
    DEFAULT_ERRORS_PATH = Pathname(__FILE__).join("../../../../config/errors.yml").realpath.freeze

    # Mapping for block kwarg options used by block_options
    #
    # @see Rule#block_options
    BLOCK_OPTIONS_MAPPINGS = ::Hash.new { |_, key| key }.update(context: :_context).freeze

    # Error raised when `rule` specifies one or more keys that the schema doesn't specify
    InvalidKeysError = ::Class.new(::StandardError)

    # Error raised when a localized message was not found
    MissingMessageError = ::Class.new(::StandardError)

    # Error raised when trying to define a schema in a contract class that already has a schema
    DuplicateSchemaError = ::Class.new(::StandardError)

    # Error raised during initialization of a contract that has no schema defined
    SchemaMissingError = ::Class.new(::StandardError) do
      # @api private
      def initialize(klass)
        super("#{klass} cannot be instantiated without a schema defined")
      end
    end

    # Error raised when a mergeable external check is used outside of a {Batch} session
    MissingBatchSessionError = ::Class.new(::StandardError) do
      # @api private
      def initialize(query_name)
        super(
          "mergeable external check #{query_name.inspect} requires an active " \
          "Dry::Validation::Batch session; wrap the calls with batch.call(contract, input)"
        )
      end
    end

    # Error raised when a rule references a query that the batch session did not register
    UnknownQueryError = ::Class.new(::StandardError) do
      # @api private
      def initialize(query_name, available = EMPTY_ARRAY)
        suffix = available.empty? ? "no queries are registered" : "available: #{available.inspect}"
        super("query #{query_name.inspect} is not registered on the batch session (#{suffix})")
      end
    end

    # Error raised when {Batch#flush} is called more than once or after a flush
    BatchFlushedError = ::Class.new(::StandardError)

    # Error raised when a query callable returns a value that is not a Hash
    QueryResultError = ::Class.new(::StandardError)
  end
end
