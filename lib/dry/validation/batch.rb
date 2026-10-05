# frozen_string_literal: true

module Dry
  module Validation
    # Batch validation support
    #
    # A batch session validates many inputs against one or more contracts
    # while merging external checks that share the same query definition and
    # context partition into a single querier call.
    #
    # @example
    #   results = Dry::Validation.batch do |batch|
    #     inputs.map { |input| batch.call(contract, input) }
    #   end
    #
    # @see ExternalCheck
    # @see Batch::Session
    #
    # @api public
    module Batch
      # Error raised when a finalized session is used to validate more input
      FinalizedError = ::Class.new(::StandardError)

      # Start a new batch validation session
      #
      # Without a block the session is returned and must be finalized
      # explicitly via {Session#finalize}. With a block the session is
      # yielded, finalized automatically and then returned.
      #
      # @yield [Batch::Session]
      #
      # @return [Batch::Session]
      #
      # @api public
      def self.session
        session = Session.new

        return session unless block_given?

        yield session

        session.finalize
      end
    end
  end
end
