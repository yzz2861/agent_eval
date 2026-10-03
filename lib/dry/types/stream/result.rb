# frozen_string_literal: true

module Dry
  module Types
    class Stream < Nominal
      # Lazy outcome of applying a stream type to a single-pass input.
      #
      # Members are converted one by one as the result is iterated, the
      # underlying input is never rewound or materialized. The result can
      # be consumed exactly once; its #status distinguishes :pending (not
      # fully consumed yet), :success (fully consumed, no failures) and
      # :failure (a member failed, see #failure_index and #error).
      #
      # Callers stopping iteration early should call #close to release the
      # underlying source.
      #
      # @api public
      class Result
        include ::Enumerable

        EXHAUSTED = ::Object.new.freeze

        # @return [Integer, nil] index of the first failing member
        attr_reader :failure_index

        # @return [CoercionError, nil] error of the first failing member
        attr_reader :error

        # @param [#each] source
        # @param [Type] member
        # @param [Symbol] on_error
        #
        # @api private
        def initialize(source, member:, on_error: :halt)
          @source = source
          @member = member
          @on_error = on_error
          @enum = source.is_a?(::Enumerator) ? source : source.to_enum(:each)
          @index = 0
          @status = :pending
          @failure_index = nil
          @error = nil
          @failed = false
          @closed = false
        end

        # Iterate over the remaining members, converting them one by one.
        # Iteration continues where the previous one stopped.
        #
        # @raise [StreamClosedError] when the result was closed
        # @raise [StreamConsumedError] when the result was fully consumed
        # @raise [CoercionError] when a member fails and the strategy is :halt
        #
        # @return [Enumerator, self]
        #
        # @api public
        def each
          return to_enum(__method__) unless block_given?

          assert_open!

          loop do
            raw = pull
            break if EXHAUSTED.equal?(raw)

            index = @index
            @index += 1

            if collect_items?
              yield build_item(raw, index)
            else
              converted = convert(raw, index)
              yield converted unless Undefined.equal?(converted)
            end
          end

          self
        end

        # Explicitly release the underlying source when stopping early.
        # Idempotent, closes the source if it responds to #close.
        #
        # @return [self]
        #
        # @api public
        def close
          unless @closed
            @closed = true
            @source.close if @source.respond_to?(:close)
          end

          self
        end

        # @return [Symbol] :pending, :success or :failure
        #
        # @api public
        attr_reader :status

        # Whether the stream has not been fully consumed yet
        #
        # @return [Boolean]
        #
        # @api public
        def pending? = @status == :pending

        # Whether the stream was fully consumed without failures
        #
        # @return [Boolean]
        #
        # @api public
        def success? = @status == :success

        # Whether a member failed (immediately with :halt, once fully
        # consumed with :collect)
        #
        # @return [Boolean]
        #
        # @api public
        def failure? = @status == :failure

        # @return [Boolean]
        #
        # @api public
        def closed? = @closed

        # @return [String]
        #
        # @api public
        def inspect
          "#<Dry::Types::Stream::Result status=#{@status} index=#{@index}" \
            "#{@closed ? " closed" : ""}>"
        end
        alias_method :to_s, :inspect

        private

        # @api private
        def collect_items? = @on_error == :collect

        # @api private
        def assert_open!
          if closed?
            raise StreamClosedError, "stream has been closed"
          elsif success?
            raise StreamConsumedError, "stream has already been fully consumed"
          elsif failure?
            raise StreamConsumedError,
              "stream was terminated by a failure at index #{failure_index}"
          end
        end

        # @api private
        def pull
          @enum.next
        rescue ::StopIteration
          @status = @failed ? :failure : :success
          EXHAUSTED
        end

        # @api private
        def convert(raw, index)
          @member.call_unsafe(raw)
        rescue CoercionError => error
          record_failure(index, error)
          @status = :failure
          raise
        end

        # @api private
        def build_item(raw, index)
          result = @member.try(raw)

          if result.success?
            Item.new(index: index, value: result.input)
          else
            record_failure(index, result.error)
            Item.new(index: index, error: result.error)
          end
        end

        # @api private
        def record_failure(index, error)
          return if @failed

          @failed = true
          @failure_index = index
          @error = error
        end
      end
    end
  end
end
