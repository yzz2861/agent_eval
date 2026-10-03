# frozen_string_literal: true

module Dry
  module Types
    class Stream
      # Lazy, single-pass result returned by a member stream
      #
      # @api public
      class Result
        include ::Enumerable

        # @return [Symbol] +:pending+, +:success+, +:failure+, or +:closed+
        attr_reader :status

        # @return [Integer, nil]
        attr_reader :failure_index

        # @return [Object, nil]
        attr_reader :error

        # @api private
        def initialize(source, member, on_error: :raise)
          @source = source
          @member = member
          @on_error = Member.error_mode(on_error)
          @mutex = ::Mutex.new
          @status = :pending
          @failure_index = nil
          @failure_indices = []
          @error = nil
        end

        # Iterate lazily through coerced members
        #
        # In +:raise+ mode each successful value is yielded. In +:continue+
        # mode an {Item} carrying the original index is yielded for every input
        # member.
        #
        # @return [Enumerator, nil]
        #
        # @api public
        def each(&block)
          return to_enum(:each) unless block

          @mutex.synchronize do
            raise @error if failure?
            raise ::IOError, "stream is closed" if closed?
            return if success?
          end

          enumerate(&block)
        end

        # Stop iteration and explicitly close the single-pass input
        #
        # @return [void]
        #
        # @api public
        def close
          @mutex.synchronize do
            return unless pending?

            @status = :closed
            @source.close if @source.respond_to?(:close)
          end
        end

        # @return [Boolean]
        #
        # @api public
        def pending? = @status.equal?(:pending)

        # @return [Boolean]
        #
        # @api public
        def success? = @status.equal?(:success)
        alias_method :succeeded?, :success?

        # @return [Boolean]
        #
        # @api public
        def failure? = @status.equal?(:failure)
        alias_method :failed?, :failure?

        # @return [Boolean]
        #
        # @api public
        def closed? = @status.equal?(:closed)

        # @return [Array<Integer>]
        #
        # @api public
        def failure_indices = @failure_indices.dup

        # Keeps inspection non-consuming.
        #
        # @return [String]
        #
        # @api public
        def inspect
          "#<Dry::Types::Stream::Result status=#{status}" \
            "#{failure_index ? " failure_index=#{failure_index}" : EMPTY_STRING}>"
        end

        private

        # @api private
        def continue? = @on_error.equal?(:continue)

        # @api private
        def enumerate
          index = 0

          @source.each do |value|
            result =
              begin
                @member.try(value)
              rescue StandardError => exception
                exception
              end

            if result.is_a?(::Exception)
              record_failure(index, result)
              if continue?
                output = Item.failure(index, value, result)
              else
                raise result
              end
              next unless continue?
            end

            if result.success?
              output = continue? ? Item.success(index, result.input) : result.input
            elsif continue?
              record_failure(index, result.error)
              output = Item.failure(index, value, result.error)
            else
              record_failure(index, result.error)
              raise result.error
            end

            if Undefined.equal?(result.input)
              index += 1
              next
            end

            yield(output)
            index += 1
          end

          @status = failure? ? :failure : :success
        end

        # @api private
        def record_failure(index, error)
          @failure_index ||= index
          @failure_indices << index unless @failure_indices.include?(index)
          @error = error
          @status = :failure
        end
      end
    end
  end
end
