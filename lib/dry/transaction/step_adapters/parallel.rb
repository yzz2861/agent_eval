# frozen_string_literal: true

require "thread"

module Dry
  module Transaction
    class StepAdapters
      # Runs independent transactions concurrently and collects named results.
      #
      # The input is passed to every branch as the same object. Branches must
      # treat it as read-only; the adapter does not freeze or copy business data.
      class Parallel
        include Dry::Monads[:result]

        def requires_operation?
          false
        end

        def call(_operation, options, args)
          branches = options.fetch(:branches)
          max_concurrency = options.fetch(:max_concurrency) {
            raise ArgumentError,
              "parallel step +#{options[:step_name]}+ requires +max_concurrency:+"
          }

          assert_branches(branches, options[:step_name])
          assert_max_concurrency(max_concurrency, options[:step_name])

          state = State.new(branches, args[0])
          worker_count = [branches.size, max_concurrency].min
          threads = Array.new(worker_count) do
            Thread.new(state) { |branch_state| worker(branch_state) }
          end
          threads.each(&:join)

          raise(state.exception) if state.exception

          if state.failures.empty?
            Success(state.successes)
          else
            Failure(state.failures)
          end
        end

        private

        def worker(state)
          loop do
            branch = state.next_branch
            break unless branch

            name, transaction = branch

            begin
              state.record_result(name, transaction.call(state.input))
            rescue StandardError => error
              state.record_exception(error)
            end
          end
        end

        def assert_branches(branches, step_name)
          unless branches.is_a?(Hash) && !branches.empty?
            raise ArgumentError,
              "parallel step +#{step_name}+ requires a non-empty +branches:+ hash"
          end

          branches.each do |name, transaction|
            next if transaction.respond_to?(:call)

            raise ArgumentError,
              "parallel branch +#{name}+ in step +#{step_name}+ must respond to +#call+"
          end
        end

        def assert_max_concurrency(max_concurrency, step_name)
          return if max_concurrency.is_a?(Integer) && max_concurrency.positive?

          raise ArgumentError,
            "parallel step +#{step_name}+ requires a positive integer +max_concurrency:+"
        end

        class State
          attr_reader :input, :successes, :failures, :exception

          def initialize(branches, input)
            @pending = branches.to_a
            @input = input
            @successes = {}
            @failures = {}
            @exception = nil
            @stop = false
            @mutex = Mutex.new
          end

          def next_branch
            @mutex.synchronize do
              return nil if @stop

              @pending.shift
            end
          end

          def record_result(name, result)
            raise InvalidResultError, name unless result.is_a?(Dry::Monads::Result)

            @mutex.synchronize do
              if result.success?
                @successes[name] = result.value!
              else
                @failures[name] = result.failure
                @stop = true
              end
            end
          end

          def record_exception(error)
            @mutex.synchronize do
              @exception ||= error
              @stop = true
            end
          end
        end

        private_constant :State
      end

      register :parallel, Parallel.new
    end
  end
end
