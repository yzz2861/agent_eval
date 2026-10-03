# frozen_string_literal: true

module Dry
  module Transaction
    class StepAdapters
      # Runs a set of named branches concurrently and combines their results.
      #
      # The step operation must return a Hash mapping branch names to branch
      # operations. Each branch operation is an ordinary callable (typically
      # another dry-transaction) that receives the step input and returns a
      # Result.
      #
      # The step input is handed to every branch as is: it is never
      # duplicated or cloned. Branch operations must therefore treat their
      # input as read-only.
      #
      # At most +max_concurrency:+ branches run at the same time. The option
      # is required so the concurrency limit is always an explicit decision
      # made by the caller.
      #
      # When every branch succeeds, the step passes a Hash of
      # +branch_name => branch_value+ (in branch definition order) to the
      # next step. When a branch fails, branches that have not started yet
      # are not started, branches already in flight are awaited, and the
      # step fails with a Hash of +branch_name => branch_failure+ for every
      # failed branch, so the failure can be traced back to its branch.
      #
      # @api private
      class Parallel
        include Dry::Monads[:result]

        def call(operation, options, args)
          limit = fetch_max_concurrency(options)
          branches = fetch_branches(operation, args, options)

          results, errors = run(branches, args[0], limit)

          raise errors.values.first unless errors.empty?

          failures = {}
          values = {}

          branches.each_key do |name|
            result = results[name]
            next unless result

            if result.failure?
              failures[name] = result.failure
            else
              values[name] = result.value!
            end
          end

          failures.empty? ? Success(values) : Failure(failures)
        end

        private

        def fetch_max_concurrency(options)
          limit = options[:max_concurrency]

          unless limit.is_a?(Integer) && limit >= 1
            raise MissingConcurrencyLimitError, options[:step_name]
          end

          limit
        end

        def fetch_branches(operation, args, options)
          branches = operation.(*args)

          unless branches.is_a?(Hash) && branches.values.all? { |branch| branch.respond_to?(:call) }
            raise InvalidBranchesError, options[:step_name]
          end

          branches
        end

        def run(branches, input, limit)
          queue = Queue.new
          branches.each { |branch| queue << branch }

          results = {}
          errors = {}
          stopped = false
          state = Mutex.new

          Array.new([limit, branches.size].min) {
            Thread.new {
              loop do
                break if state.synchronize { stopped }

                name, branch = begin
                  queue.pop(true)
                rescue ThreadError
                  break
                end

                # A branch dequeued but not yet started must not start once
                # a sibling branch has failed.
                break if state.synchronize { stopped }

                begin
                  result = branch.call(input)

                  unless result.is_a?(Dry::Monads::Result)
                    raise InvalidResultError, name
                  end

                  state.synchronize {
                    results[name] = result
                    stopped = true if result.failure?
                  }
                rescue => e
                  state.synchronize {
                    errors[name] = e
                    stopped = true
                  }
                end
              end
            }
          }.each(&:join)

          [results, errors]
        end
      end

      register :parallel, Parallel.new
    end
  end
end
