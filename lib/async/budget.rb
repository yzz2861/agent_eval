# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "fiber"

Fiber.attr_accessor :async_budget

require_relative "clock"

module Async
	# A cooperative work budget for tasks that process many records in memory without touching I/O.
	#
	# Fibers are cooperatively scheduled: a tight CPU-bound loop that never performs a blocking operation will starve every other task in the reactor. A budget fixes this without changing existing behavior. The caller marks {#checkpoint!} inside the loop, and the budget yields back to the scheduler once either a fixed number of operations have been performed or a monotonic time quantum has elapsed.
	#
	# Yielding is cooperative. A budget can only take effect at a {#checkpoint!} call; it cannot preempt code that never checks in. Cancellation is likewise observed at checkpoints, because a yield is a scheduling point where a pending cancellation can be delivered.
	#
	# Budgets are optional and opt-in. Calling {Task#checkpoint!} or {Budget.checkpoint!} without an active budget is a no-op, so adding checkpoints to a library is backward compatible.
	#
	# @example Processing a large collection fairly.
	# 	Async::Budget.with(operations: 100) do
	# 		records.each do |record|
	# 			process(record)
	# 			Async::Budget.checkpoint!
	# 		end
	# 	end
	class Budget
		# Create a new budget and execute the given block within its scope.
		#
		# The budget becomes the {Budget.current} budget for the duration of the block, even when invoked without a running task. At least one limit must be given.
		#
		# @parameter operations [Integer | Nil] The maximum number of {#checkpoint!} operations per quantum before yielding.
		# @parameter time [Numeric | Nil] The maximum monotonic time, in seconds, per quantum before yielding.
		# @parameter parent [Budget | Nil] The enclosing budget. Defaults to {Budget.current}.
		# @parameter clock [#now] The monotonic clock used to measure time, responding to `#now` in seconds. Injected in tests to make time-based yields deterministic.
		# @yields {...} The block to execute within the budget scope.
		# @returns [Object] The result of the block.
		def self.with(operations: nil, time: nil, parent: nil, clock: Clock, &block)
			raise ArgumentError, "Must specify at least one of `operations:` or `time:`!" if operations.nil? && time.nil?
			
			budget = self.new(operations: operations, time: time, parent: parent || Budget.current, clock: clock)
			
			return budget.call(&block)
		end
		
		# Perform a checkpoint against the {Budget.current} budget, if any.
		#
		# Without an active budget, this is a no-op, which makes it safe to call from shared library code unconditionally.
		#
		# @parameter operations [Integer] The number of logical operations performed since the previous checkpoint.
		def self.checkpoint!(operations = 1)
			Budget.current&.checkpoint!(operations)
		end
		
		# @returns [Budget | Nil] The innermost active budget for the current fiber, if any.
		def self.current
			Fiber.current.async_budget
		end
		
		# Create a new budget. Prefer {Budget.with} for block-scoped use.
		#
		# At least one limit must be given.
		#
		# @parameter operations [Integer | Nil] The maximum number of operations per quantum before yielding.
		# @parameter time [Numeric | Nil] The maximum monotonic time, in seconds, per quantum before yielding.
		# @parameter parent [Budget | Nil] The enclosing budget. Defaults to {Budget.current}.
		# @parameter clock [#now] The monotonic clock used to measure time.
		def initialize(operations: nil, time: nil, parent: Budget.current, clock: Clock)
			raise ArgumentError, "Must specify at least one of `operations:` or `time:`!" if operations.nil? && time.nil?
			
			@operations_limit = operations
			@time_limit = time
			@parent = parent
			@clock = clock
			
			@consumed_operations = 0
			@window_started_at = nil
		end
		
		# @returns [Integer | Nil] The maximum number of operations per quantum before yielding.
		attr :operations_limit
		
		# @returns [Numeric | Nil] The maximum monotonic time, in seconds, per quantum before yielding.
		attr :time_limit
		
		# @returns [Budget | Nil] The enclosing budget, if nested.
		attr :parent
		
		# @returns [#now] The clock used to measure time.
		attr :clock
		
		# @returns [Integer] The number of operations consumed within the current quantum.
		attr :consumed_operations
		
		# @returns [Numeric | Nil] The monotonic timestamp at which the current quantum started.
		attr :window_started_at
		
		# Activate this budget for the duration of the block.
		#
		# Nested scopes form a chain: a child scope's {#checkpoint!} consumes against every enclosing scope, and a yield is required once any scope in the chain is exhausted. This means a child scope cannot reset its counter to bypass a tighter parent limit; every enclosing scope sees all of the child's operations.
		#
		# @yields {...} The block to execute within the budget scope.
		# @returns [Object] The result of the block.
		def call(&block)
			previous = Fiber.current.async_budget
			Fiber.current.async_budget = self
			
			return yield(self)
		ensure
			Fiber.current.async_budget = previous
		end
		
		# Mark a checkpoint.
		#
		# The given number of operations is consumed against this budget and every enclosing budget. If any scope in the chain has reached its operation count or elapsed its time quantum, the current fiber yields to the scheduler so other tasks can make progress.
		#
		# When the fiber resumes, a fresh quantum starts for the whole chain: every scope's operation counter resets to zero and its time window restarts. Resets never happen without a yield, so counters cannot be reset merely by entering or leaving a nested scope.
		#
		# A yield is a scheduling point: if the current task was cancelled while the fiber was yielded, the {Async::Cancel} exception is raised here. Cancellation is therefore visible at checkpoints. Use {Task#defer_cancel} around cleanup code that must finish before the task is cancelled.
		#
		# @parameter operations [Integer] The number of logical operations performed since the previous checkpoint.
		# @raises {Async::Cancel} If the current task was cancelled while yielded.
		def checkpoint!(operations = 1)
			self.consume!(operations)
			
			if self.exhausted?
				# Without a scheduler (e.g. outside a task) there is nothing to yield to, so simply begin a fresh quantum:
				if scheduler = Fiber.scheduler
					scheduler.yield
					
					# While we were yielded, the task may have been cancelled without the exception being delivered yet (e.g. a cancellation queued with `Task#cancel(later: true)`). A checkpoint must observe cancellation, so deliver it explicitly:
					task = Task.current?
					
					if task && (task.cancelled? || scheduler.pending_cancel?(task))
						# The queued cancellation will be delivered by `cancel` below rather than the ready queue:
						scheduler.clear_pending_cancel(task)
						task.cancel(false)
					end
				end
				
				# The whole chain begins a fresh quantum:
				self.reset!
			end
		end
		
		# @returns [Boolean] Whether this scope or any enclosing scope has exhausted its current quantum.
		def exhausted?
			node = self
			
			while node
				if node.operations_exhausted? || node.time_exhausted?
					return true
				end
				
				node = node.parent
			end
			
			return false
		end
		
		# @returns [Boolean] Whether the operation count limit has been reached for this scope.
		def operations_exhausted?
			if @operations_limit
				return @consumed_operations >= @operations_limit
			end
			
			return false
		end
		
		# @returns [Boolean] Whether the elapsed time quantum has been reached for this scope.
		def time_exhausted?
			if @time_limit
				# Lazily start the time window on the first operation of the quantum:
				@window_started_at ||= @clock.now
				
				return @clock.now - @window_started_at >= @time_limit
			end
			
			return false
		end
		
		# Consume the given number of operations against the whole scope chain.
		#
		# @parameter operations [Integer] The number of operations performed.
		def consume!(operations = 1)
			node = self
			
			while node
				node.consume_operations!(operations)
				node = node.parent
			end
		end
		
		# Reset the current quantum for the whole scope chain, after a yield.
		def reset!
			node = self
			
			while node
				node.reset_operations!
				node = node.parent
			end
		end
		
		# @returns [String] A description of the budget and its limits.
		def to_s
			limits = []
			limits << "operations=#{@operations_limit}" if @operations_limit
			limits << "time=#{@time_limit}" if @time_limit
			
			return "\#<#{self.class} #{limits.join(' ')}>"
		end
		
		protected
		
		# Consume operations against this scope only.
		def consume_operations!(operations)
			@consumed_operations += operations
		end
		
		# Reset this scope's quantum counters.
		def reset_operations!
			@consumed_operations = 0
			# The fresh quantum starts now (the fiber has just resumed):
			@window_started_at = @clock.now if @time_limit
		end
	end
end
