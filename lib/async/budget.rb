# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "clock"

Fiber.attr_accessor :async_budget

module Async
	# A work budget limits how much work a task can perform before yielding back to the scheduler, so that other tasks and timers can make progress.
	#
	# Budgets are optional and cooperative: they only take effect when the caller marks checkpoints, e.g. once per record processed in a hot loop. A checkpoint is charged against an operation count and/or a monotonic time limit. When either is exhausted, the current fiber yields to the scheduler and the budget is re-allotted.
	#
	# Budgets can be nested. Checkpoints in a nested (child) budget are also charged to all enclosing (parent) budgets, so a child scope cannot bypass the limits of its parent by resetting its own counters. When any budget in the chain is exhausted, the fiber yields, and the exhausted budget along with any budgets nested within it are re-allotted. Budgets above the exhausted one are not reset.
	#
	# Cancellation is delivered at checkpoints: yielding to the scheduler allows a pending {Async::Cancel} to be raised in the current task. Code that never calls {#checkpoint} cannot be preempted. Use {Task#defer_cancel} to protect cleanup code that must run to completion.
	#
	# @example Processing a large batch of records without starving other tasks.
	# 	Async::Budget.with(operations: 100, duration: 0.01) do |budget|
	# 		records.each do |record|
	# 			process(record)
	# 			budget.checkpoint
	# 		end
	# 	end
	#
	# @public Since *Async v2.47*.
	class Budget
		class << self
			# @returns [Budget | Nil] The budget currently active for the executing fiber, if any.
			def current
				Fiber.current.async_budget
			end
			
			# Mark a checkpoint against the current budget, if one is active. If no budget is active, this is a no-op, so instrumented code behaves the same whether or not a budget is in effect.
			#
			# @parameter cost [Integer] The number of operations to charge.
			# @returns [Boolean] Whether the checkpoint yielded to the scheduler.
			def checkpoint(cost = 1)
				if budget = self.current
					budget.checkpoint(cost)
				else
					false
				end
			end
			
			# Open a budget scope for the duration of the block. If another budget is already active, the new budget is nested within it.
			#
			# @yields {|budget| ...} The budget scope.
			# @returns [Object] The result of the block.
			def with(**options, &block)
				self.new(parent: self.current, **options).with(&block)
			end
		end
		
		# Create a new budget.
		#
		# @parameter operations [Integer | Nil] The maximum number of operations (checkpoint cost) before yielding.
		# @parameter duration [Numeric | Nil] The maximum monotonic time in seconds before yielding.
		# @parameter parent [Budget | Nil] The parent budget, which is charged together with this one.
		# @parameter clock [#call] A monotonic clock, used to measure the duration budget. Defaults to {Clock.now}.
		def initialize(operations: nil, duration: nil, parent: nil, clock: Clock.method(:now))
			if operations.nil? and duration.nil?
				raise ArgumentError, "Must specify at least one of operations: or duration:!"
			end
			
			if operations and operations < 1
				raise ArgumentError, "Operations must be at least 1!"
			end
			
			if duration and duration <= 0
				raise ArgumentError, "Duration must be positive!"
			end
			
			@operations = operations
			@duration = duration
			@parent = parent
			@clock = clock
			
			@operations_remaining = nil
			@started_at = nil
			
			@yields = 0
			
			reset!
		end
		
		# @returns [Budget | Nil] The parent budget, if any.
		attr :parent
		
		# @returns [Integer | Nil] The configured operation budget.
		attr :operations
		
		# @returns [Numeric | Nil] The configured time budget in seconds.
		attr :duration
		
		# @returns [Integer] The number of times this budget has caused a yield.
		attr :yields
		
		# @returns [Integer | Nil] The operations remaining before this budget is exhausted.
		attr :operations_remaining
		
		# Activate this budget for the duration of the block, making it the current budget for the executing fiber. The current budget is fiber-local and is not inherited by child tasks; pass the budget explicitly or call {#with} within the child task.
		#
		# @yields {|budget| ...}
		# @returns [Object] The result of the block.
		def with
			fiber = Fiber.current
			previous = fiber.async_budget
			fiber.async_budget = self
			
			begin
				yield self
			ensure
				fiber.async_budget = previous
			end
		end
		
		# Open a nested budget scope within this one. The nested budget inherits this budget's clock unless one is provided.
		#
		# @yields {|budget| ...} The nested budget.
		# @returns [Object] The result of the block.
		def nest(**options, &block)
			options[:clock] ||= @clock
			
			self.class.new(**options, parent: self).with(&block)
		end
		
		# @returns [Boolean] Whether the operation budget is exhausted.
		def depleted?
			!@operations_remaining.nil? and @operations_remaining <= 0
		end
		
		# @returns [Boolean] Whether the time budget has expired.
		def expired?
			!@duration.nil? and (@clock.call - @started_at) >= @duration
		end
		
		# @returns [Boolean] Whether either budget is exhausted.
		def exhausted?
			depleted? or expired?
		end
		
		# Mark a checkpoint, charging the cost to this budget and all parent budgets. If any budget in the chain is exhausted, yield to the scheduler and re-allot the exhausted budget and any budgets nested within it.
		#
		# @asynchronous May yield to the scheduler, allowing other tasks to run and pending cancellation to be delivered.
		# @parameter cost [Integer] The number of operations to charge.
		# @returns [Boolean] Whether the checkpoint yielded to the scheduler.
		def checkpoint(cost = 1)
			# Charge the cost to every budget in the chain, so nested scopes cannot bypass the limits of their parents:
			budget = self
			while budget
				budget.charge(cost)
				budget = budget.parent
			end
			
			# Find the outermost exhausted budget, if any:
			exhausted = nil
			budget = self
			while budget
				if budget.exhausted?
					exhausted = budget
				end
				budget = budget.parent
			end
			
			if exhausted
				exhausted.perform_yield
				
				# Re-allot the exhausted budget and everything nested within it. Budgets above the exhausted budget retain their consumed allotment:
				budget = self
				loop do
					budget.reset!
					break if budget.equal?(exhausted)
					budget = budget.parent
				end
				
				return true
			end
			
			return false
		end
		
		protected
		
		# Charge the cost of operations against this budget.
		def charge(cost)
			if @operations_remaining
				@operations_remaining -= cost
			end
		end
		
		# Re-allot this budget: restore the full operation count and restart the time budget.
		def reset!
			@operations_remaining = @operations
			@started_at = @clock.call
		end
		
		# Yield to the scheduler, if one is present, and count the yield. Without a scheduler, the budget is still re-allotted, but no yield occurs.
		def perform_yield
			@yields += 1
			
			Fiber.scheduler&.yield
		end
	end
end
