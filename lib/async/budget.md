A work budget limits how much work a task can perform before yielding back to the scheduler, so that long-running, CPU-bound loops do not starve other tasks and timers.

Budgets are optional and cooperative: they only take effect when the caller marks checkpoints, e.g. once per record processed. A checkpoint is charged against an operation count and/or a monotonic time limit, and when either is exhausted, the current fiber yields to the scheduler and the budget is re-allotted.

## Example

~~~ ruby
require 'async'
require 'async/budget'

Async do
	Async::Budget.with(operations: 100, duration: 0.01) do |budget|
		records.each do |record|
			process(record)
			budget.checkpoint
		end
	end
end
~~~

## Nesting

Budgets can be nested. Checkpoints in a nested (child) budget are also charged to all enclosing (parent) budgets, so a child scope cannot bypass the limits of its parent by resetting its own counters. When any budget in the chain is exhausted, the fiber yields, and the exhausted budget along with any budgets nested within it are re-allotted. Budgets above the exhausted one are not reset.

~~~ ruby
Async::Budget.with(operations: 10_000) do |budget|
	batches.each do |batch|
		budget.nest(operations: 100) do |nested|
			batch.each do |record|
				process(record)
				nested.checkpoint
			end
		end
	end
end
~~~

## Instrumenting Libraries

Libraries can sprinkle checkpoints that only activate when the caller has configured a budget. Without an active budget, {Async::Budget.checkpoint} is a no-op:

~~~ ruby
def process_all(records)
	records.each do |record|
		process(record)
		Async::Budget.checkpoint
	end
end
~~~

## Cancellation

Cancellation is delivered at checkpoints: yielding to the scheduler allows a pending {Async::Cancel} to be raised in the current task. Use {Async::Task#defer_cancel} to protect cleanup code that must run to completion. Budgets cannot preempt code that never calls {Async::Budget#checkpoint}.
