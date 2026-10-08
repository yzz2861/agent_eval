A cooperative work budget which prevents an in-memory hot loop from starving other tasks. The caller marks a checkpoint inside the loop, and the budget yields back to the reactor once an operation count or a monotonic time quantum is exhausted. After a yield, every active scope starts a fresh quantum.

Yielding is cooperative: a budget cannot preempt code which never calls a checkpoint. Cancellation requested while yielded becomes visible at the next checkpoint; cleanup that must run to completion can use {Async::Task#defer_cancel}.

Without an active budget, {Async::Task#checkpoint!} is a no-op, so it is safe to add checkpoints to shared libraries unconditionally.

## Example

~~~ ruby
require 'async'
require 'async/budget'

Async do
	# Process at most 100 records before yielding to timers and short tasks:
	Async::Budget.with(operations: 100) do
		records.each do |record|
			process(record)
			Async::Budget.checkpoint!
		end
	end
end
~~~

Budgets can also yield based on elapsed monotonic time, and the clock can be injected to make tests deterministic:

~~~ ruby
Async::Budget.with(time: 0.01) do
	huge_array.each do |item|
		compute(item)
		Async::Budget.checkpoint!
	end
end
~~~

Scopes can be nested. A child scope consumes against every enclosing scope, so it cannot reset its counter to bypass a tighter parent limit:

~~~ ruby
Async::Budget.with(operations: 1000) do
	Async::Budget.with(operations: 100) do
		# Yields at least every 100 operations; the outer limit is never bypassed.
	end
end
~~~
