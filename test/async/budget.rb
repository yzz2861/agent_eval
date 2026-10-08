# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async"
require "async/budget"
require "async/queue"

require "sus/fixtures/async"

describe Async::Budget do
	include Sus::Fixtures::Async::ReactorContext
	
	# Test instrumentation wrapping {Async::Scheduler#yield}, applied to the scheduler singleton class so it also counts yields inside the reactor nested by the reactor fixture.
	module YieldCounter
		attr_accessor :yield_count
		
		def yield(...)
			self.yield_count = (self.yield_count || 0) + 1
			super(...) # Explicit `super` with arguments disambiguates from the `yield` keyword.
		end
	end
	
	# Ensure the scheduler running the current test counts every cooperative yield.
	def instrument_scheduler!
		scheduler = Fiber.scheduler
		scheduler.singleton_class.prepend(YieldCounter) unless scheduler.singleton_class.ancestors.include?(YieldCounter)
		return scheduler
	end
	
	def yield_count
		instrument_scheduler!
		
		return Fiber.scheduler.yield_count || 0
	end
	
	# A manually advanced monotonic clock, so time-based budgets are deterministic in tests.
	class ManualClock
		attr_accessor :now
		
		def initialize(now = 0.0)
			@now = now
		end
		
		def advance(duration)
			@now += duration
		end
	end
	
	let(:clock) {ManualClock.new}
	
	with "without an active budget" do
		it "has no current budget" do
			expect(Async::Budget.current).to be_nil
		end
		
		it "checkpoint! is a no-op and never yields" do
			short_ran = false
			yields_before = yield_count
			timer = nil
			
			Async do |task|
				# A timer job that can only progress once the reactor gets control:
				timer = task.async do
					sleep(0.01)
					short_ran = true
				end
				
				100.times do
					task.checkpoint!
				end
				
				# Without a budget the hot loop never yielded, so the timer cannot have fired yet:
				expect(short_ran).to be == false
				expect(yield_count - yields_before).to be == 0
			end.wait
			
			# The timer runs once the enclosing task finishes and the reactor gets control:
			timer.wait
			expect(short_ran).to be == true
		end
		
		it "preserves the block result" do
			result = Async do |task|
				task.checkpoint!
				:ok
			end.wait
			
			expect(result).to be == :ok
		end
	end
	
	with "operation budget" do
		it "yields once the operation count is consumed" do
			yields_before = yield_count
			
			Async::Budget.with(operations: 3) do |budget|
				10.times do |index|
					budget.checkpoint!
					
					# On the 3rd, 6th and 9th operation the chain yielded and the quantum was reset to zero:
					expected = ((index + 1) % 3)
					expect(budget.consumed_operations).to be == expected
				end
			end
			
			expect(yield_count - yields_before).to be == 3
		end
		
		it "can account for multiple operations per checkpoint" do
			yields_before = yield_count
			
			Async::Budget.with(operations: 10) do
				Async::Budget.checkpoint!(6)
				expect(yield_count - yields_before).to be == 0
				
				Async::Budget.checkpoint!(4)
				expect(yield_count - yields_before).to be == 1
			end
		end
	end
	
	with "time budget" do
		it "yields once the elapsed quantum is reached, using the injected clock" do
			yields_before = yield_count
			
			Async::Budget.with(time: 0.01, clock: clock) do |budget|
				budget.checkpoint!
				expect(yield_count - yields_before).to be == 0
				
				clock.advance(0.005)
				budget.checkpoint!
				expect(yield_count - yields_before).to be == 0
				
				clock.advance(0.005)
				budget.checkpoint!
				expect(yield_count - yields_before).to be == 1
				
				# The time window restarts when the fiber resumes:
				expect(budget.window_started_at).to be == 0.01
				
				clock.advance(0.01)
				budget.checkpoint!
				expect(yield_count - yields_before).to be == 2
			end
		end
	end
	
	with "combined limits" do
		it "yields when either the operation count or the time quantum is reached" do
			yields_before = yield_count
			
			# The tight operation limit binds; the time limit never elapses:
			Async::Budget.with(operations: 3, time: 60, clock: clock) do
				6.times {Async::Budget.checkpoint!}
			end
			
			expect(yield_count - yields_before).to be == 2
			
			yields_before = yield_count
			
			# The clock advances past the time limit before the operation count is reached:
			Async::Budget.with(operations: 100, time: 0.5, clock: clock) do
				5.times do
					Async::Budget.checkpoint!
					clock.advance(0.5)
				end
			end
			
			expect(yield_count - yields_before).to be == 4
		end
	end
	
	with "nested scopes" do
		it "consumes child operations against every enclosing scope" do
			yields_before = yield_count
			
			Async::Budget.with(operations: 6) do |outer|
				Async::Budget.with(operations: 3) do |inner|
					expect(inner.parent).to be_equal(outer)
					
					3.times {inner.checkpoint!}
					
					# The tighter inner limit triggered the yield:
					expect(yield_count - yields_before).to be == 1
					# The parent saw the same operations, and reset together with the child:
					expect(outer.consumed_operations).to be == 0
					expect(inner.consumed_operations).to be == 0
					
					3.times {inner.checkpoint!}
					expect(yield_count - yields_before).to be == 2
				end
				
				# Counters were not reset merely by leaving the inner scope:
				expect(outer.consumed_operations).to be == 0
				outer.checkpoint!
				expect(outer.consumed_operations).to be == 1
			end
		end
		
		it "cannot bypass a tighter parent limit by resetting the child counter" do
			yields_before = yield_count
			
			Async::Budget.with(operations: 2) do |outer|
				Async::Budget.with(operations: 100) do |inner|
					2.times {inner.checkpoint!}
					
					# The parent limit of 2 forced the yield even though the child only reached 2 of 100:
					expect(yield_count - yields_before).to be == 1
					expect(outer.consumed_operations).to be == 0
					expect(inner.consumed_operations).to be == 0
				end
			end
		end
		
		it "restores the previous current scope when leaving a nested scope" do
			Async::Budget.with(operations: 5) do |outer|
				expect(Async::Budget.current).to be_equal(outer)
				
				Async::Budget.with(operations: 2) do |inner|
					expect(Async::Budget.current).to be_equal(inner)
				end
				
				expect(Async::Budget.current).to be_equal(outer)
			end
			
			expect(Async::Budget.current).to be_nil
		end
	end
	
	with "cancellation" do
		it "makes cancellation visible at the next checkpoint" do
			checkpoints = [0]
			error = nil
			
			task = Async do
				Async::Budget.with(operations: 5) do
					loop do
						Async::Budget.checkpoint!
						checkpoints[0] += 1
					end
				end
			rescue Async::Cancel => caught
				error = caught
				raise
			end
			
			# Let the worker run for a couple of quanta, then cancel it from the enclosing task:
			sleep(0.01)
			task.cancel
			task.wait
			
			expect(task).to be(:cancelled?)
			expect(error).to be_a(Async::Cancel)
			expect(checkpoints[0]).to be > 0
		end
		
		it "delivers a deferred cancellation queued while yielded" do
			ready = Async::Queue.new
			continuing = nil
			error = nil
			
			task = Async do
				Async::Budget.with(operations: 1) do
					ready.enqueue(:ready)
					Async::Budget.checkpoint!
					continuing = true
				end
			rescue Async::Cancel => caught
				error = caught
				raise
			end
			
			canceller = Async do
				ready.dequeue
				# The worker is parked at its first checkpoint; queue a deferred cancellation:
				task.cancel(true)
			end
			
			canceller.wait
			task.wait
			
			expect(task).to be(:cancelled?)
			expect(error).to be_a(Async::Cancel)
			expect(continuing).to be_nil
		end
		
		it "allows cleanup via defer_cancel to finish before cancellation" do
			ready = Async::Queue.new
			cleanup = []
			error = nil
			
			task = Async do |inner|
				Async::Budget.with(operations: 1) do
					inner.defer_cancel do
						3.times do |index|
							cleanup << index
							
							if index.zero?
								# Hand control to the canceller once cleanup has started:
								ready.enqueue(:ready)
							end
							
							Async::Budget.checkpoint!
						end
					end
				end
			rescue Async::Cancel => caught
				error = caught
				raise
			end
			
			canceller = Async do
				ready.dequeue
				task.cancel
			end
			
			canceller.wait
			task.wait
			
			expect(task).to be(:cancelled?)
			expect(error).to be_a(Async::Cancel)
			expect(cleanup).to be == [0, 1, 2]
		end
		
		it "cannot preempt a loop that never checks in" do
			ticks = [0]
			
			task = Async do
				# A tight loop without checkpoints runs to completion even once a cancellation is requested:
				1000.times do
					ticks[0] += 1
				end
			end
			
			task.cancel
			task.wait
			
			# The task completed its atomic loop; cooperativity is explicitly not preemption:
			expect(ticks[0]).to be == 1000
		end
	end
	
	with "fairness" do
		it "lets timers and short tasks progress from a hot in-memory loop" do
		short_progress = Array.new(3, 0)
		timer_done = false
		yields_before = yield_count
		
		records = 300
		processed = 0
		timer = nil
		
		Async do |task|
			# Short jobs that yield immediately and would otherwise be starved by the hot loop:
			3.times do |index|
				task.async do
					task.yield
					short_progress[index] += 1
				end
			end
			
			# A timer task that relies on the reactor's timer queue firing:
			timer = task.async do
				sleep(0.01)
				timer_done = true
			end
			
			# The hot loop: purely in-memory work with explicit checkpoints:
			Async::Budget.with(operations: 20) do
				records.times do
					processed += 1
					Async::Budget.checkpoint!
				end
			end
		end.wait
		
		# The hot loop must finish all of its work, and give the timer a turn to fire:
		timer.wait
		
		expect(processed).to be == records
		expect(short_progress).to be == [1, 1, 1]
		expect(timer_done).to be == true
		# Every 20 records the hot loop yielded; the short tasks add their own yields:
		expect(yield_count - yields_before).to be >= records / 20
		end
	end
	
	with "validation" do
		it "requires at least one limit" do
			expect do
			Async::Budget.new
		end.to raise_exception(ArgumentError, message: be =~ /at least one/)
			
			expect do
			Async::Budget.with{}
		end.to raise_exception(ArgumentError, message: be =~ /at least one/)
		end
	end
end
