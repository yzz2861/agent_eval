# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async"
require "async/budget"

describe Async::Budget do
	it "requires at least one budget" do
		expect{Async::Budget.new}.to raise_exception(ArgumentError, message: be =~ /operations: or duration:/)
	end
	
	it "validates the configured budgets" do
		expect{Async::Budget.new(operations: 0)}.to raise_exception(ArgumentError, message: be =~ /Operations must be at least 1/)
		expect{Async::Budget.new(duration: 0)}.to raise_exception(ArgumentError, message: be =~ /Duration must be positive/)
	end
	
	with "an operation budget" do
		it "yields after the configured number of operations" do
			budget = Async::Budget.new(operations: 3)
			
			results = 10.times.map{budget.checkpoint}
			
			expect(results).to be == [false, false, true, false, false, true, false, false, true, false]
			expect(budget.yields).to be == 3
		end
		
		it "supports charging multiple operations per checkpoint" do
			budget = Async::Budget.new(operations: 10)
			
			expect(budget.checkpoint(5)).to be == false
			expect(budget.operations_remaining).to be == 5
			
			expect(budget.checkpoint(5)).to be == true
			expect(budget.operations_remaining).to be == 10
			expect(budget.yields).to be == 1
		end
	end
	
	with "a time budget" do
		it "yields when the duration has expired" do
			time = 0.0
			clock = ->{time}
			budget = Async::Budget.new(duration: 1.0, clock: clock)
			
			expect(budget.checkpoint).to be == false
			
			time = 0.5
			expect(budget.checkpoint).to be == false
			
			time = 1.0
			expect(budget.checkpoint).to be == true
			
			# The budget is re-allotted after the yield:
			expect(budget).not.to be(:exhausted?)
			
			time = 1.5
			expect(budget.checkpoint).to be == false
			
			time = 2.0
			expect(budget.checkpoint).to be == true
			
			expect(budget.yields).to be == 2
		end
		
		it "yields when either budget is exhausted" do
			time = 0.0
			budget = Async::Budget.new(operations: 100, duration: 1.0, clock: ->{time})
			
			time = 1.0
			expect(budget.checkpoint).to be == true
			expect(budget.operations_remaining).to be == 100
		end
	end
	
	with "nested budgets" do
		it "charges checkpoints to parent budgets" do
			parent = Async::Budget.new(operations: 5)
			
			parent.nest(operations: 2) do |child|
				2.times{child.checkpoint}
				
				# The child yielded and was re-allotted, but the parent retains its consumed allotment:
				expect(child.yields).to be == 1
				expect(child.operations_remaining).to be == 2
				expect(parent.operations_remaining).to be == 3
				expect(parent.yields).to be == 0
				
				2.times{child.checkpoint}
				
				expect(child.yields).to be == 2
				expect(parent.operations_remaining).to be == 1
				
				# The next checkpoint exhausts the parent, re-allotting both scopes:
				expect(child.checkpoint).to be == true
				expect(parent.yields).to be == 1
				expect(parent.operations_remaining).to be == 5
				expect(child.operations_remaining).to be == 2
			end
		end
		
		it "cannot be bypassed by resetting a nested scope" do
			parent = Async::Budget.new(operations: 10)
			
			parent.with do
				# Each nested scope only performs 3 operations, well within its own
				# generous budget, but the parent budget is still enforced:
				4.times do
					parent.nest(operations: 1000) do |child|
						3.times{child.checkpoint}
					end
				end
			end
			
			expect(parent.yields).to be == 1
			expect(parent.operations_remaining).to be == 8
		end
		
		it "inherits the clock when nesting" do
			time = 0.0
			parent = Async::Budget.new(duration: 10.0, clock: ->{time})
			
			parent.nest(duration: 1.0) do |child|
				time = 1.0
				expect(child.checkpoint).to be == true
				expect(parent).not.to be(:exhausted?)
			end
		end
	end
	
	with ".with" do
		it "sets the current budget for the duration of the block" do
			expect(Async::Budget.current).to be_nil
			
			Async::Budget.with(operations: 2) do |budget|
				expect(Async::Budget.current).to be == budget
				
				expect(Async::Budget.checkpoint).to be == false
				expect(Async::Budget.checkpoint).to be == true
			end
			
			expect(Async::Budget.current).to be_nil
		end
		
		it "nests within the current budget" do
			Async::Budget.with(operations: 3) do |parent|
				Async::Budget.with(operations: 1) do |child|
					expect(child.parent).to be == parent
				end
			end
		end
		
		it "restores the current budget when the block raises" do
			Async::Budget.with(operations: 1) do |outer|
				expect do
					Async::Budget.with(operations: 1) do |inner|
						raise "Boom!"
					end
				end.to raise_exception(RuntimeError, message: be =~ /Boom!/)
				
				expect(Async::Budget.current).to be == outer
			end
		end
	end
	
	with "no active budget" do
		it "is a no-op" do
			expect(Async::Budget.current).to be_nil
			expect(Async::Budget.checkpoint).to be == false
		end
	end
	
	with "a hot loop" do
		it "allows timers and other tasks to make progress" do
			Async do |task|
				iterations = 0
				timer_progress = nil
				task_progress = nil
				
				timer = task.async do
					sleep 0.01
					timer_progress = iterations
				end
				
				short = task.async do |subtask|
					subtask.yield
					task_progress = iterations
				end
				
				budget = Async::Budget.new(operations: 1_000)
				
				budget.with do
					1_000_000.times do |i|
						iterations = i
						budget.checkpoint
					end
				end
				
				timer.wait
				short.wait
				
				# The budget yielded regularly throughout the loop:
				expect(budget.yields).to be > 0
				
				# The timer fired while the loop was still running:
				expect(timer_progress).not.to be_nil
				expect(timer_progress).to be < 999_999
				
				# The short task was resumed at the first checkpoint yield:
				expect(task_progress).not.to be_nil
				expect(task_progress).to be < 10_000
			end
		end
		
		it "does not yield without a budget, preserving existing behavior" do
			Async do |task|
				iterations = 0
				timer_progress = nil
				
				timer = task.async do
					sleep 0.01
					timer_progress = iterations
				end
				
				1_000_000.times do |i|
					iterations = i
					# With no active budget, checkpoints are a no-op:
					Async::Budget.checkpoint
				end
				
				# The timer could not fire while the loop was running:
				expect(timer_progress).to be_nil
				
				timer.wait
				expect(timer_progress).to be == 999_999
			end
		end
		
		it "delivers cancellation at checkpoints" do
			Async do |task|
				iterations = 0
				cleaned_up = false
				
				worker = task.async do |subtask|
					budget = Async::Budget.new(operations: 100)
					
					begin
						budget.with do
							loop do
								iterations += 1
								# Safety net: fail rather than hang if the budget never yields:
								raise "Budget failed to yield!" if iterations > 10_000_000
								budget.checkpoint
							end
						end
					ensure
						subtask.defer_cancel do
							cleaned_up = true
						end
					end
				end
				
				canceller = task.async do
					sleep 0.01
					worker.cancel
				end
				
				worker.wait
				canceller.wait
				
				expect(worker).to be(:cancelled?)
				expect(cleaned_up).to be == true
				expect(iterations).to be > 0
			end
		end
	end
end
