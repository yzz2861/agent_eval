# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "sus/fixtures/async"
require "async/watch_cell"

describe Async::WatchCell do
	include Sus::Fixtures::Async::ReactorContext
	
	let(:cell) {subject.new(:initial)}
	
	it "stores a value and a monotonic version" do
		expect(cell.value).to be == :initial
		expect(cell.version).to be == 0
		expect(cell.get).to be == [:initial, 0]
		
		changed, value, version = cell.update(:second)
		expect(changed).to be == true
		expect(value).to be == :second
		expect(version).to be == 1
		expect(cell.get).to be == [:second, 1]
	end
	
	it "coalesces updates made before a subscriber waits" do
		cell.update(:second)
		cell.update(:third)
		
		expect(cell.changed_since(0)).to be == [:third, 2]
	end
	
	it "does not miss an update while entering the wait" do
		task = reactor.async do
			cell.changed_since(0)
		end
		
		reactor.yield
		expect(cell.waiting_count).to be == 1
		cell.update(:updated)
		
		expect(task.wait).to be == [:updated, 1]
	end
	
	with "#update" do
		it "atomically applies a block to the current value" do
			changed, value, version = cell.update do |current|
				expect(current).to be == :initial
				:updated
			end
			
			expect(changed).to be == true
			expect(value).to be == :updated
			expect(version).to be == 1
		end
		
		it "leaves value and version unchanged when the block raises" do
			expect do
				cell.update do
					raise RuntimeError, "boom"
				end
			end.to raise_exception(RuntimeError, message: be == "boom")
			
			expect(cell.get).to be == [:initial, 0]
			expect(cell).not.to be(:closed?)
		end
		
		it "does not advance for an equal value by default" do
			expect(cell.update(:initial)).to be == [false, :initial, 0]
		end
		
		it "can advance for an equal value per update" do
			expect(cell.update(:initial, force: true)).to be == [true, :initial, 1]
		end
		
		it "defaults to advancing for equal values when configured" do
			cell = subject.new(:initial, force: true)
			expect(cell.update(:initial)).to be == [true, :initial, 1]
		end
		
		it "can keep the default version for one equal update" do
			cell = subject.new(:initial, force: true)
			expect(cell.update(:initial, force: false)).to be == [false, :initial, 0]
			expect(cell.update(:initial)).to be == [true, :initial, 1]
		end
		
		it "raises after close" do
			cell.close
			
			expect do
				cell.update(:updated)
			end.to raise_exception(subject::ClosedError)
		end
	end
	
	with "#changed_since" do
		it "waits for and returns a newer value and version" do
			task = reactor.async do
				cell.changed_since(0)
			end
			
			reactor.yield
			cell.update(:updated)
			
			expect(task.wait).to be == [:updated, 1]
		end
		
		it "returns immediately when already newer" do
			cell.update(:updated)
			
			task = reactor.async do
				cell.changed_since(0)
			end
			
			expect(task.wait).to be == [:updated, 1]
			expect(cell.waiting_count).to be == 0
		end
		
		it "coalesces updates while a subscriber is waiting" do
			task = reactor.async do
				cell.changed_since(0)
			end
			
			reactor.yield
			cell.update(:a)
			cell.update(:b)
			cell.update(:c)
			
			expect(task.wait).to be == [:c, 3]
		end
		
		it "does not enqueue updates for a slow subscriber" do
			cell.update(1)
			first, first_version = cell.changed_since(0)
			
			100.times do |index|
				cell.update(index + 2)
			end
			
			expect(first).to be == 1
			expect(first_version).to be == 1
			expect(cell.changed_since(first_version)).to be == [101, 101]
			expect(cell.waiting_count).to be == 0
		end
		
		it "keeps state proportional to waiting subscribers rather than updates" do
			ready = 3.times.map {::Thread::Queue.new}
			gate = ::Thread::Queue.new
			done = 3.times.map {::Thread::Queue.new}
			results = Array.new(3) {[]}
			
			subscribers = 3.times.map do |index|
				reactor.async do
					results[index] << cell.changed_since(0)
					ready[index].push(true)
					gate.pop
					value, observed_version = cell.changed_since(1)
					results[index] << [value, observed_version]
					begin
						cell.changed_since(observed_version)
					rescue subject::ClosedError
						results[index] << :closed
					end
					done[index].push(true)
				end
			end
			
			reactor.yield
			expect(cell.waiting_count).to be == 3
			
			cell.update(:a)
			ready.each(&:pop)
			3.times {gate.push(true)}
			reactor.yield
			
			expect(cell.waiting_count).to be == 3
			500.times do |update_index|
				cell.update(update_index)
			end
			expect(cell.waiting_count).to be == 3
			expect(cell.instance_variable_get(:@waiting).size).to be == 3
			
			cell.update(:b)
			cell.close
			done.each(&:pop)
			
			expect(cell.waiting_count).to be == 0
			results.each do |result|
				expect(result).to be == [[:a, 1], [:b, 502], :closed]
			end
		end
		
		it "raises immediately after close when there is no unobserved value" do
			cell.close
			
			expect do
				cell.changed_since(0)
			end.to raise_exception(subject::ClosedError)
		end
		
		it "delivers the final value once before the closed state" do
			cell.update(:final)
			cell.close
			
			expect(cell.changed_since(0)).to be == [:final, 1]
			expect do
				cell.changed_since(cell.version)
			end.to raise_exception(subject::ClosedError)
		end
		
		it "releases waiting subscribers with a final value and then closed status" do
			results = []
			
			task = reactor.async do
				results << cell.changed_since(0)
				begin
					cell.changed_since(1)
				rescue subject::ClosedError
					results << :closed
				end
			end
			
			reactor.yield
			cell.update(:final)
			cell.close
			task.wait
			
			expect(results).to be == [[:final, 1], :closed]
			expect(cell.waiting_count).to be == 0
		end
		
		it "removes a waiting subscriber when the task is cancelled" do
			task = reactor.async do
				cell.changed_since(0)
			end
			
			reactor.yield
			expect(cell.waiting_count).to be == 1
			
			task.stop
			task.wait
			expect(cell.waiting_count).to be == 0
			
			expect do
				cell.update(:still_works)
			end.not.to raise_exception
		end
		
		it "releases thread waiters after coalesced cross-thread updates" do
			cell = subject.new(0)
			finished = ::Thread::Queue.new
			
			subscribers = 4.times.map do
				::Thread.new do
					value, observed_version = cell.changed_since(0)
					begin
						cell.changed_since(observed_version)
					rescue subject::ClosedError
						finished.push([value, :closed])
					end
				end
			end
			
			sleep(0.001) until cell.waiting_count == 4
			
			producer = ::Thread.new do
				1000.times do |index|
					cell.update(index)
				end
				cell.close
			end
			
			results = 4.times.map {finished.pop}
			producer.join
			subscribers.each(&:join)
			
			expect(results).to be == Array.new(4) {[999, :closed]}
			expect(cell.waiting_count).to be == 0
		end
	end
end
