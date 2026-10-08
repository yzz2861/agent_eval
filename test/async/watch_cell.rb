# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "sus/fixtures/async"

require "async/watch_cell"
require "async/queue"

describe Async::WatchCell do
	include Sus::Fixtures::Async::ReactorContext
	
	let(:cell) {subject.new("initial")}
	
	it "has an initial value and version" do
		expect(cell.value).to be == "initial"
		expect(cell.version).to be == 0
		expect(cell.snapshot).to be == ["initial", 0]
		expect(cell).not.to be(:closed?)
	end
	
	with "#update" do
		it "updates the value and advances the version" do
			result = cell.update do |value|
				expect(value).to be == "initial"
				"updated"
			end
			
			expect(result).to be == "updated"
			expect(cell.snapshot).to be == ["updated", 1]
		end
		
		it "does not change the value or version when the block raises" do
			expect do
				cell.update{raise "Boom!"}
			end.to raise_exception(RuntimeError, message: be == "Boom!")
			
			expect(cell.snapshot).to be == ["initial", 0]
		end
		
		it "serializes concurrent updates even when the block yields" do
			cell = subject.new(0)
			
			tasks = 10.times.map do
				reactor.async do
					cell.update do |value|
						# Force a yield in the middle of the read-modify-write:
						sleep(0.001)
						value + 1
					end
				end
			end
			
			tasks.each(&:wait)
			
			expect(cell.snapshot).to be == [10, 10]
		end
		
		it "advances the version even when the value is unchanged" do
			cell.value = "initial"
			
			expect(cell.snapshot).to be == ["initial", 1]
		end
		
		with "deduplicate: true" do
			let(:cell) {subject.new("initial", deduplicate: true)}
			
			it "does not advance the version when the value is unchanged" do
				cell.value = "initial"
				expect(cell.snapshot).to be == ["initial", 0]
				
				cell.value = "updated"
				expect(cell.snapshot).to be == ["updated", 1]
			end
		end
	end
	
	with "#changed_since" do
		it "returns immediately when a newer version is already available" do
			cell.value = "updated"
			
			expect(cell.changed_since(0)).to be == ["updated", 1]
		end
		
		it "waits for a newer version" do
			subscriber = reactor.async do
				cell.changed_since(0)
			end
			
			expect(cell.waiting_count).to be == 1
			
			cell.value = "updated"
			
			expect(subscriber.wait).to be == ["updated", 1]
		end
		
		it "does not miss updates that occur between reading the version and waiting" do
			ready = Async::Queue.new
			proceed = Async::Queue.new
			observed = nil
			
			subscriber = reactor.async do
				# Read the current version...
				version = cell.version
				
				# ...then allow an update to occur before we start waiting:
				ready.push(true)
				proceed.pop
				
				# The intervening update must not be missed:
				observed = cell.changed_since(version)
			end
			
			# The subscriber has read the version, but is not waiting yet:
			ready.pop
			cell.value = "updated"
			proceed.push(true)
			
			subscriber.wait
			expect(observed).to be == ["updated", 1]
		end
		
		it "coalesces consecutive updates into the latest value" do
			observed = nil
			
			subscriber = reactor.async do
				observed = cell.changed_since(0)
			end
			
			expect(cell.waiting_count).to be == 1
			
			10.times do |i|
				cell.value = "update-#{i}"
			end
			
			subscriber.wait
			
			# Only the latest value is observed, exactly once:
			expect(observed).to be == ["update-9", 10]
			
			# There is no backlog of pending notifications:
			expect(cell.waiting_count).to be == 0
		end
		
		it "supports multiple slow subscribers with independent versions" do
			observed = []
			
			subscribers = 3.times.map do |i|
				reactor.async do
					observed[i] = cell.changed_since(i)
				end
			end
			
			expect(cell.waiting_count).to be == 3
			
			5.times {|i| cell.value = "update-#{i}"}
			
			subscribers.each(&:wait)
			
			expect(observed).to be == [
				["update-4", 5],
				["update-4", 5],
				["update-4", 5],
			]
		end
		
		it "allows slow subscribers to catch up to the latest value in a loop" do
			seen = []
			
			subscriber = reactor.async do
				version = 0
				
				begin
					loop do
						value, version = cell.changed_since(version)
						seen << value
					end
				rescue Async::WatchCell::ClosedError
					# The subscriber observed the final value before the cell was closed.
				end
			end
			
			expect(cell.waiting_count).to be == 1
			
			10.times {|i| cell.value = i}
			cell.close
			
			subscriber.wait
			
			# Intermediate values were coalesced, and the final value was observed:
			expect(seen).to be == [9]
		end
	end
	
	with "#close" do
		it "wakes up waiting subscribers" do
			subscriber = reactor.async do
				cell.changed_since(0)
			end
			
			expect(cell.waiting_count).to be == 1
			
			cell.close
			
			expect do
				subscriber.wait
			end.to raise_exception(Async::WatchCell::ClosedError)
			
			expect(cell).to be(:closed?)
		end
		
		it "allows subscribers to observe the final value before closed" do
			cell.value = "updated"
			cell.close
			
			# The last unobserved version is still available:
			expect(cell.changed_since(0)).to be == ["updated", 1]
			
			# Once observed, the closed state is reported:
			expect do
				cell.changed_since(1)
			end.to raise_exception(Async::WatchCell::ClosedError)
		end
		
		it "cannot be updated after close" do
			cell.close
			
			expect do
				cell.update {"updated"}
			end.to raise_exception(Async::WatchCell::ClosedError)
			
			expect do
				cell.value = "updated"
			end.to raise_exception(Async::WatchCell::ClosedError)
		end
		
		it "can be closed multiple times" do
			cell.close
			
			expect do
				cell.close
			end.not.to raise_exception
		end
	end
	
	with "space usage" do
		it "does not accumulate state across updates" do
			# Many updates with no waiters:
			1000.times {|i| cell.value = i}
			
			expect(cell.waiting_count).to be == 0
			expect(cell.version).to be == 1000
			
			# A subscriber starting from an old version observes only the latest value:
			expect(cell.changed_since(0)).to be == [999, 1000]
			
			# No backlog of pending notifications remains, so a subscriber of the
			# current version blocks until the next update:
			subscriber = reactor.async do
				cell.changed_since(1000)
			end
			
			expect(cell.waiting_count).to be == 1
			
			cell.value = 1001
			expect(subscriber.wait).to be == [1001, 1001]
		end
		
		it "only retains state proportional to the number of waiters" do
			finished = false
			
			subscribers = 3.times.map do
				reactor.async do
					version = 0
					
					until finished
						_value, version = cell.changed_since(version)
					end
				end
			end
			
			# The number of waiters remains constant regardless of how many
			# updates are published:
			10.times do |i|
				expect(cell.waiting_count).to be == 3
				cell.value = i
				reactor.yield
			end
			
			expect(cell.waiting_count).to be == 3
			
			finished = true
			cell.value = :done
			subscribers.each(&:wait)
		end
	end
end
