# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "thread"

require_relative "deadline"

module Async
	# A thread-safe, bounded mailbox supporting selective receive.
	#
	# Messages are retained in arrival order until a receive completes. When
	# multiple receivers are waiting, each message is offered to waiters in their
	# registration order. The selected message is removed without moving the
	# messages before or after it.
	#
	# Predicates are always invoked without holding the mailbox mutex.
	class Mailbox
		# Raised when trying to enqueue a message to a closed mailbox.
		class ClosedError < RuntimeError
		end
		
		Waiter = Struct.new(:fiber, :deadline, :condition, :state, :value, :exception) do
			def alive?
				return self.fiber&.alive?
			end
			
			def expired?
				return false if self.deadline == Deadline::Zero
				return !self.deadline.nil? && self.deadline.expired?
			end
			
			def signal
				self.condition.signal
			end
		end
		
		private_constant :Waiter
		
		# Create a new mailbox.
		#
		# @parameter capacity [Integer, nil] Maximum number of messages retained while no receiver selects them. `nil` means unlimited.
		def initialize(capacity = nil)
			if capacity && capacity < 1
				raise ArgumentError, "Capacity must be positive!"
			end
			
			@capacity = capacity
			
			@messages = []
			@waiters = []
			@predicates = {}
			@closed = false
			@matching = nil
			
			@mutex = Mutex.new
			@space = ConditionVariable.new
		end
		
		# @returns [Integer, nil] The maximum number of retained messages.
		attr :capacity
		
		# @returns [Integer] The number of messages currently retained.
		def size
			@mutex.synchronize{@messages.size}
		end
		
		# @returns [Boolean] Whether the mailbox currently contains no messages.
		def empty?
			@mutex.synchronize{@messages.empty?}
		end
		
		# @returns [Boolean] Whether a push would block because the mailbox is full.
		def limited?
			@mutex.synchronize{!@capacity.nil? && @messages.size >= @capacity}
		end
		
		# @returns [Boolean] Whether the mailbox is closed.
		def closed?
			@mutex.synchronize{@closed}
		end
		
		# @returns [Integer] The number of receivers currently waiting.
		def waiting_count
			@mutex.synchronize{@waiters.size}
		end
		
		# Add a message to the mailbox.
		#
		# A bounded mailbox blocks when it is full until a receiver removes a
		# message or the mailbox is closed, giving producers backpressure for
		# messages that remain unmatched indefinitely.
		def push(message)
			@mutex.lock
			
			loop do
				raise_closed if @closed
				break unless @matching
				@space.wait(@mutex)
			end
			
			unless @capacity.nil? || @messages.size < @capacity
				wait_for_space
			end
			
			@messages << message
			pump!
			return message
		ensure
			finish_lock!
		end
		
		def <<(message)
			return self.push(message)
		end
		
		def enqueue(*messages)
			@mutex.lock
			
			loop do
				raise_closed if @closed
				break unless @matching
				@space.wait(@mutex)
			end
			
			messages.each do |message|
				loop do
					raise_closed if @closed
					break unless @matching
					@space.wait(@mutex)
				end
				
				wait_for_space unless @capacity.nil?
				
				@messages << message
			end
			
			pump!
			return messages
		ensure
			finish_lock!
		end
		
		# Receive the first arrival-order message accepted by the predicate.
		#
		# Existing waiters are served before a newly arriving receiver. For each
		# message, waiters are considered in registration order, so equal
		# eligibility follows FIFO fairness.
		#
		# @parameter timeout [Numeric, nil] Maximum time to wait. Nil waits indefinitely; zero or less performs one non-blocking scan.
		# @returns [Object, nil] The selected message, or nil on timeout or closed drain.
		def receive_if(timeout: nil, &predicate)
			deadline = Deadline.start(timeout)
			
			@mutex.lock
			cleanup_waiters!
			
			if @matching
				waiter = add_waiter(deadline, predicate)
				return wait_for_match(waiter, deadline)
			end
			
			waiter = add_waiter(deadline, predicate)
			result = pump!
			return result unless result.nil?
			return nil if deadline == Deadline::Zero
			
			return wait_for_match(waiter, deadline)
		ensure
			finish_lock!
		end
		
		# Receive the next available message.
		def receive(timeout: nil)
			receive_if(timeout: timeout){true}
		end
		
		alias dequeue receive
		alias pop receive
		
		# Close the mailbox. Existing messages can still be drained; after the drain, receivers return nil.
		def close
			@mutex.lock
			
			while @matching
				@space.wait(@mutex)
			end
			
			@closed = true
			result = pump!
			return result
		ensure
			finish_lock!
		end
		
		private
		
		def raise_closed
			raise ClosedError, "Cannot enqueue messages to a closed mailbox!"
		end
		
		def wait_for_space
			while @capacity && @messages.size >= @capacity
				@space.wait(@mutex)
				raise_closed if @closed
			end
		end
		
		def add_waiter(deadline, predicate)
			waiter = Waiter.new(Fiber.current, deadline, ConditionVariable.new, nil, nil, nil)
			@waiters << waiter
			@predicates[waiter] = predicate
			return waiter
		end
		
		def cleanup_waiters!
			@waiters.dup.each do |waiter|
				next if waiter.alive? && !waiter.expired?
				
				remove_waiter(waiter)
			end
		end
		
		def remove_waiter(waiter)
			@waiters.delete(waiter)
			@predicates.delete(waiter)
		end
		
		def next_pair(rejected)
			@messages.each_with_index do |message, message_index|
				rejected_waiters = rejected[message_index]
				
				@waiters.each do |waiter|
					next unless waiter.alive? && !waiter.expired?
					next if rejected_waiters&.include?(waiter)
					
					return [message, message_index, waiter]
				end
			end
			
			return nil
		end
		
		# Called with the mutex held. The mutex is released while user predicates
		# execute and reacquired before state is inspected or changed.
		def pump!
			@matching = true
			result = nil
			rejected = []
			waiters_to_signal = []
			
			while true
				cleanup_waiters!
				pair = next_pair(rejected)
				
				unless pair
					finish_waiters_if_closed!(waiters_to_signal)
					@matching = nil
					
					@mutex.unlock
					@space.broadcast
					waiters_to_signal.each(&:signal)
					@mutex.lock
					return result
				end
				
				message, message_index, waiter = pair
				predicate = @predicates.fetch(waiter)
				outcome = invoke_predicate(predicate, message)
				
				unless waiter.alive?
					remove_waiter(waiter)
					next
				end
				
				if outcome.is_a?(Exception)
					if waiter.fiber == Fiber.current
						remove_waiter(waiter)
						
						@mutex.unlock
						@space.broadcast
						waiters_to_signal.each(&:signal)
						raise outcome
					end
					
					waiter.state = :error
					waiter.exception = outcome
					remove_waiter(waiter)
					waiters_to_signal << waiter
					next
				end
				
				if waiter.expired?
					remove_waiter(waiter)
					next
				end
				
				unless outcome
					(rejected[message_index] ||= []) << waiter
					next
				end
				
				@messages.delete_at(message_index)
				rejected.delete_at(message_index)
				
				waiter.state = :message
				waiter.value = message
				remove_waiter(waiter)
				waiters_to_signal << waiter
				result = message if waiter.fiber == Fiber.current
			end
		ensure
			@matching = false
			
			if $!
				@mutex.unlock if @mutex.owned?
				@space.broadcast
				waiters_to_signal.each(&:signal)
			end
		end
		
		def invoke_predicate(predicate, message)
			@mutex.unlock
			begin
				return predicate.call(message)
			rescue StandardError => exception
				return exception
			ensure
				@mutex.lock
			end
		end
		
		def finish_waiters_if_closed!(waiters_to_signal)
			return unless @closed
			
			@waiters.dup.each do |waiter|
				waiter.state = :closed
				waiter.value = nil
				remove_waiter(waiter)
				waiters_to_signal << waiter
			end
		end
		
		def wait_for_match(waiter, deadline)
			begin
				until waiter.state
					if deadline
						remaining = deadline.remaining
						return nil if remaining <= 0
						waiter.condition.wait(@mutex, remaining)
					else
						waiter.condition.wait(@mutex)
					end
				end
				
				if waiter.state == :error
					raise waiter.exception
				else
					return waiter.value
				end
			ensure
				remove_waiter(waiter)
			end
		end
		
		def finish_lock!
			return unless @mutex.owned?
			
			@mutex.unlock
		rescue ThreadError
		end
	end
end
