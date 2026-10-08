# frozen_string_literal: true

require_relative "condition"
require_relative "error"

module Async
	# A fiber-safe mailbox which supports selective message receiving.
	#
	# Unlike {Queue}, which is strictly first-in-first-out, a mailbox allows
	# receivers to wait for a message matching a specific predicate using
	# {receive_if}. Non-matching messages remain buffered in their original
	# order for other receivers. This is useful for protocols where several
	# independent conversations share one channel, e.g. waiting for a reply
	# with a specific `request_id` while leaving unrelated messages in place.
	#
	# When several receivers are waiting, they are woken in the order they
	# started waiting (first-come, first-served), and each one, in turn, takes
	# the first buffered message matching its predicate. Thus, if multiple
	# receivers could accept the same message, the one that has been waiting
	# the longest receives it.
	#
	# Predicates are always evaluated in the fiber of the calling receiver,
	# without holding any internal lock. If a predicate raises an exception,
	# it propagates to that receiver only; the message is not removed and
	# other receivers are unaffected. Predicates should not mutate the
	# mailbox.
	#
	# This implementation is fiber-cooperative and is not safe to share
	# across multiple threads; use it within a single reactor.
	#
	# @public Since *Async v2.47*.
	class Mailbox
		# An error raised when trying to push a message to a closed mailbox.
		class ClosedError < RuntimeError
		end
		
		# Create a new mailbox.
		#
		# @parameter limit [Integer | Nil] The maximum number of messages that can be buffered. If the mailbox is full, {push} blocks until a message is received, providing back-pressure when messages are not being consumed. If nil, the mailbox is unbounded.
		def initialize(limit: nil)
			@messages = []
			@limit = limit
			@closed = false
			
			# Signaled when a message is pushed or the mailbox is closed:
			@available = Condition.new
			
			# Signaled when a message is received or the mailbox is closed:
			@space = Condition.new
		end
		
		# @attribute [Integer | Nil] The maximum number of messages that can be buffered.
		attr :limit
		
		# @returns [Boolean] Whether the mailbox is closed.
		def closed?
			@closed
		end
		
		# Close the mailbox. Waiting receivers return `nil` unless a buffered message already matches their predicate. Buffered messages can still be received after closing. Subsequent calls to {push} will raise {ClosedError}, and blocked producers will be woken with {ClosedError}.
		def close
			return if @closed
			
			@closed = true
			@available.signal
			@space.signal
			
			return nil
		end
		
		# @returns [Integer] The number of buffered messages.
		def size
			@messages.size
		end
		
		# @returns [Boolean] Whether the mailbox is empty.
		def empty?
			@messages.empty?
		end
		
		# @returns [Integer] The number of tasks waiting for a message.
		def waiting_count
			@available.waiting_count
		end
		
		# @returns [Boolean] Whether trying to push a message would block.
		def limited?
			!@limit.nil? && !@closed && @messages.size >= @limit
		end
		
		# Push a message into the mailbox.
		#
		# If the mailbox has a limit and is full, blocks until a message is received or the mailbox is closed.
		#
		# @parameter message [Object] The message to buffer.
		# @returns [Mailbox] Returns self for chaining.
		# @raises [ClosedError] If the mailbox is closed.
		def push(message)
			if @limit
				while @messages.size >= @limit
					raise ClosedError, "Cannot push messages to a closed mailbox!" if @closed
					
					@space.wait
				end
			end
			
			raise ClosedError, "Cannot push messages to a closed mailbox!" if @closed
			
			@messages << message
			@available.signal
			
			return self
		end
		
		# Compatibility with {Queue#<<}.
		def <<(message)
			self.push(message)
		end
		
		# Receive the first message, in arrival order, for which the predicate returns true. All other messages remain buffered, preserving their relative order.
		#
		# If no buffered message matches, waits until a matching message arrives, the timeout expires, or the mailbox is closed.
		#
		# @parameter timeout [Numeric | Nil] The maximum time to wait for a matching message. If nil, waits indefinitely. If 0, only checks buffered messages without blocking.
		# @yields {|message| ...} The predicate used to select a message.
		# @returns [Object | Nil] The first matching message, or nil if the timeout expired or the mailbox was closed before a matching message arrived.
		def receive_if(timeout: nil, &predicate)
			raise ArgumentError, "Predicate block is required!" unless predicate
			
			# Fast path: check buffered messages without blocking:
			if index = find_index(&predicate)
				return take(index)
			end
			
			return nil if @closed || timeout == 0
			
			if timeout
				begin
					Task.current.with_timeout(timeout) do
						return wait_for(&predicate)
					end
				rescue TimeoutError
					return nil
				end
			else
				return wait_for(&predicate)
			end
		end
		
		# Receive the oldest buffered message, waiting if the mailbox is empty.
		#
		# @parameter timeout [Numeric | Nil] The maximum time to wait for a message.
		# @returns [Object | Nil] The oldest message, or nil if the timeout expired or the mailbox was closed while empty.
		def receive(timeout: nil)
			receive_if(timeout: timeout) {true}
		end
		
		private
		
		# Find the index of the first buffered message matching the predicate. Called without holding any lock; exceptions propagate to the caller.
		def find_index(&predicate)
			@messages.index do |message|
				predicate.call(message)
			end
		end
		
		# Remove and return the message at the given index, waking up blocked producers.
		def take(index)
			message = @messages.delete_at(index)
			@space.signal
			
			return message
		end
		
		# Wait until a matching message is pushed or the mailbox is closed.
		def wait_for(&predicate)
			while true
				@available.wait
				
				if index = find_index(&predicate)
					return take(index)
				end
				
				return nil if @closed
			end
		end
	end
end
