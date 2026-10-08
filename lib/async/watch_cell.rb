# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "thread"

module Async
	# A thread-safe cell that broadcasts only the most recently observed value.
	#
	# Updates while a subscriber is not waiting are coalesced. Each subscriber tracks the version it has already observed and passes it to changed_since.
	class WatchCell
		# Raised when a closed cell is updated, or when a subscriber has observed the final version.
		class ClosedError < RuntimeError
			def initialize(message = "watch cell is closed")
				super
			end
		end
		
		# Create a new watch cell.
		#
		# @parameter value [Object] The initial value.
		# @parameter version [Integer] The initial version.
		# @parameter force [Boolean] Whether assigning an equal value advances the version.
		def initialize(value = nil, version: 0, force: false)
			@value = value
			@version = version
			@force = force
			@mutex = Mutex.new
			@waiting = {}
			@closed = false
		end
		
		# @returns [Object] The current value.
		def value
			@mutex.synchronize {@value}
		end
		
		# @returns [Integer] The current monotonically increasing version.
		def version
			@mutex.synchronize {@version}
		end
		
		# @returns [Array(Object, Integer)] The current value and version as one atomic snapshot.
		def get
			@mutex.synchronize {return @value, @version}
		end
		
		# @returns [Boolean] Whether the cell is closed.
		def closed?
			@mutex.synchronize {@closed}
		end
		
		# @returns [Integer] The number of fibers currently waiting for a newer version.
		def waiting_count
			@mutex.synchronize {@waiting.size}
		end
		
		# Atomically update the cell.
		#
		# The block receives the current value. If it raises, neither the value nor the version is changed.
		#
		# @parameter new_value [Object] An optional replacement value; ignored when a block is given.
		# @parameter force [Boolean, nil] Whether an equal value should advance the version. nil uses the cell default.
		# @returns [Array(Boolean, Object, Integer)] Whether the version advanced, the resulting value, and the resulting version.
		def update(new_value = nil, force: nil, &block)
			@mutex.synchronize do
				raise ClosedError if @closed
				
				new_value = block.call(@value) if block
				advance = force
				advance = @force if advance.nil?
				
				unless advance || new_value != @value
					return false, @value, @version
				end
				
				@value = new_value
				@version += 1
				signal
				return true, @value, @version
			end
		end
		
		# Wait for a value newer than the subscriber's observed version.
		#
		# The current version is checked and the wait is registered atomically, so an update between those operations cannot be missed.
		#
		# If the cell closed with a newer value, that value is returned once with its version. The following call raises ClosedError.
		#
		# @parameter observed_version [Integer] The version last observed by the subscriber.
		# @returns [Array(Object, Integer)] The current value and version when the version is newer than the observed version.
		def changed_since(observed_version)
			queue = ::Thread::Queue.new
			
			@mutex.synchronize do
				if @version > observed_version
					return @value, @version
				elsif @closed
					raise ClosedError
				end
				@waiting[queue] = true
			end
			
			begin
				queue.pop
			ensure
				@mutex.synchronize {@waiting.delete(queue)}
			end
			
			@mutex.synchronize do
				if @version > observed_version
					return @value, @version
				elsif @closed
					raise ClosedError
				else
					raise "Unexpected wakeup without a version change!"
				end
			end
		end
		
		# Close the cell and release all waiting fibers.
		#
		# Fibers with an unobserved final version receive that value before seeing the closed state.
		def close
			@mutex.synchronize do
				return if @closed
				@closed = true
				signal
			end
		end
		
		private
		
		def signal
			@waiting.each_key(&:close)
		end
	end
end
