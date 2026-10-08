# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "condition"
require_relative "semaphore"

module Async
	# A cell which holds a value along with a monotonically increasing version.
	#
	# Subscribers track their own observed version and use {changed_since} to wait for a newer value. Consecutive updates are coalesced: subscribers always observe the latest value rather than every intermediate change. This makes it suitable for propagating configuration updates, where only the most recent value matters.
	#
	# The cell does not buffer changes: memory usage is proportional to the number of tasks currently waiting, and does not grow with the number of updates.
	#
	# @public Since *Async v2.47*.
	class WatchCell
		# An error raised when operating on a closed cell.
		class ClosedError < RuntimeError
		end
		
		# Create a new watch cell.
		#
		# @parameter value [Object] The initial value.
		# @parameter deduplicate [Boolean] If true, updates which do not change the value (according to `==`) do not advance the version. If false, every update advances the version, even if the value is unchanged.
		def initialize(value = nil, deduplicate: false)
			@value = value
			@version = 0
			@deduplicate = deduplicate
			@closed = false
			
			@condition = Condition.new
			@update_lock = Semaphore.new(1)
		end
		
		# The current value.
		attr :value
		
		# The current version, incremented on every (effective) update.
		attr :version
		
		# @returns [Array] The current value and version, as a consistent snapshot.
		def snapshot
			return @value, @version
		end
		
		# @returns [Boolean] Whether the cell is closed.
		def closed?
			@closed
		end
		
		# @returns [Integer] The number of tasks currently waiting for a change.
		def waiting_count
			@condition.waiting_count
		end
		
		# Atomically update the value using a block.
		#
		# The block is called with the current value and its result becomes the new value. Updates are serialized, so the block may yield (e.g. perform asynchronous operations) without interleaving with other updates. If the block raises an exception, neither the value nor the version is changed.
		#
		# @yields {|value| ...} The current value.
		# @returns [Object] The new value.
		# @raises [ClosedError] If the cell is closed.
		def update
			@update_lock.acquire do
				if @closed
					raise ClosedError, "Cannot update a closed watch cell!"
				end
				
				value = yield(@value)
				
				unless @deduplicate and value == @value
					@value = value
					@version += 1
					
					@condition.signal
				end
				
				value
			end
		end
		
		# Set the value directly.
		#
		# @parameter value [Object] The new value.
		def value=(value)
			self.update{value}
		end
		
		# Wait until the cell holds a version newer than the given one, and return the latest value and version.
		#
		# The check and the wait are performed atomically with respect to updates: an update which occurs after reading the version, but before waiting, is never missed. Intermediate updates may be coalesced, so only the latest value is observed.
		#
		# If the cell is closed, the last unobserved value is still returned; only once the caller has observed the final version does this method raise {ClosedError}. Waiting tasks are therefore never blocked forever.
		#
		# @parameter version [Integer] The version last observed by the caller.
		# @returns [Array] The latest value and its version.
		# @raises [ClosedError] If the cell is closed and no newer version is available.
		def changed_since(version)
			while @version <= version
				if @closed
					raise ClosedError, "The watch cell is closed!"
				end
				
				@condition.wait
			end
			
			return @value, @version
		end
		
		# Close the cell. Waiting tasks are woken up: they observe the final value if they have not already, and subsequent calls to {changed_since} raise {ClosedError}.
		def close
			@closed = true
			@condition.signal
			
			return nil
		end
	end
end
