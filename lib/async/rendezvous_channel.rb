# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

module Async
	# A channel which performs a synchronous handshake between senders and receivers.
	#
	# Unlike {Queue} (and {LimitedQueue}, which still buffers up to a limited number of items), a rendezvous channel stores no buffered elements: a send operation only completes once a receive operation has actually taken the value. Both ends may be closed independently; closing wakes the corresponding waiters while preserving any committed deliveries.
	#
	# Pending operations progress through three distinct states:
	#
	# - *Queued*: the operation is waiting in the (first-in, first-out) queue for a counterpart.
	# - *Reserved*: a sender and a receiver have been paired, but the value has not yet been handed over.
	# - *Committed*: the receiver has taken the value and the delivery is final.
	#
	# Cancellation (e.g. stopping a task) is safe at every stage: a value is never delivered twice, and a sender whose value was not received never reports success.
	#
	# @public Since *Async v2.27*.
	class RendezvousChannel
		# An error raised when a send operation cannot complete because the channel is closed.
		class ClosedError < RuntimeError
		end
		
		# A pending send operation.
		# @private
		class Offer
			def initialize(value)
				@value = value
				
				# One of: :queued, :reserved, :committed or :cancelled.
				@state = :queued
				
				# The request this offer is reserved with, if any:
				@request = nil
				
				# Used to wake the waiting sender. A ::Thread::Queue is used so that a signal sent before the sender starts waiting is not lost:
				@ready = ::Thread::Queue.new
			end
			
			attr :value
			attr_accessor :state
			attr_accessor :request
			attr :ready
		end
		
		# A pending receive operation.
		# @private
		class Request
			def initialize
				# One of: :queued, :reserved, :committed or :cancelled.
				@state = :queued
				
				# The offer this request is reserved with, if any:
				@offer = nil
				
				# Whether the request is currently in the channel's receiver queue:
				@enqueued = false
				
				# The committed value, if any:
				@value = nil
				
				@ready = ::Thread::Queue.new
			end
			
			attr_accessor :state
			attr_accessor :offer
			attr_accessor :enqueued
			attr_accessor :value
			attr :ready
		end
		
		private_constant :Offer, :Request
		
		# Create a new rendezvous channel.
		def initialize
			# Offers waiting for a receiver, in first-in first-out order:
			@senders = []
			
			# Requests waiting for a sender, in first-in first-out order:
			@receivers = []
			
			@send_closed = false
			@receive_closed = false
			
			# Guards all mutable state. Never wait on an operation while holding this mutex:
			@mutex = ::Thread::Mutex.new
		end
		
		# @returns [Boolean] Whether the send side of the channel is closed.
		def send_closed?
			@send_closed
		end
		
		# @returns [Boolean] Whether the receive side of the channel is closed.
		def receive_closed?
			@receive_closed
		end
		
		# @returns [Boolean] Whether both sides of the channel are closed.
		def closed?
			@send_closed && @receive_closed
		end
		
		# @returns [Integer] The number of senders waiting for a receiver.
		def waiting_senders
			@mutex.synchronize{@senders.size}
		end
		
		# @returns [Integer] The number of receivers waiting for a sender.
		def waiting_receivers
			@mutex.synchronize{@receivers.size}
		end
		
		# Send a value to a receiver.
		#
		# Blocks until a receive operation has actually taken the value. Only then does the send succeed.
		#
		# @parameter value [Object] The value to send.
		# @returns [Object] The value, once it has been received.
		# @raises [ClosedError] If the channel is closed, or closed while waiting, before the value was received.
		def send(value)
			offer = Offer.new(value)
			
			begin
				@mutex.synchronize do
					if @send_closed
						raise ClosedError, "Cannot send to a closed channel!"
					end
					
					if @receive_closed
						raise ClosedError, "Cannot send a value: the receive side of the channel is closed!"
					end
					
					if (request = @receivers.shift)
						request.enqueued = false
						reserve(offer, request)
					else
						@senders.push(offer)
					end
				end
				
				# Wait until the offer is either committed or cancelled:
				offer.ready.pop
				
				if offer.state == :committed
					return value
				else
					raise ClosedError, "Send was cancelled before the value was received!"
				end
			ensure
				cancel_offer(offer)
			end
		end
		
		# Compatibility with {Queue#push}.
		def push(value)
			self.send(value)
		end
		
		# Compatibility with {Queue#<<}.
		def <<(value)
			self.send(value)
		end
		
		# Receive a value from a sender.
		#
		# Blocks until a sent value has been committed to this receive operation.
		#
		# @returns [Object, nil] The received value, or nil if the channel is closed (while waiting) before a value was committed.
		def receive
			request = Request.new
			
			begin
				loop do
					@mutex.synchronize do
						if request.state == :reserved
							# A sender paired with us while we were waiting; take the value and commit the delivery:
							commit(request)
						elsif request.state == :queued
							if (offer = @senders.shift)
								# A sender is already waiting; take the value and commit immediately:
								request.offer = offer
								offer.request = request
								commit(request)
							elsif @receive_closed || @send_closed
								# No value can ever arrive:
								request.state = :cancelled
							elsif !request.enqueued
								@receivers.push(request)
								request.enqueued = true
							end
						end
					end
					
					if request.state == :committed
						return request.value
					elsif request.state == :cancelled
						return nil
					end
					
					# Wait until the request is reserved, unpaired or cancelled:
					request.ready.pop
				end
			ensure
				cancel_request(request)
			end
		end
		
		# Compatibility with {Queue#pop}.
		def pop
			self.receive
		end
		
		# Compatibility with {Queue#dequeue}.
		def dequeue
			self.receive
		end
		
		# Close the send side of the channel.
		#
		# Subsequent sends raise {ClosedError}. Waiting senders are woken and raise {ClosedError}, as their values can never be received. Waiting receivers are woken and return nil, as no further values can arrive. Reserved pairings are allowed to commit.
		def close_send
			@mutex.synchronize do
				unless @send_closed
					@send_closed = true
					
					while (offer = @senders.shift)
						offer.state = :cancelled
						offer.ready.push(true)
					end
					
					while (request = @receivers.shift)
						request.enqueued = false
						request.state = :cancelled
						request.ready.push(true)
					end
				end
			end
			
			return self
		end
		
		# Close the receive side of the channel.
		#
		# Subsequent receives return nil. Waiting receivers are woken and return nil. Waiting senders are woken and raise {ClosedError}, as their values can never be received. Reserved pairings are allowed to commit.
		def close_receive
			@mutex.synchronize do
				unless @receive_closed
					@receive_closed = true
					
					while (request = @receivers.shift)
						request.enqueued = false
						request.state = :cancelled
						request.ready.push(true)
					end
					
					while (offer = @senders.shift)
						offer.state = :cancelled
						offer.ready.push(true)
					end
				end
			end
			
			return self
		end
		
		# Close both sides of the channel, waking all waiters.
		def close
			close_send
			close_receive
			
			return self
		end
		
		private
		
		# Reserve a pairing between an offer and a request. The request commits the delivery when the receiver resumes.
		#
		# Must be called with the mutex held.
		def reserve(offer, request)
			offer.state = :reserved
			offer.request = request
			
			request.state = :reserved
			request.offer = offer
			
			request.ready.push(true)
		end
		
		# Commit the delivery of a reserved request: the receiver takes the value and the sender is woken with success.
		#
		# Must be called with the mutex held.
		def commit(request)
			offer = request.offer
			
			request.offer = nil
			offer.request = nil
			
			request.value = offer.value
			
			offer.state = :committed
			request.state = :committed
			
			offer.ready.push(true)
		end
		
		# Cancel a pending send operation, e.g. because the sending task was stopped. If the offer was reserved, the pairing is dissolved and the receiver is woken so it can wait for another sender.
		def cancel_offer(offer)
			@mutex.synchronize do
				case offer.state
				when :queued
					offer.state = :cancelled
					@senders.delete(offer)
				when :reserved
					offer.state = :cancelled
					
					if (request = offer.request)
						offer.request = nil
						request.offer = nil
						
						# Return the receiver to the front of the queue to preserve pairing order:
						request.state = :queued
						request.enqueued = true
						@receivers.unshift(request)
						request.ready.push(true)
					end
				end
			end
		end
		
		# Cancel a pending receive operation, e.g. because the receiving task was stopped. If the request was reserved, the pairing is dissolved and the offer is paired with the next waiting receiver, or returned to the front of the queue.
		def cancel_request(request)
			@mutex.synchronize do
				case request.state
				when :queued
					request.state = :cancelled
					
					if request.enqueued
						request.enqueued = false
						@receivers.delete(request)
					end
				when :reserved
					request.state = :cancelled
					
					if (offer = request.offer)
						request.offer = nil
						offer.request = nil
						offer.state = :queued
						
						requeue_offer(offer)
					end
				end
			end
		end
		
		# Re-queue an offer whose reserved receiver went away, pairing it with the next waiting receiver if possible.
		#
		# Must be called with the mutex held.
		def requeue_offer(offer)
			if (request = @receivers.shift)
				request.enqueued = false
				reserve(offer, request)
			elsif @send_closed || @receive_closed
				# The offer can never be delivered:
				offer.state = :cancelled
				offer.ready.push(true)
			else
				# Return the offer to the front of the queue to preserve pairing order:
				@senders.unshift(offer)
			end
		end
	end
end
