# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "thread"

require_relative "cancel"
require_relative "task"

module Async
	# A thread-safe, unbuffered channel. A successful send means that a receiver has taken the value.
	#
	# @asynchronous This class is thread-safe.
	class RendezvousChannel
		# Raised when an operation is attempted on a closed end of the channel.
		class ClosedError < RuntimeError
		end
		
		# Raised when sending to a channel whose receive end is closed.
		class ReceiveClosedError < ClosedError
		end
		
		# Raised when operating on a channel whose send end is closed.
		class SendClosedError < ClosedError
		end
		
		def initialize
			@mutex = Thread::Mutex.new
			@senders = []
			@receivers = []
			
			@send_closed = false
			@receive_closed = false
			@pair_id = 0
		end
		
		# @returns [Boolean] Whether both ends of the channel are closed.
		def closed?
			send_closed? && receive_closed?
		end
		
		# @returns [Boolean] Whether the send end of the channel is closed.
		def send_closed?
			@mutex.synchronize{@send_closed}
		end
		
		# @returns [Boolean] Whether the receive end of the channel is closed.
		def receive_closed?
			@mutex.synchronize{@receive_closed}
		end
		
		# Close the send end. Waiting receivers return nil, while subsequent sends raise.
		def close_send
			@mutex.synchronize do
				return if @send_closed
				
				@send_closed = true
				
				@senders.each do |request|
					request.state = :closed
					request.gateway.push(:send_closed)
				end
				
				@receivers.each do |request|
					request.state = :closed
					request.gateway.push(:send_closed)
				end
				
				@senders.clear
				@receivers.clear
			end
		end
		
		# Close the receive end. Waiting operations raise, while committed deliveries are preserved.
		def close_receive
			@mutex.synchronize do
				return if @receive_closed
				
				@receive_closed = true
				
				@senders.each do |request|
					request.state = :closed
					request.gateway.push(:receive_closed)
				end
				
				@receivers.each do |request|
					request.state = :closed
					request.gateway.push(:receive_closed)
				end
				
				@senders.clear
				@receivers.clear
			end
		end
		
		# Close both ends of the channel. Reserved pairs are allowed to complete.
		def close
			close_send
			close_receive
		end
		
		# Rendezvous channels never retain a value.
		# @returns [Integer] Always zero.
		def size
			0
		end
		
		# @returns [Boolean] Always true.
		def empty?
			true
		end
		
		# @returns [Integer] The number of tasks waiting to send.
		def waiting_sender_count
			@mutex.synchronize{@senders.size}
		end
		
		# @returns [Integer] The number of tasks waiting to receive.
		def waiting_receiver_count
			@mutex.synchronize{@receivers.size}
		end
		
		# Send a value. This method only returns once a receiver has committed to taking the value.
		# @parameter value [Object] The value to send.
		# @returns [Object] The sent value.
		def send(value)
			request = Request.new(:sender, value)
			
			@mutex.synchronize do
				if @send_closed
					raise SendClosedError, "Cannot send to a closed channel!"
				elsif @receive_closed
					raise ReceiveClosedError, "Cannot send to a closed channel!"
				elsif receiver = @receivers.shift
					pair(request, receiver, false, true)
				else
					@senders << request
				end
			end
			
			wait_for_send(request)
		rescue Cancel
			cancel_request(request)
			raise unless request.state == :committed
			
			value
		end
		
		# Receive a value. Returns nil after the send end is closed and all deliveries are complete.
		# @returns [Object, nil] The received value, or nil when the send end is closed.
		def receive
			request = Request.new(:receiver)
			
			@mutex.synchronize do
				if @receive_closed
					raise ReceiveClosedError, "Cannot receive from a closed channel!"
				elsif @send_closed
					return nil
				elsif sender = @senders.shift
					pair(sender, request, true, false)
				else
					@receivers << request
				end
			end
			
			wait_for_receive(request)
		rescue Cancel
			cancel_request(request)
			raise unless request.state == :committed
			
			request.value
		end
		
		private
		
		class Request
			attr_reader :role, :fiber, :task, :gateway
			attr_accessor :value, :state, :partner, :pair_id
			
			def initialize(role, value = nil)
				@role = role
				@fiber = Fiber.current
				@task = Task.current?
				@value = value
				@gateway = Thread::Queue.new
				@state = :waiting
				@partner = nil
				@pair_id = nil
			end
		end
		
		private_constant :Request
		
		def bind(sender, receiver)
			@pair_id += 1
			
			sender.state = :reserved
			receiver.state = :reserved
			sender.partner = receiver
			receiver.partner = sender
			sender.pair_id = @pair_id
			receiver.pair_id = @pair_id
			
			@pair_id
		end
		
		def pair(sender, receiver, sender_queued, receiver_queued)
			pair_id = bind(sender, receiver)
			
			sender.gateway.push([:paired, pair_id]) if sender_queued
			
			if receiver_queued
				receiver.gateway.push([:paired, pair_id])
				receiver.gateway.push([:ready, pair_id]) unless sender_queued
			end
		end
		
		def repair(sender, receiver)
			pair_id = bind(sender, receiver)
			
			receiver.gateway.push([:paired, pair_id])
			receiver.gateway.push([:ready, pair_id])
		end
		
		def wait_for_send(request)
			loop do
				case request.gateway.pop
				in [:paired, pair_id]
					next unless request.state == :reserved && request.pair_id == pair_id
					
					request.partner.gateway.push([:ready, pair_id])
				in :committed
					return request.value
				in :cancelled
					# The request was already requeued or repaired under the mutex.
				in :send_closed
					raise SendClosedError, "Cannot send to a closed channel!"
				in :receive_closed
					raise ReceiveClosedError, "Cannot send to a closed channel!"
				end
			end
		end
		
		def wait_for_receive(request)
			loop do
				case request.gateway.pop
				in [:paired, pair_id]
					next unless request.state == :reserved && request.pair_id == pair_id
				in [:ready, pair_id]
					next unless request.state == :reserved && request.pair_id == pair_id
					
					if commit_receive(request)
						return request.value
					end
				in :cancelled
					# The request was already requeued or repaired under the mutex.
				in :send_closed
					return nil
				in :receive_closed
					raise ReceiveClosedError, "Cannot receive from a closed channel!"
				end
			end
		end
		
		def commit_receive(request)
			@mutex.synchronize do
				return false unless request.state == :reserved && request.partner
				
				request.value = request.partner.value
				request.state = :committed
				request.partner.state = :committed
				request.partner.gateway.push(:committed)
				
				true
			end
		end
		
		def cancel_request(request)
			@mutex.synchronize do
				return if request.state == :committed || request.state == :closed
				return unless request.state == :waiting || request.state == :reserved
				
				if request.state == :waiting
					queue = request.role == :sender ? @senders : @receivers
					queue.delete(request)
					request.state = :cancelled
					return
				end
				
				request.state = :cancelled
				request.pair_id = nil
				partner = request.partner
				request.partner = nil
				partner.partner = nil
				partner.pair_id = nil
				partner.state = :waiting
				request.gateway.push(:cancelled)
				
				if request.role == :sender
					if sender = @senders.shift
						repair(sender, partner)
					else
						@receivers.unshift(partner)
						partner.gateway.push(:cancelled)
					end
				else
					if receiver = @receivers.shift
						repair(partner, receiver)
					else
						@senders.unshift(partner)
						partner.gateway.push(:cancelled)
					end
				end
			end
		end
	end
end
