# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/rendezvous_channel"

require "sus/fixtures/async"

describe Async::RendezvousChannel do
	include Sus::Fixtures::Async::ReactorContext
	
	let(:channel) {subject.new}
	
	with "#send and #receive" do
		it "does not buffer values: send blocks until a receive takes the value" do
			sent = false
			
			sender = reactor.async do
				channel.send(:value)
				sent = true
			end
			
			# The value is not buffered; the sender is still waiting:
			expect(channel.waiting_senders).to be == 1
			expect(sent).to be == false
			expect(sender).not.to be(:finished?)
			
			expect(channel.receive).to be == :value
			
			sender.wait
			expect(sent).to be == true
		end
		
		it "pairs a waiting sender with a receiver (sender first)" do
			sender = reactor.async do
				channel.send(:value)
			end
			
			expect(channel.waiting_senders).to be == 1
			
			expect(channel.receive).to be == :value
			expect(sender.wait).to be == :value
		end
		
		it "pairs a waiting receiver with a sender (receiver first)" do
			received = nil
			
			receiver = reactor.async do
				received = channel.receive
			end
			
			expect(channel.waiting_receivers).to be == 1
			
			expect(channel.send(:value)).to be == :value
			expect(receiver.wait).to be == :value
			expect(received).to be == :value
		end
		
		it "pairs multiple senders and receivers in FIFO order" do
			senders = 3.times.map do |index|
				reactor.async do
					channel.send(index)
				end
			end
			
			expect(channel.waiting_senders).to be == 3
			
			received = 3.times.map{channel.receive}
			
			expect(received).to be == [0, 1, 2]
			3.times{|index| expect(senders[index].wait).to be == index}
		end
		
		it "pairs multiple receivers with senders in FIFO order" do
			received = []
			
			receivers = 3.times.map do
				reactor.async do
					received << channel.receive
				end
			end
			
			expect(channel.waiting_receivers).to be == 3
			
			3.times{|index| channel.send(index)}
			receivers.each(&:wait)
			
			expect(received).to be == [0, 1, 2]
		end
		
		it "supports queue-compatible aliases" do
			receiver = reactor.async do
				channel.pop
			end
			
			channel << :value
			expect(receiver.wait).to be == :value
			
			sender = reactor.async do
				channel.push(:other)
			end
			
			expect(channel.dequeue).to be == :other
			expect(sender.wait).to be == :other
		end
	end
	
	with "cancellation while queued" do
		it "removes a cancelled sender from the queue and never reports success" do
			result = :pending
			
			sender = reactor.async do
				result = channel.send(:value)
			end
			
			expect(channel.waiting_senders).to be == 1
			
			sender.cancel
			
			expect(channel.waiting_senders).to be == 0
			expect(result).to be == :pending
			
			# The channel remains usable:
			receiver = reactor.async{channel.receive}
			expect(channel.send(:other)).to be == :other
			expect(receiver.wait).to be == :other
		end
		
		it "does not deliver a cancelled sender's value to a later receiver" do
			first = reactor.async{channel.send(:cancelled)}
			second = reactor.async{channel.send(:kept)}
			
			expect(channel.waiting_senders).to be == 2
			
			first.cancel
			
			expect(channel.waiting_senders).to be == 1
			expect(channel.receive).to be == :kept
			expect(second.wait).to be == :kept
		end
		
		it "removes a cancelled receiver from the queue" do
			results = []
			
			first = reactor.async{results << channel.receive}
			second = reactor.async{results << channel.receive}
			
			expect(channel.waiting_receivers).to be == 2
			
			first.cancel
			
			expect(channel.waiting_receivers).to be == 1
			
			channel.send(:value)
			second.wait
			
			expect(results).to be == [:value]
		end
	end
	
	with "cancellation at the pairing boundary" do
		it "re-pairs the offer when the reserved receiver is cancelled before committing" do
			received = :none
			
			receiver = reactor.async do
				received = channel.receive
			end
			
			expect(channel.waiting_receivers).to be == 1
			
			sent = :pending
			sender = reactor.async do
				sent = channel.send(:value)
			end
			
			# The pairing is reserved, but the receiver has not committed the delivery yet:
			expect(channel.waiting_senders).to be == 0
			expect(channel.waiting_receivers).to be == 0
			expect(sent).to be == :pending
			
			# Cancel the receiver at the pairing boundary:
			receiver.cancel
			
			# The offer is re-queued, not lost, and the receiver took nothing:
			expect(channel.waiting_senders).to be == 1
			expect(received).to be == :none
			
			# The value is delivered exactly once, to the next receiver:
			expect(channel.receive).to be == :value
			expect(sender.wait).to be == :value
			expect(sent).to be == :value
		end
		
		it "re-pairs the request when the reserved sender is cancelled before committing" do
			receiver = reactor.async do
				channel.receive
			end
			
			expect(channel.waiting_receivers).to be == 1
			
			sent = :pending
			sender = reactor.async do
				sent = channel.send(:value)
			end
			
			# The pairing is reserved, but not committed:
			expect(channel.waiting_senders).to be == 0
			expect(channel.waiting_receivers).to be == 0
			
			# Cancel the sender at the pairing boundary:
			sender.cancel
			
			# The sender did not succeed, and the receiver is waiting again:
			expect(sent).to be == :pending
			expect(channel.waiting_receivers).to be == 1
			
			# The cancelled value is never delivered; the next send pairs with the waiting receiver:
			expect(channel.send(:other)).to be == :other
			expect(receiver.wait).to be == :other
		end
	end
	
	with "#close_send" do
		it "wakes waiting senders with ClosedError" do
			errors = []
			
			senders = 2.times.map do |index|
				reactor.async do
					begin
						channel.send(index)
					rescue Async::RendezvousChannel::ClosedError => error
						errors << error
					end
				end
			end
			
			expect(channel.waiting_senders).to be == 2
			
			channel.close_send
			senders.each(&:wait)
			
			expect(errors.size).to be == 2
			expect(channel.send_closed?).to be == true
			expect(channel.receive_closed?).to be == false
		end
		
		it "prevents subsequent sends and returns nil to receivers" do
			channel.close_send
			
			expect do
				channel.send(:value)
			end.to raise_exception(Async::RendezvousChannel::ClosedError)
			
			# No value can ever arrive:
			expect(channel.receive).to be_nil
		end
		
		it "wakes waiting receivers with nil" do
			results = []
			
			receivers = 2.times.map do
				reactor.async{results << channel.receive}
			end
			
			expect(channel.waiting_receivers).to be == 2
			
			channel.close_send
			receivers.each(&:wait)
			
			expect(results).to be == [nil, nil]
		end
		
		it "preserves committed results" do
			receiver = reactor.async{channel.receive}
			sender = reactor.async{channel.send(:value)}
			
			# The pairing is reserved; closing the send side does not prevent the commit:
			channel.close_send
			
			expect(sender.wait).to be == :value
			expect(receiver.wait).to be == :value
		end
	end
	
	with "#close_receive" do
		it "wakes waiting receivers with nil" do
			results = []
			
			receivers = 2.times.map do
				reactor.async{results << channel.receive}
			end
			
			expect(channel.waiting_receivers).to be == 2
			
			channel.close_receive
			receivers.each(&:wait)
			
			expect(results).to be == [nil, nil]
			expect(channel.receive_closed?).to be == true
			expect(channel.send_closed?).to be == false
		end
		
		it "fails waiting senders as their values can never be received" do
			errors = []
			
			senders = 2.times.map do |index|
				reactor.async do
					begin
						channel.send(index)
					rescue Async::RendezvousChannel::ClosedError => error
						errors << error
					end
				end
			end
			
			expect(channel.waiting_senders).to be == 2
			
			channel.close_receive
			senders.each(&:wait)
			
			expect(errors.size).to be == 2
		end
		
		it "prevents subsequent sends and receives" do
			channel.close_receive
			
			expect(channel.receive).to be_nil
			
			expect do
				channel.send(:value)
			end.to raise_exception(Async::RendezvousChannel::ClosedError)
		end
	end
	
	with "#close" do
		it "closes both sides and wakes all waiters" do
			send_errors = []
			
			senders = 2.times.map do |index|
				reactor.async do
					begin
						channel.send(index)
					rescue Async::RendezvousChannel::ClosedError => error
						send_errors << error
					end
				end
			end
			
			expect(channel.waiting_senders).to be == 2
			
			channel.close
			senders.each(&:wait)
			
			expect(send_errors.size).to be == 2
			expect(channel).to be(:closed?)
			
			expect(channel.receive).to be_nil
			expect do
				channel.send(:value)
			end.to raise_exception(Async::RendezvousChannel::ClosedError)
		end
		
		it "wakes waiting receivers with nil" do
			results = []
			
			receivers = 2.times.map do
				reactor.async{results << channel.receive}
			end
			
			expect(channel.waiting_receivers).to be == 2
			
			channel.close
			receivers.each(&:wait)
			
			expect(results).to be == [nil, nil]
			expect(channel).to be(:closed?)
		end
		
		it "is idempotent" do
			channel.close
			channel.close_send
			channel.close_receive
			
			expect(channel).to be(:closed?)
		end
	end
end
