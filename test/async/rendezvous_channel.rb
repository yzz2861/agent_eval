# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async"
require "async/rendezvous_channel"

require "sus/fixtures/async"

class CancelAtReservationChannel < Async::RendezvousChannel
	private
	
	def pair(sender, receiver, sender_queued, receiver_queued)
		super
		
		task = sender_queued ? receiver.task : sender.task
		Fiber.scheduler.resume(task.fiber, Async::Cancel, cause: nil)
	end
end

private_constant :CancelAtReservationChannel

describe Async::RendezvousChannel do
	include Sus::Fixtures::Async::ReactorContext
	
	let(:channel) {subject.new}
	
	it "does not retain a value" do
		expect(channel.size).to be == 0
		expect(channel).to be(:empty?)
	end
	
	it "completes a handshake when the sender arrives first" do
		sender = reactor.async do
			result = channel.send(:item)
			[:sent, result]
		end
		
		expect(channel.waiting_sender_count).to be == 1
		
		receiver = reactor.async do
			result = channel.receive
			[:received, result]
		end
		
		expect(receiver.wait).to be == [:received, :item]
		expect(sender.wait).to be == [:sent, :item]
		expect(channel.size).to be == 0
	end
	
	it "completes a handshake when the receiver arrives first" do
		receiver = reactor.async do
			result = channel.receive
			[:received, result]
		end
		
		expect(channel.waiting_receiver_count).to be == 1
		
		sender = reactor.async do
			result = channel.send(:item)
			[:sent, result]
		end
		
		expect(receiver.wait).to be == [:received, :item]
		expect(sender.wait).to be == [:sent, :item]
		expect(channel.size).to be == 0
	end
	
	it "pairs senders and receivers in FIFO order" do
		sent = []
		senders = 3.times.map do |index|
			reactor.async do
				channel.send(index)
				sent << index
			end
		end
		
		results = 3.times.map do
			reactor.async{channel.receive}.wait
		end
		
		senders.each(&:wait)
		
		expect(results).to be == [0, 1, 2]
		expect(sent).to be == [0, 1, 2]
		expect(channel.waiting_sender_count).to be == 0
		expect(channel.waiting_receiver_count).to be == 0
	end
	
	it "pairs receivers in FIFO order" do
		receivers = 3.times.map do
			reactor.async{channel.receive}
		end
		
		senders = 3.times.map do |index|
			reactor.async do
				channel.send(index)
				index
			end
		end
		
		results = receivers.map(&:wait)
		senders.each(&:wait)
		
		expect(results).to be == [0, 1, 2]
		expect(channel.waiting_sender_count).to be == 0
		expect(channel.waiting_receiver_count).to be == 0
	end
	
	it "removes a queued sender without delivering its value" do
		first = reactor.async do
			begin
				channel.send(:first)
				[:sent, :first]
			rescue Async::Cancel
				[:cancelled, :first]
			end
		end
		
		second = reactor.async do
			begin
				channel.send(:second)
				[:sent, :second]
			rescue Async::Cancel
				[:cancelled, :second]
			end
		end
		
		expect(channel.waiting_sender_count).to be == 2
		
		first.cancel
		expect(first.wait).to be == [:cancelled, :first]
		expect(channel.waiting_sender_count).to be == 1
		
		received = reactor.async{channel.receive}.wait
		
		expect(received).to be == :second
		expect(second.wait).to be == [:sent, :second]
		expect(channel.waiting_sender_count).to be == 0
	end
	
	it "removes a queued receiver and pairs the next receiver" do
		first = reactor.async do
			begin
				[:received, channel.receive]
			rescue Async::Cancel
				[:cancelled, :first]
			end
		end
		
		second = reactor.async do
			begin
				[:received, channel.receive]
			rescue Async::Cancel
				[:cancelled, :second]
			end
		end
		
		expect(channel.waiting_receiver_count).to be == 2
		
		first.cancel
		expect(first.wait).to be == [:cancelled, :first]
		expect(channel.waiting_receiver_count).to be == 1
		
		sender = reactor.async do
			channel.send(:item)
			:sent
		end
		
		expect(second.wait).to be == [:received, :item]
		expect(sender.wait).to be == :sent
	end
	
	with "a reserved pair" do
		it "cancels a later sender before delivery and re-pairs the receiver" do
			channel = CancelAtReservationChannel.new
			
			receiver = reactor.async do
				begin
					[:received, channel.receive]
				rescue Async::Cancel
					[:cancelled, :receiver]
				end
			end
			
			later_sender = reactor.async do
				begin
					channel.send(:later)
					[:sent, :later]
				rescue Async::Cancel
					[:cancelled, :later]
				end
			end
			
			later_sender.cancel
			expect(later_sender.wait).to be == [:cancelled, :later]
			expect(channel.waiting_sender_count).to be == 0
			expect(channel.waiting_receiver_count).to be == 1
			
			next_sender = reactor.async do
				channel.send(:next)
				[:sent, :next]
			end
			
			expect(receiver.wait).to be == [:received, :next]
			expect(next_sender.wait).to be == [:sent, :next]
		end
		
		it "cancels a later receiver before commit and re-pairs the sender" do
			channel = CancelAtReservationChannel.new
			
			sender = reactor.async do
				begin
					channel.send(:item)
					[:sent, :item]
				rescue Async::Cancel
					[:cancelled, :sender]
				end
			end
			
			later_receiver = reactor.async do
				begin
					[:received, channel.receive]
				rescue Async::Cancel
					[:cancelled, :later]
				end
			end
			
			later_receiver.cancel
			expect(later_receiver.wait).to be == [:cancelled, :later]
			expect(channel.waiting_sender_count).to be == 1
			expect(channel.waiting_receiver_count).to be == 0
			
			next_receiver = reactor.async do
				[:received, channel.receive]
			end
			
			expect(next_receiver.wait).to be == [:received, :item]
			expect(sender.wait).to be == [:sent, :item]
		end
		
		it "keeps a committed delivery if cancellation arrives afterward" do
			sender = reactor.async do
			begin
				channel.send(:item)
				:sent
			rescue Async::Cancel
				:cancelled
			end
		end
		
		receiver = reactor.async do
			begin
				[:received, channel.receive]
			rescue Async::Cancel
				:cancelled
			end
		end
		
		expect(receiver.wait).to be == [:received, :item]
		expect(sender.wait).to be == :sent
		
		sender.cancel
		receiver.cancel
		expect(sender).to be(:completed?)
		expect(receiver).to be(:completed?)
		expect(channel.size).to be == 0
		end
	end
	
	with "#close_send" do
		it "wakes waiting receivers with nil" do
			receiver = reactor.async do
				[:received, channel.receive]
			end
			
			channel.close_send
			
			expect(receiver.wait).to be == [:received, nil]
			expect(channel).to be(:send_closed?)
		end
		
		it "does not allow further sends" do
			channel.close_send
			
			expect do
				channel.send(:item)
			end.to raise_exception(Async::RendezvousChannel::SendClosedError)
		end
	end
	
	with "#close_receive" do
		it "wakes waiting senders with an error" do
			sender = reactor.async do
				begin
					channel.send(:item)
					:sent
				rescue Async::RendezvousChannel::ClosedError
					:closed
				end
			end
			
			channel.close_receive
			
			expect(sender.wait).to be == :closed
			expect(channel).to be(:receive_closed?)
		end
		
		it "does not allow further receives" do
			channel.close_receive
			
			expect do
				channel.receive
			end.to raise_exception(Async::RendezvousChannel::ReceiveClosedError)
		end
	end
	
	with "#close" do
		it "wakes a waiting sender when both ends close" do
			sender = reactor.async do
				begin
					channel.send(:item)
					:sent
				rescue subject::ClosedError
					:closed
				end
			end
			
			channel.close
			
			expect(channel).to be(:closed?)
			expect(sender.wait).to be == :closed
		end
		
		it "returns nil to a waiting receiver when both ends close" do
			receiver = reactor.async do
				begin
					[:received, channel.receive]
				rescue subject::ClosedError
					:closed
				end
			end
			
			channel.close
			
			expect(channel).to be(:closed?)
			expect(receiver.wait).to be == [:received, nil]
		end
		
		it "can close both ends concurrently" do
			closed_send = reactor.async{channel.close_send; :send_closed}
			closed_receive = reactor.async{channel.close_receive; :receive_closed}
			
			expect(closed_send.wait).to be == :send_closed
			expect(closed_receive.wait).to be == :receive_closed
			expect(channel).to be(:closed?)
		end
		
		it "reports explicit errors after both ends close" do
			channel.close
			
			expect{channel.send(:item)}.to raise_exception(subject::ClosedError)
			expect{channel.receive}.to raise_exception(subject::ClosedError)
		end
		
		it "does not retain a value after both ends close" do
			channel.close
			
			expect(channel).to be(:closed?)
			expect(channel.size).to be == 0
		end
	end
end
