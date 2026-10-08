# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/mailbox"
require "sus/fixtures/async"

describe Async::Mailbox do
	include Sus::Fixtures::Async::ReactorContext
	
	let(:mailbox) {subject.new}
	
	def message(tag, id = tag)
		{tag: tag, id: id}
	end
	
	with "#receive_if" do
		it "selects a middle message without changing the relative order of the rest" do
			first_a = message(:a, :a1)
			first_b = message(:b, :b1)
			first_c = message(:c)
			second_b = message(:b, :b2)
			second_a = message(:a, :a2)
			
			mailbox.enqueue(first_a, first_b, first_c, second_b, second_a)
			
			expect(mailbox.receive_if(timeout: 0){|item| item[:tag] == :b}).to be == first_b
			expect(mailbox.receive).to be == first_a
			expect(mailbox.receive_if(timeout: 0){|item| item[:tag] == :c}).to be == first_c
			expect(mailbox.receive).to be == second_b
			expect(mailbox.receive).to be == second_a
			expect(mailbox).to be(:empty?)
		end
		
		it "fairly gives one message to the earliest eligible waiter" do
			first = reactor.async do
				mailbox.receive_if{|item| item[:tag] == :x}
			end
			sleep(0.001)
			expect(mailbox.waiting_count).to be == 1
			
			second = reactor.async do
				mailbox.receive_if{|item| item[:tag] == :x}
			end
			sleep(0.001)
			expect(mailbox.waiting_count).to be == 2
			
			first_message = message(:x, 1)
			mailbox.push(first_message)
			
			expect(first.wait).to be == first_message
			expect(mailbox.waiting_count).to be == 1
			expect(mailbox).to be(:empty?)
			
			second_message = message(:x, 2)
			mailbox.push(second_message)
			expect(second.wait).to be == second_message
		end
		
		it "does not invoke the predicate while holding the mailbox mutex" do
			mailbox.push(message(:x))
			mutex = mailbox.instance_variable_get(:@mutex)
			
			mailbox.receive_if(timeout: 0) do
				expect(mutex).not.to be(:locked?)
				expect(mutex).not.to be(:owned?)
				true
			end
		end
		
		it "keeps the message when the current receiver's predicate raises" do
			item = message(:x)
			mailbox.push(item)
			
			expect do
				mailbox.receive_if(timeout: 0) {raise "predicate failed"}
			end.to raise_exception(RuntimeError, message: be == "predicate failed")
			
			expect(mailbox.size).to be == 1
			expect(mailbox.receive).to be == item
		end
		
		it "only fails the waiter whose predicate raises" do
			item = message(:x)
			failure = nil
			
			reactor.async do
				begin
					mailbox.receive_if {raise "predicate failed"}
				rescue RuntimeError => error
					failure = error
				end
			end
			succeeding = reactor.async do
				mailbox.receive_if{|message| message[:tag] == :x}
			end
			sleep(0.001)
			
			mailbox.push(item)
			
			expect(succeeding.wait).to be == item
			expect(failure).to be_a(RuntimeError)
			expect(failure.message).to be == "predicate failed"
		end
		
		it "returns nil when timeout expires without removing any message" do
			item = message(:x)
			mailbox.push(item)
			
			expect(mailbox.receive_if(timeout: 0.01){|message| message[:tag] == :y}).to be_nil
			expect(mailbox.size).to be == 1
			expect(mailbox.receive).to be == item
		end
		
		it "supports cancelling a waiting receiver" do
			item = message(:x)
			waiting = reactor.async do
				mailbox.receive_if{|message| message[:tag] == :x}
			end
			sleep(0.001)
			
			waiting.stop
			expect(waiting.wait).to be_nil
			expect(waiting).to be(:cancelled?)
			expect(mailbox.waiting_count).to be == 0
			
			mailbox.push(item)
			expect(mailbox.receive).to be == item
		end
	end
	
	with "capacity" do
		it "blocks producers while unmatched messages fill the mailbox" do
			bounded = subject.new(2)
			first = message(:a)
			second = message(:a)
			third = message(:a)
			
			bounded.push(first)
			bounded.push(second)
			expect(bounded).to be(:limited?)
			
			producer = reactor.async do
				bounded.push(third)
			end
			sleep(0.01)
			expect(bounded.size).to be == 2
			expect(producer).to be(:running?)
			
			consumer = reactor.async do
				bounded.receive_if{|item| item[:id] == first[:id]}
			end
			
			expect(consumer.wait).to be == first
			expect(producer.wait).to be == third
			expect(bounded.size).to be == 2
			expect(bounded.receive).to be == second
			expect(bounded.receive).to be == third
		end
	end
	
	with "#close" do
		it "wakes waiters and drains retained messages before returning nil" do
			item = message(:x)
			waiting = reactor.async do
				mailbox.receive
			end
			sleep(0.001)
			
			mailbox.close
			expect(waiting.wait).to be_nil
			
			closed = subject.new
			closed.push(item)
			closed.close
			
			expect(closed.receive_if(timeout: 0){true}).to be == item
			expect(closed.receive).to be_nil
			expect{closed.push(message(:y))}.to raise_exception(subject::ClosedError)
		end
	end
end
