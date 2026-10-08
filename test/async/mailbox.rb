# frozen_string_literal: true

require "async/mailbox"

require "sus/fixtures/async"

describe Async::Mailbox do
	include Sus::Fixtures::Async::ReactorContext
	
	let(:mailbox) {subject.new}
	
	with "#push" do
		it "buffers messages in arrival order" do
			mailbox.push(:a)
			mailbox << :b
			
			expect(mailbox.size).to be == 2
			expect(mailbox.receive).to be == :a
			expect(mailbox.receive).to be == :b
			expect(mailbox).to be(:empty?)
		end
		
		it "raises an error when pushing to a closed mailbox" do
			mailbox.close
			
			expect do
				mailbox.push(:message)
			end.to raise_exception(Async::Mailbox::ClosedError)
		end
	end
	
	with "#receive_if" do
		it "removes only the first matching message and preserves the relative order of the rest" do
			mailbox.push({label: "a"})
			mailbox.push({label: "b"})
			mailbox.push({label: "c"})
			mailbox.push({label: "b"})
			mailbox.push({label: "d"})
			
			expect(mailbox.receive_if{|message| message[:label] == "b"}).to be == {label: "b"}
			expect(mailbox.size).to be == 4
			
			expect(mailbox.receive).to be == {label: "a"}
			expect(mailbox.receive).to be == {label: "c"}
			expect(mailbox.receive).to be == {label: "b"}
			expect(mailbox.receive).to be == {label: "d"}
			expect(mailbox).to be(:empty?)
		end
		
		it "requires a predicate" do
			expect do
				mailbox.receive_if
			end.to raise_exception(ArgumentError)
		end
		
		it "waits until a matching message arrives, skipping non-matching messages" do
			child = reactor.async do
				mailbox.receive_if{|message| message[:kind] == :wanted}
			end
			
			expect(mailbox.waiting_count).to be == 1
			
			mailbox.push({kind: :unwanted, id: 1})
			mailbox.push({kind: :unwanted, id: 2})
			mailbox.push({kind: :wanted, id: 3})
			
			expect(child.wait).to be == {kind: :wanted, id: 3}
			
			# Non-matching messages remain buffered in order:
			expect(mailbox.receive).to be == {kind: :unwanted, id: 1}
			expect(mailbox.receive).to be == {kind: :unwanted, id: 2}
			expect(mailbox).to be(:empty?)
		end
		
		it "allocates messages to waiting receivers in first-come-first-served order" do
			received = []
			
			first = reactor.async do
				received << [:first, mailbox.receive_if{|message| message[:kind] == :hit}]
			end
			
			second = reactor.async do
				received << [:second, mailbox.receive_if{|message| message[:kind] == :hit}]
			end
			
			expect(mailbox.waiting_count).to be == 2
			
			# Both receivers match this message; the longest-waiting one gets it:
			mailbox.push({kind: :hit, id: 1})
			
			first.wait
			expect(received).to be == [[:first, {kind: :hit, id: 1}]]
			expect(mailbox.waiting_count).to be == 1
			
			mailbox.push({kind: :hit, id: 2})
			
			second.wait
			expect(received).to be == [
				[:first, {kind: :hit, id: 1}],
				[:second, {kind: :hit, id: 2}],
			]
			expect(mailbox).to be(:empty?)
		end
		
		it "propagates predicate errors to the caller without removing the message" do
			mailbox.push(:boom)
			
			expect do
				mailbox.receive_if{|message| raise "predicate failed!"}
			end.to raise_exception(RuntimeError, message: be == "predicate failed!")
			
			expect(mailbox.size).to be == 1
			expect(mailbox.receive).to be == :boom
		end
		
		it "only affects the receiver whose predicate fails" do
			failing = reactor.async do
				begin
					mailbox.receive_if{|message| raise "predicate failed!"}
				rescue => error
					error
				end
			end
			
			succeeding = reactor.async do
				mailbox.receive_if{|message| message == :hello}
			end
			
			mailbox.push(:hello)
			
			expect(succeeding.wait).to be == :hello
			
			# The predicate error was raised into the failing receiver only:
			expect(failing.wait).to be_a(RuntimeError)
			expect(failing.result.message).to be == "predicate failed!"
			
			expect(mailbox).to be(:empty?)
		end
		
		it "can be cancelled while waiting" do
			child = reactor.async do
				mailbox.receive_if{|message| true}
			end
			
			expect(mailbox.waiting_count).to be == 1
			
			child.stop
			child.wait
			
			expect(child).to be(:cancelled?)
			expect(mailbox.waiting_count).to be == 0
			
			# The mailbox is still usable:
			mailbox.push(:hello)
			expect(mailbox.receive).to be == :hello
		end
		
		with "timeout" do
			it "returns nil if the timeout expires before a matching message arrives" do
				mailbox.push({kind: :unwanted})
				
				expect(mailbox.receive_if(timeout: 0.001){|message| message[:kind] == :wanted}).to be_nil
				
				# The non-matching message was not consumed:
				expect(mailbox.size).to be == 1
			end
			
			it "returns a matching message before the timeout expires" do
				mailbox.push(:hello)
				
				expect(mailbox.receive_if(timeout: 1){|message| message == :hello}).to be == :hello
			end
			
			it "does not block when the timeout is zero" do
				expect(mailbox.receive_if(timeout: 0){|message| true}).to be_nil
				
				mailbox.push(:hello)
				expect(mailbox.receive_if(timeout: 0){|message| true}).to be == :hello
			end
		end
		
		with "close" do
			it "returns nil to waiting receivers" do
				child = reactor.async do
					mailbox.receive_if{|message| true}
				end
				
				mailbox.close
				
				expect(child.wait).to be_nil
				expect(mailbox).to be(:closed?)
			end
			
			it "can still receive buffered messages after closing" do
				mailbox.push(:a)
				mailbox.push(:b)
				mailbox.close
				
				expect(mailbox.receive_if{|message| message == :b}).to be == :b
				expect(mailbox.receive_if{|message| true}).to be == :a
				expect(mailbox.receive_if{|message| true}).to be_nil
			end
		end
	end
	
	with "limit" do
		let(:mailbox) {subject.new(limit: 1)}
		
		it "blocks producers when full until a message is received" do
			mailbox.push(:first)
			expect(mailbox).to be(:limited?)
			
			producer = reactor.async do
				mailbox.push(:second)
			end
			
			# The producer is blocked and the message was not buffered:
			expect(mailbox.size).to be == 1
			
			expect(mailbox.receive).to be == :first
			producer.wait
			
			expect(mailbox.receive).to be == :second
		end
		
		it "wakes blocked producers with an error when closed" do
			mailbox.push(:first)
			
			producer = reactor.async do
				mailbox.push(:second)
			end
			
			mailbox.close
			
			expect do
				producer.wait
			end.to raise_exception(Async::Mailbox::ClosedError)
		end
	end
end
