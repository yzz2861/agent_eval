# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2019-2026, by Samuel Williams.
# Copyright, 2019, by Soumya.
# Copyright, 2026, by William T. Nelson.

require "socket"
require "securerandom"
require "protocol/websocket/connection"

describe Protocol::WebSocket::Connection do
	let(:sockets) {Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)}
	
	let(:client) {Protocol::WebSocket::Framer.new(sockets.first)}
	let(:server) {Protocol::WebSocket::Framer.new(sockets.last)}
	
	let(:connection) {subject.new(server)}
	
	with "#close!" do
		it "can manipulate open/closed state" do
			expect(connection).not.to be(:closed?)
			connection.close!
			expect(connection).to be(:closed?)
			connection.open!
			expect(connection).not.to be(:closed?)
		end
		
		it "ignores write failures" do
			server.close
			connection.close!
			expect(connection).to be(:closed?)
		end
	end
	
	with "#close_write" do
		it "can close the write side of the connection" do
			connection.close_write
			
			frame = client.read_frame
			expect(frame).to be_a(Protocol::WebSocket::CloseFrame)
			
			client.write_frame(frame.reply)
			client.close
			
			frame = connection.read_frame
			expect(frame).to be_a(Protocol::WebSocket::CloseFrame)
			
			expect(connection).to be(:closed?)
		end
		
		it "does not raise if the underlying stream is closed" do
			server.close
			
			expect do
				connection.close_write
			end.not.to raise_exception
			
			expect(connection).to be(:closed?)
		end
		
		it "does not raise if the underlying stream is closed (with error)" do
			server.close
			
			expect do
				connection.close_write(RuntimeError.new("something went wrong"))
			end.not.to raise_exception
			
			expect(connection).to be(:closed?)
		end
		
		it "is not closed when close_write succeeds" do
			connection.close_write
			
			expect(connection).not.to be(:closed?)
		end
		
		it "can still read after a successful close_write" do
			text_frame = Protocol::WebSocket::TextFrame.new(true)
			text_frame.pack("Hello")
			client.write_frame(text_frame)
			
			connection.close_write
			
			message = connection.read
			expect(message).to be == "Hello"
		end
	end
	
	with "#shutdown" do
		it "can shutdown the connection" do
			data_frame = Protocol::WebSocket::TextFrame.new(true).tap do |frame|
				frame.pack("Hello World!")
			end
			client.write_frame(data_frame)
			
			close_frame = Protocol::WebSocket::CloseFrame.new.tap(&:pack)
			client.write_frame(close_frame)
			
			connection.shutdown
			expect(connection).to be(:closed?)
		end
	end
	
	it "doesn't generate mask by default" do
		expect(connection.mask).to be == nil
	end
	
	with "explicit role" do
		it "can act as a client with a generated mask" do
			client_connection = subject.new(client, role: :client)
			
			expect(client_connection).to be(:client?)
			expect(client_connection).not.to be(:server?)
			expect(client_connection).to be(:strict?)
			expect(client_connection.mask).to be == true
			expect(client.role).to be == :client
			
			# The actual random key is generated when a frame is packed:
			frame = client_connection.pack_text_frame("Hi")
			expect(frame.mask).to be(:kind_of?, String)
			expect(frame.mask.bytesize).to be == 4
		end
		
		it "can act as a server without a mask" do
			server_connection = subject.new(server, role: :server)
			
			expect(server_connection).to be(:server?)
			expect(server_connection.mask).to be == nil
			expect(server.role).to be == :server
		end
		
		it "rejects an invalid role" do
			expect do
				subject.new(server, role: :peer)
			end.to raise_exception(ArgumentError, message: be =~ /Invalid role/)
		end
		
		it "rejects a mask for a server" do
			expect do
				subject.new(server, role: :server, mask: true)
			end.to raise_exception(ArgumentError, message: be =~ /server must not mask/)
		end
		
		it "rejects an explicit false mask for a client" do
			expect do
				subject.new(client, role: :client, mask: false)
			end.to raise_exception(ArgumentError, message: be =~ /client must mask/i)
		end
		
		it "accepts an explicit mask key for a client" do
			mask = "\x01\x02\x03\x04".b
			client_connection = subject.new(client, role: :client, mask: mask)
			
			expect(client_connection.mask).to be == mask
		end
		
		it "defaults to legacy mode without enforcement" do
			expect(connection).not.to be(:strict?)
			expect(connection.role).to be == nil
			expect(connection).not.to be(:client?)
			expect(connection).not.to be(:server?)
		end
	end
	
	with "strict masking over a real connection" do
		it "rejects unmasked frames read by a server and closes with 1002" do
			server_connection = subject.new(server, role: :server)
			
			# The client (violating the spec) sends an unmasked text frame:
			client.write_frame(Protocol::WebSocket::TextFrame.new(true, "bad"))
			
			error = nil
			begin
				server_connection.read_frame
			rescue Protocol::WebSocket::ProtocolError => error
			end
			
			expect(error).to be_a(Protocol::WebSocket::ProtocolError)
			expect(error.code).to be == Protocol::WebSocket::Error::PROTOCOL_ERROR
			expect(server_connection).to be(:closed?)
			
			close_frame = client.read_frame
			expect(close_frame).to be_a(Protocol::WebSocket::CloseFrame)
			code, _ = close_frame.unpack
			expect(code).to be == Protocol::WebSocket::Error::PROTOCOL_ERROR
		end
		
		it "rejects masked frames read by a client" do
			client_connection = subject.new(client, role: :client)
			
			frame = Protocol::WebSocket::TextFrame.new(true, mask: true)
			frame.pack("bad")
			server.write_frame(frame)
			
			expect do
				client_connection.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /masked frame from server/)
		end
		
		it "communicates with matching masks between client and server" do
			client_connection = subject.new(client, role: :client)
			server_connection = subject.new(server, role: :server)
			
			thread = Thread.new do
				client_connection.send_text("Hello World")
				client_connection.flush
			end
			
			message = server_connection.read
			expect(message).to be == "Hello World"
			
			thread.join
		end
	end
	
	with "masked connection" do
		let(:connection) {subject.new(server, mask: true)}
		
		it "generates valid mask" do
			frame = connection.send_text("Hello World")
			expect(frame.mask).to be(:kind_of?, String)
			expect(frame.mask.bytesize).to be == 4
		end
	end
	
	with "#reserve!" do
		let(:bit) {Protocol::WebSocket::Frame::RSV1}
		
		it "can reserve a bit" do
			expect(connection.reserved & bit).not.to be(:zero?)
			connection.reserve!(bit)
			expect(connection.reserved & bit).to be(:zero?)
		end
		
		it "can't reserve the same bit twice" do
			connection.reserve!(bit)
			
			expect do
				connection.reserve!(bit)
			end.to raise_exception(ArgumentError, message: be =~ /Unable to use/)
		end
	end
	
	with "fragmented frames" do
		let(:text_frame) do
			Protocol::WebSocket::TextFrame.new(false).tap{|frame| frame.pack("Hello ")}
		end
		
		let(:binary_frame) do
			Protocol::WebSocket::BinaryFrame.new(false).tap{|frame| frame.pack "Hello World!"}
		end
		
		let(:ping_frame) do
			Protocol::WebSocket::PingFrame.new.tap{|frame| frame.pack("Yo")}
		end
		
		let(:continuation_frame) do
			Protocol::WebSocket::ContinuationFrame.new(true).tap{|frame| frame.pack("world!")}
		end
		
		it "can reconstruct fragmented message" do
			client.write_frame(text_frame)
			client.write_frame(ping_frame)
			client.write_frame(continuation_frame)
			
			message = connection.read
			expect(message).to be == "Hello world!"
			expect(message.encoding).to be == Encoding::UTF_8
			
			expect(client.read_frame).to be == ping_frame.reply
		end
		
		it "rejects text frames when expecting continuation" do
			client.write_frame(text_frame)
			client.write_frame(text_frame)
			
			expect do
				connection.read
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /expecting continuation/)
		end
		
		it "rejects text frames when expecting continuation" do
			client.write_frame(binary_frame)
			client.write_frame(binary_frame)
			
			expect do
				connection.read
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /expecting continuation/)
		end
		
		it "rejects continuation frames if they are not expected" do
			client.write_frame(continuation_frame)
			
			expect do
				connection.read
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /unexpected continuation/)
		end
	end
	
	with "#send_text" do
		it "can send and receive text frames" do
			connection.send_text("Hello World".encode(Encoding::UTF_8))
			
			expect(client.read_frame).to be(:kind_of?, Protocol::WebSocket::TextFrame)
		end
	end
	
	with "#send_binary" do
		it "can send and receive binary frames" do
			connection.send_binary("Hello World")
			
			expect(client.read_frame).to be(:kind_of?, Protocol::WebSocket::BinaryFrame)
		end
	end
	
	with "#read_frame" do
		it "rejects frames with reserved flags set" do
			frame = Protocol::WebSocket::TextFrame.new
			frame.pack "Hello World!"
			frame.flags = Protocol::WebSocket::Frame::RSV1
			
			client.write_frame(frame)
			
			expect do
				connection.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /reserved flags set/)
		end
		
		it "closes connection if general exception occurs during processing" do
			frame = Protocol::WebSocket::TextFrame.new
			frame.pack "Hello World!"
			
			client.write_frame(frame)
			
			mock(server) do |mock|
				mock.replace(:read_frame) do
					raise EOFError, "Fake error"
				end
			end
			
			expect do
				connection.read_frame
			end.to raise_exception(EOFError, message: be =~ /Fake error/)
			
			expect(connection).to be(:closed?)
			
			frame = client.read_frame
			expect(frame).to be_a(Protocol::WebSocket::CloseFrame)
		end
	end
	
	with "#receive_frame" do
		let(:frame) {Protocol::WebSocket::Frame.new}
		
		it "rejects unhandled frames" do
			expect do
				frame.apply(connection)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Unhandled frame/)
		end
	end
	
	with "#receive_close" do
		it "does not close the underlying connection" do
			close_frame = Protocol::WebSocket::CloseFrame.new
			close_frame.pack
			
			expect(client).not.to receive(:close)
			close_frame.apply(connection)
		end
		
		it "raises an exception when the close frame has an error code" do
			close_frame = Protocol::WebSocket::CloseFrame.new
			close_frame.pack(1001, "Fake error message")
			
			expect do
				close_frame.apply(connection)
			end.to raise_exception(Protocol::WebSocket::ClosedError, message: be =~ /Fake error message/)
			
			expect(connection).to be(:closed?)
		end
	end
	
	with "#send_ping" do
		it "can send a ping and receive a pong" do
			connection.send_ping
			frame = client.read_frame
			expect(frame).to be_a(Protocol::WebSocket::PingFrame)
			
			pong_frame = frame.reply(mask: connection.mask)
			client.write_frame(pong_frame)
			
			frame = connection.read_frame
			expect(frame).to be_a(Protocol::WebSocket::PongFrame)
		end
		
		it "can't send a ping in a closed state" do
			connection.close!
			
			expect do
				connection.send_ping
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Cannot send ping/)
		end
		
		it "can't receive a ping in a closed state" do
			ping_frame = Protocol::WebSocket::PingFrame.new
			
			connection.close!
			
			expect do
				connection.receive_ping(ping_frame)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Cannot receive ping/)
		end
	end
	
	with "different message lengths" do
		it "can handle a short message (<126)" do
			thread = Thread.new do
				client.write_frame(Protocol::WebSocket::TextFrame.new(true).tap{|frame| frame.pack("a" * 15)})
			end
			
			message = connection.read
			expect(message.size).to be == 15
			
			thread.join
		end
		
		it "can handle a medium message (<65k)" do
			thread = Thread.new do
				client.write_frame(Protocol::WebSocket::TextFrame.new(true).tap{|frame| frame.pack("a" * 60_000)})
			end
			
			message = connection.read
			expect(message.size).to be == 60_000
			
			thread.join
		end
		
		it "can handle large message (>65k)" do
			thread = Thread.new do
				client.write_frame(Protocol::WebSocket::TextFrame.new(true).tap{|frame| frame.pack("a" * 90_000)})
			end
			
			message = connection.read
			expect(message.size).to be == 90_000
			
			thread.join
		end
	end
	
	with "masked frames with extended lengths" do
		let(:connection) {subject.new(server)}
		
		it "can handle a masked medium message (length=126 encoding)" do
			thread = Thread.new do
				frame = Protocol::WebSocket::TextFrame.new(true, mask: true)
				frame.pack("a" * 200)
				client.write_frame(frame)
			end
			
			message = connection.read
			expect(message.size).to be == 200
			expect(message).to be == ("a" * 200)
			
			thread.join
		end
		
		it "can handle a masked large message (length=127 encoding)" do
			thread = Thread.new do
				frame = Protocol::WebSocket::TextFrame.new(true, mask: true)
				frame.pack("a" * 70_000)
				client.write_frame(frame)
			end
			
			message = connection.read
			expect(message.size).to be == 70_000
			
			thread.join
		end
	end
	
	with "invalid unicode text message in 3 fragments" do
		let(:payload1) {"\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5".b}
		let(:payload2) {"\xf4\x90\x80\x80".b}
		let(:payload3) {"\x65\x64\x69\x74\x65\x64".b}
		
		it "fails with protocol error" do
			thread = Thread.new do
				client.write_frame(Protocol::WebSocket::TextFrame.new(false, payload1))
				client.write_frame(Protocol::WebSocket::ContinuationFrame.new(false, payload2))
				client.write_frame(Protocol::WebSocket::ContinuationFrame.new(true, payload3))
			end
			
			expect do
				connection.read
			end.to raise_exception(Protocol::WebSocket::ProtocolError)
			
			thread.join
		ensure
			client.close
			server.close
		end
	end
	
	with "#write" do
		it "can write strings (legacy text message)" do
			connection.write("Hello World!")
			
			frame = client.read_frame
			expect(frame.unpack).to be == "Hello World!"
		end
		
		it "can write binary strings (legacy binary message)" do
			connection.write("Hello World!".b)
			
			frame = client.read_frame
			expect(frame).to be_a(Protocol::WebSocket::BinaryFrame)
			expect(frame.unpack).to be == "Hello World!".b
		end
		
		it "can send text messages" do
			message = Protocol::WebSocket::TextMessage.new("Hello World!")
			connection.write(message)
			
			frame = client.read_frame
			expect(frame).to be_a(Protocol::WebSocket::TextFrame)
			expect(frame.unpack).to be == "Hello World!"
		end
		
		it "can send ping mmessages" do
			message = Protocol::WebSocket::PingMessage.new("Hello World!")
			connection.write(message)
			
			frame = client.read_frame
			expect(frame).to be_a(Protocol::WebSocket::PingFrame)
			expect(frame.unpack).to be == "Hello World!"
		end
	end
end
