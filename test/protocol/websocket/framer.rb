# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2023-2026, by Samuel Williams.
# Copyright, 2026, by William T. Nelson.

require "protocol/websocket/framer"

describe Protocol::WebSocket::Framer do
	let(:stream) {StringIO.new}
	let(:framer) {subject.new(stream)}
	let(:mask_key) {"mask"}
	
	with "#write_frame" do
		it "fails with invalid mask size" do
			frame = Protocol::WebSocket::Frame.new(true, "12345")
			frame.mask = "bad"
			
			expect do
				framer.write_frame(frame)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Invalid mask length/)
		end
		
		it "requires client frames to be masked" do
			frame = Protocol::WebSocket::TextFrame.new(true, "Hello")

			expect do
				subject.new(stream, role: :client).write_frame(frame)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Client frames must be masked/)
		end

		it "requires server frames to be unmasked" do
			frame = Protocol::WebSocket::TextFrame.new(true, "Hello", mask: true)

			expect do
				subject.new(stream, role: :server).write_frame(frame)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Server frames must not be masked/)
		end

		it "writes correctly masked client and unmasked server frames" do
			client_stream = StringIO.new
			server_stream = StringIO.new

			subject.new(client_stream, role: :client).write_frame(Protocol::WebSocket::TextFrame.new(true, mask: true).tap{|frame| frame.pack("Hello")})
			subject.new(server_stream, role: :server).write_frame(Protocol::WebSocket::TextFrame.new(true, "Hello"))

			expect(client_stream.string.getbyte(1) & 0b1000_0000).not.to be(:zero?)
			expect(server_stream.string.getbyte(1) & 0b1000_0000).to be(:zero?)
		end

		it "writes a text frame and reads it back" do
			output = StringIO.new
			writer = Protocol::WebSocket::Framer.new(output)
			
			frame = Protocol::WebSocket::TextFrame.new(true, "Hello")
			writer.write_frame(frame)
			
			reader = Protocol::WebSocket::Framer.new(StringIO.new(output.string))
			received = reader.read_frame
			expect(received).to be_a(Protocol::WebSocket::TextFrame)
			expect(received.payload).to be == "Hello"
		end
	end
	
	with "#read_frame" do
		it "rejects unmasked frames from a client when acting as a server" do
			stream.string = "\x81\x05Hello"
			stream.rewind

			expect do
				subject.new(stream, role: :server).read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /unmasked frame from client/) do |error|
				expect(error.code).to be == Protocol::WebSocket::Error::PROTOCOL_ERROR
			end

			expect(stream.pos).to be == 2
		end

		it "rejects masked frames from a server when acting as a client" do
			stream.string = "\x81\x85#{mask_key}\x25\x05\x19\x0B\x17"
			stream.rewind

			expect do
				subject.new(stream, role: :client).read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /masked frame from server/) do |error|
				expect(error.code).to be == Protocol::WebSocket::Error::PROTOCOL_ERROR
			end

			expect(stream.pos).to be == 2
		end

		it "fails if it can't read the frame header" do
			expect do
				framer.read_frame
			end.to raise_exception(EOFError, message: be =~ /Could not read frame header/)
		end
		
		it "rejects reserved non-control opcodes" do
			stream.string = "\x83\x00"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Non-control opcode.*reserved/)
		end
		
		it "rejects reserved control opcodes" do
			stream.string = "\x8B\x00"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Control opcode.*reserved/)
		end
		
		it "rejects invalid control frame payload length" do
			# FIN=1, opcode=0x8 (close), MASK=0, length=127 → violates max 125 for control frames
			stream.string = "\x88\x7F"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Invalid control frame payload length/)

			expect(stream.pos).to be == 2
		end
		
		it "rejects fragmented control frames" do
			# FIN=0, opcode=0x8 (close), MASK=0, length=15
			stream.string = "\x08\x0F"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Fragmented control frame/)
		end
		
		it "rejects reserved flags that were not negotiated" do
			stream.string = "\xC1\x05Hello"
			stream.rewind

			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /reserved flags set/)

			expect(stream.pos).to be == 2
		end

		it "accepts reserved flags that were negotiated" do
			stream.string = "\xC1\x05Hello"
			stream.rewind

			frame = framer.read_frame(reserved: Protocol::WebSocket::Frame::RESERVED & ~Protocol::WebSocket::Frame::RSV1)

			expect(frame.flags & Protocol::WebSocket::Frame::RSV1).not.to be(:zero?)
		end

		it "uses message too large as the close code for oversized payloads" do
			stream.string = "\x82\x7D"
			stream.rewind

			expect do
				framer.read_frame(124)
			end.to raise_exception(Protocol::WebSocket::ProtocolError) do |error|
				expect(error.code).to be == Protocol::WebSocket::Error::MESSAGE_TOO_LARGE
			end

			expect(stream.pos).to be == 2
		end

		it "uses protocol error for payloads larger than the protocol limit" do
			stream.string = "\x82\x7F\x80\x00\x00\x00\x00\x00\x00\x00"
			stream.rewind

			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError) do |error|
				expect(error.code).to be == Protocol::WebSocket::Error::PROTOCOL_ERROR
			end

			expect(stream.pos).to be == 10
		end

		it "rejects frames bigger than the maximum frame size" do
			# FIN=1, opcode=0x2 (binary), MASK=0, length=125
			stream.string = "\x82\x7D"
			stream.rewind
			
			expect do
				framer.read_frame(124)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Invalid payload length: \d+ > \d+!/)
		end
		
		it "rejects frames with truncated payload" do
			# FIN=1, opcode=0x2 (binary), MASK=0, length=5, only 4 bytes of payload
			stream.string = "\x82\x051234"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(EOFError, message: be =~ /Incorrect payload length: \d+ != \d+!/)
		end
		
		it "reads a text frame" do
			# FIN=1, opcode=0x1 (text), MASK=0, length=5, payload="Hello"
			stream.string = "\x81\x05Hello"
			stream.rewind
			
			frame = framer.read_frame
			expect(frame).to be_a(Protocol::WebSocket::TextFrame)
			expect(frame.payload).to be == "Hello"
			expect(frame.mask).to be == false
		end
	end
end
