# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2023-2026, by Samuel Williams.
# Copyright, 2026, by William T. Nelson.

require "protocol/websocket/framer"
require "securerandom"

describe Protocol::WebSocket::Framer do
	let(:stream) {StringIO.new}
	let(:framer) {subject.new(stream)}
	
	# Build a masked version of an unmasked frame (short or extended length).
	def masked_frame(bytes, mask: "\x37\xFA\x21\x3D")
		bytes = bytes.b
		mask = mask.b
		
		encoding = bytes.getbyte(1) & 0b0111_1111
		extended = encoding == 126 ? 2 : (encoding == 127 ? 8 : 0)
		
		result = bytes.byteslice(0, 2).b
		result.setbyte(1, result.getbyte(1) | 0b1000_0000)
		
		result << bytes.byteslice(2, extended) if extended > 0
		
		payload_start = 2 + extended
		payload = bytes.byteslice(payload_start, bytes.bytesize - payload_start)
		
		result << mask
		result << payload.each_byte.with_index.map do |byte, index|
			byte ^ mask.getbyte(index % 4)
		end.pack("C*")
		
		return result
	end
	
	with "role validation" do
		it "accepts :client, :server and nil" do
			expect(subject.new(stream, role: :client).role).to be == :client
			expect(subject.new(stream, role: :server).role).to be == :server
			expect(subject.new(stream).role).to be == nil
		end
		
		it "rejects invalid roles" do
			expect do
				subject.new(stream, role: :peer)
			end.to raise_exception(ArgumentError, message: be =~ /Invalid role/)
		end
		
		it "is strict only when a role is given" do
			expect(subject.new(stream)).not.to be(:strict?)
			expect(subject.new(stream, role: :server)).to be(:strict?)
		end
	end
	
	with "#write_frame" do
		it "fails with invalid mask size" do
			frame = Protocol::WebSocket::Frame.new(true, "12345")
			frame.mask = "bad"
			
			expect do
				framer.write_frame(frame)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Invalid mask length/)
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
		
		with "strict role enforcement" do
			it "requires masked frames for a client" do
				writer = subject.new(StringIO.new, role: :client)
				
				expect do
					writer.write_frame(Protocol::WebSocket::TextFrame.new(true, "Hello"))
				end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Client frames must be masked/)
			end
			
			it "rejects masked frames for a server" do
				writer = subject.new(StringIO.new, role: :server)
				frame = Protocol::WebSocket::TextFrame.new(true, mask: true)
				frame.pack("Hello")
				
				expect do
					writer.write_frame(frame)
				end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Server frames must not be masked/)
			end
			
			it "writes according to the configured role" do
				server_output = StringIO.new
				subject.new(server_output, role: :server).write_frame(
					Protocol::WebSocket::TextFrame.new(true, "Hi")
				)
				expect(server_output.string.getbyte(1) & 0b1000_0000).to be == 0
				
				client_frame = Protocol::WebSocket::TextFrame.new(true, mask: true)
				client_frame.pack("Hi")
				
				client_output = StringIO.new
				subject.new(client_output, role: :client).write_frame(client_frame)
				expect(client_output.string.getbyte(1) & 0b1000_0000).not.to be == 0
			end
		end
	end
	
	with "#read_frame" do
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
		
		it "rejects invalid control frame payload length encoding" do
			stream.string = "\x88\xFF"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Invalid control frame payload length.*125/)
		end
		
		it "rejects fragmented control frames" do
			stream.string = "\x08\x0F"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /Fragmented control frame/)
		end
		
		it "rejects reserved RSV bits by default" do
			stream.string = "\xF1\x00"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /reserved flags set/)
		end
		
		it "accepts RSV bits negotiated by an extension" do
			stream.string = "\xC1\x00"
			stream.rewind
			
			frame = framer.read_frame(reserved: Protocol::WebSocket::Frame::RESERVED & ~Protocol::WebSocket::Frame::RSV1)
			expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true
		end
		
		it "still rejects un-negotiated RSV bits when other bits are allowed" do
			stream.string = "\xE1\x00"
			stream.rewind
			
			expect do
				framer.read_frame(reserved: Protocol::WebSocket::Frame::RESERVED & ~Protocol::WebSocket::Frame::RSV1)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /reserved flags set/)
		end
		
		with "strict server role" do
			let(:framer) {subject.new(stream, role: :server)}
			
			it "rejects unmasked client frames before reading the payload" do
				stream.string = "\x81\x05Hello"
				stream.rewind
				
				expect do
					framer.read_frame
				end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /unmasked frame from client/)
				
				expect(stream.pos).to be == 2
			end
			
			it "accepts masked client frames and unmasks them" do
				stream.string = masked_frame("\x81\x05Hello")
				stream.rewind
				
				frame = framer.read_frame
				expect(frame).to be_a(Protocol::WebSocket::TextFrame)
				expect(frame.mask).to be == "\x37\xFA\x21\x3D".b
				expect(frame.unpack).to be == "Hello"
			end
			
			it "rejects unmasked frames using 64-bit length without reading extended bytes" do
				stream.string = "\x82\x7F".b + [2**40].pack("Q>") + "\x00".b * 4
				stream.rewind
				
				expect do
					framer.read_frame
				end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /unmasked frame from client/)
				
				expect(stream.pos).to be == 2
			end
		end
		
		with "strict client role" do
			let(:framer) {subject.new(stream, role: :client)}
			
			it "rejects masked server frames before reading the mask and payload" do
				stream.string = masked_frame("\x81\x05Hello")
				stream.rewind
				
				expect do
					framer.read_frame
				end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /masked frame from server/)
				
				expect(stream.pos).to be == 2
			end
			
			it "accepts unmasked server frames" do
				stream.string = "\x81\x05Hello"
				stream.rewind
				
				frame = framer.read_frame
				expect(frame.unpack).to be == "Hello"
				expect(frame.mask).to be == false
			end
		end
		
		with "legacy role (nil)" do
			it "accepts both masked and unmasked frames" do
				stream.string = "\x81\x05Hello"
				stream.rewind
				expect(framer.read_frame.unpack).to be == "Hello"
				
				stream.string = masked_frame("\x81\x05Hello")
				stream.rewind
				expect(framer.read_frame.unpack).to be == "Hello"
			end
		end
		
		it "rejects the most significant bit being set in the 64-bit length" do
			stream.string = "\x82\x7F".b + [2**63].pack("Q>")
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /most significant bit/)
		end
		
		it "rejects non-minimal 16-bit length encoding before reading payload" do
			stream.string = "\x82\x7E".b + [100].pack("n") + "\x00".b * 4
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /16-bit length used/)
			
			expect(stream.pos).to be == 4
		end
		
		it "rejects non-minimal 64-bit length encoding before reading payload" do
			stream.string = "\x82\x7F".b + [100].pack("Q>") + "\x00".b * 4
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /64-bit length used/)
			
			expect(stream.pos).to be == 10
		end
		
		it "rejects frames bigger than the maximum frame size with a 1009 close code" do
			stream.string = "\x82\x7D"
			stream.rewind
			
			error = nil
			
			begin
				framer.read_frame(124)
			rescue Protocol::WebSocket::ProtocolError => error
			end
			
			expect(error).to be_a(Protocol::WebSocket::ProtocolError)
			expect(error.message).to be =~ /Invalid payload length: 125 > 124!/
			expect(error.code).to be == Protocol::WebSocket::Error::MESSAGE_TOO_LARGE
		end
		
		it "uses the protocol error code for structural header errors" do
			stream.string = "\x83\x00"
			stream.rewind
			
			error = nil
			begin
				framer.read_frame
			rescue Protocol::WebSocket::ProtocolError => error
			end
			
			expect(error.code).to be == Protocol::WebSocket::Error::PROTOCOL_ERROR
		end
		
		it "rejects frames with truncated payload" do
			stream.string = "\x82\x051234"
			stream.rewind
			
			expect do
				framer.read_frame
			end.to raise_exception(EOFError, message: be =~ /Incorrect payload length: \d+ != \d+!/)
		end
		
		it "reads a text frame" do
			stream.string = "\x81\x05Hello"
			stream.rewind
			
			frame = framer.read_frame
			expect(frame).to be_a(Protocol::WebSocket::TextFrame)
			expect(frame.payload).to be == "Hello"
			expect(frame.mask).to be == false
		end
	end
end
