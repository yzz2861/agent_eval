# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/websocket/extension/compression"
require "protocol/websocket/connection"

require "securerandom"
require "socket"

describe Protocol::WebSocket::Extension::Compression do
	let(:compressible) {"permessage-deflate context takeover " * 8}
	
	def connection
		Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(nil))
	end
	
	with subject::Deflate do
		it "skips messages shorter than the minimum size" do
			deflate = subject::Deflate.new(connection, minimum_size: 32)
			
			frame = deflate.pack_text_frame("Hello World")
			
			expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
			expect(frame.unpack).to be == "Hello World"
		end
		
		it "skips short messages by default" do
			frame = subject::Deflate.new(connection).pack_text_frame("Hello World")
			
			expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
		end
		
		it "skips eligible messages that do not become smaller" do
			deflate = subject::Deflate.new(connection, minimum_size: 32)
			buffer = SecureRandom.random_bytes(256)
			
			frame = deflate.pack_binary_frame(buffer, compress: :auto)
			
			expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
			expect(frame.unpack).to be == buffer
		end
		
		it "compresses eligible messages that become smaller" do
			deflate = subject::Deflate.new(connection, minimum_size: 32)
			
			frame = deflate.pack_text_frame(compressible)
			
			expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true
			expect(frame.length).to be < compressible.bytesize
		end
		
		it "honors an explicit request to compress" do
			deflate = subject::Deflate.new(connection, minimum_size: 1024)
			
			frame = deflate.pack_text_frame("Hello World", compress: true)
			
			expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true
		end
		
		it "does not automatically compress binary messages" do
			frame = subject::Deflate.new(connection).pack_binary_frame(compressible)
			
			expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
		end
		
		it "does not update the compression context for an abandoned trial" do
			deflate = subject::Deflate.new(connection, minimum_size: 32)
			
			deflate.pack_text_frame(compressible)
			context = deflate.instance_variable_get(:@deflate)
			
			deflate.pack_binary_frame(SecureRandom.random_bytes(256), compress: :auto)
			
			expect(deflate.instance_variable_get(:@deflate)).to be(:equal?, context)
		end
		
		it "does not retain the compression context when context takeover is disabled" do
			deflate = subject::Deflate.new(connection, context_takeover: false, minimum_size: 32)
			
			deflate.pack_text_frame(compressible)
			
			expect(deflate.instance_variable_get(:@deflate)).to be == nil
		end
		
		it "can decode a compressed, skipped, and recompressed sequence with context takeover" do
			sockets = Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)
			
			begin
				client = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.first), mask: true)
				server = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.last))
				
				Protocol::WebSocket::Extension::Compression.client(client)
				Protocol::WebSocket::Extension::Compression.server(server)
				
				skipped = SecureRandom.random_bytes(256)
				
				client.send_text(compressible)
				client.send_binary(skipped, compress: :auto)
				client.send_text(compressible)
				client.flush
				
				first_frame = server.framer.read_frame
				skipped_frame = server.framer.read_frame
				third_frame = server.framer.read_frame
				
				expect(first_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true
				expect(skipped_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
				expect(third_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true
				
				expect(server.reader.unpack_frames([first_frame])).to be == compressible
				expect(server.reader.unpack_frames([skipped_frame])).to be == skipped
				expect(server.reader.unpack_frames([third_frame])).to be == compressible
			ensure
				sockets.each(&:close)
			end
		end
		
		it "does not compress control frames" do
			sockets = Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)
			
			begin
				client = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.first), mask: true)
				server = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.last))
				
				Protocol::WebSocket::Extension::Compression.client(client)
				Protocol::WebSocket::Extension::Compression.server(server)
				
				client.send_ping("hello")
				client.flush
				server.read_frame
				
				frame = client.framer.read_frame
				
				expect(frame).to be(:control?)
				expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
			ensure
				sockets.each(&:close)
			end
		end
	end
end
