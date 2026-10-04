# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "socket"
require "zlib"

require "protocol/websocket/connection"
require "protocol/websocket/extension/compression"

	describe Protocol::WebSocket::Extension::Compression::Inflate do
		let(:sockets) {Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)}
		let(:client) {Protocol::WebSocket::Framer.new(sockets.first)}
		let(:server) {Protocol::WebSocket::Framer.new(sockets.last)}
		let(:connection) do
			connection = Protocol::WebSocket::Connection.new(server)
			Protocol::WebSocket::Extension::Compression.server(connection)
			connection
		end

		def deflate_messages(*messages)
			deflate = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -15)
			results = messages.map do |message|
				deflate.deflate(message, Zlib::SYNC_FLUSH)[0...-4]
			end
			deflate.close
			results
		end

		def write_compressed_frame(payload, finished: true)
			frame = if finished
				Protocol::WebSocket::ContinuationFrame.new(true, payload, flags: Protocol::WebSocket::Frame::RSV1)
			else
				Protocol::WebSocket::TextFrame.new(false, payload, flags: Protocol::WebSocket::Frame::RSV1)
			end

			client.write_frame(frame)
		end

		it "incrementally decompresses a message" do
			client.write_frame(Protocol::WebSocket::TextFrame.new(true, deflate_messages("Hello compressed!")[0], flags: Protocol::WebSocket::Frame::RSV1))

			stream = connection.read_message_stream
			chunks = []

			while chunk = stream.readpartial(5)
				chunks << chunk
			end

			expect(chunks.join).to be == "Hello compressed!"
		end

		it "continues decompression across fragmented messages" do
			first, second = deflate_messages("first message", "second message")
			split = first.bytesize / 2

			write_compressed_frame(first.byteslice(0, split), finished: false)
			client.write_frame(Protocol::WebSocket::ContinuationFrame.new(true, first.byteslice(split, first.bytesize - split)))
			client.write_frame(Protocol::WebSocket::TextFrame.new(true, second, flags: Protocol::WebSocket::Frame::RSV1))

			stream = connection.read_message_stream
			expect(stream.readpartial(5)).to be == "firs"
			stream.discard

			next_stream = connection.read_message_stream
			expect(next_stream.readpartial).to be == "second message"
		end

		it "continues the negotiated context across messages" do
			first, second = deflate_messages("first message", "second message")

			client.write_frame(Protocol::WebSocket::TextFrame.new(true, first, flags: Protocol::WebSocket::Frame::RSV1))
			client.write_frame(Protocol::WebSocket::TextFrame.new(true, second, flags: Protocol::WebSocket::Frame::RSV1))

			first_stream = connection.read_message_stream
			expect(first_stream.readpartial(5)).to be == "firs"
			first_stream.discard

			second_stream = connection.read_message_stream
			expect(second_stream.readpartial).to be == "second message"
		end

		it "closes the connection when compressed data is invalid" do
			client.write_frame(Protocol::WebSocket::TextFrame.new(true, "not compressed", flags: Protocol::WebSocket::Frame::RSV1))

			stream = connection.read_message_stream

			expect do
				stream.readpartial
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /invalid compressed payload/)

			expect(connection).to be(:closed?)
			expect(client.read_frame.unpack.first).to be == Protocol::WebSocket::Error::INVALID_PAYLOAD
		end
	end
