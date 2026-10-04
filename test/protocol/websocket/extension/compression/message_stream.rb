# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "socket"
require "zlib"

require "protocol/websocket/connection"
require "protocol/websocket/extension/compression"

describe Protocol::WebSocket::Extension::Compression do
	let(:sockets) {Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)}

	let(:client) do
		Protocol::WebSocket::Connection.new(
			Protocol::WebSocket::Framer.new(sockets.first)
		)
	end

	let(:server) do
		Protocol::WebSocket::Connection.new(
			Protocol::WebSocket::Framer.new(sockets.last)
		)
	end

	before do
		subject.client(client)
		subject.server(server)
	end

	with "message streaming" do
		it "decompresses a large compressed message into chunks" do
			message = "Hello World!" * 200
			client.send_text(message)
			client.flush

			stream = server.read_stream
			expect(stream.type).to be == :text

			chunks = []
			while chunk = stream.read_partial(64)
				chunks << chunk
			end

			expect(chunks.count).to be > 1
			expect(chunks.join).to be == message
		end

		it "continues decompression state across fragments" do
			message = "Hello World!" * 100

			deflate = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -15)
			payload = deflate.deflate(message, Zlib::NO_FLUSH)
			payload << deflate.flush(Zlib::SYNC_FLUSH)[0...-4]
			deflate.close
			first_payload = payload.byteslice(0, payload.bytesize / 2)
			last_payload = payload.byteslice(first_payload.bytesize, payload.bytesize)

			first_frame = Protocol::WebSocket::TextFrame.new(
				false,
				first_payload,
				flags: Protocol::WebSocket::Frame::RSV1
			)
			final_frame = Protocol::WebSocket::ContinuationFrame.new(true, last_payload)

			client.write_frame(first_frame)
			client.write_frame(final_frame)
			client.flush

			stream = server.read_stream
			chunks = []
			while chunk = stream.read_partial(4096)
				chunks << chunk
			end

			expect(chunks.join).to be == message
		end

		it "preserves compression context across messages" do
			first_message = "Hello World!" * 100
			second_message = "Hello World!" * 101

			client.send_text(first_message)
			client.send_text(second_message)
			client.flush

			first_stream = server.read_stream
			expect(first_stream.read_partial(first_message.bytesize)).to be == first_message
			expect(first_stream.read_partial).to be == nil

			second_stream = server.read_stream
			expect(second_stream.read_partial(second_message.bytesize)).to be == second_message
			expect(second_stream.read_partial).to be == nil
		end

		it "drains a discarded compressed message before reading the next one" do
			first_message = "first message" * 20
			second_message = "second message" * 20

			client.send_text(first_message)
			client.send_text(second_message)
			client.flush

			first_stream = server.read_stream
			expect(first_stream.read_partial(10)).not.to be == nil
			first_stream.discard

			second_stream = server.read_stream
			expect(second_stream.read_partial(second_message.bytesize)).to be == second_message
			expect(second_stream.read_partial).to be == nil
		end
	end
end
