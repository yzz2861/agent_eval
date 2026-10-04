# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "socket"
require "securerandom"
require "stringio"

require "protocol/websocket/connection"
require "protocol/websocket/framer"
require "protocol/websocket/extension/compression"

describe Protocol::WebSocket::Extension::Compression do
	let(:sockets) {Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)}

	let(:client_connection) do
		Protocol::WebSocket::Connection.new(
			Protocol::WebSocket::Framer.new(sockets.first), mask: true
		)
	end

	let(:server_connection) do
		Protocol::WebSocket::Connection.new(
			Protocol::WebSocket::Framer.new(sockets.last)
		)
	end

	before do
		subject.client(client_connection)
		subject.server(server_connection)
	end

	it "automatically skips compression when it does not reduce payload size" do
		frame = client_connection.send_text("Hello World")
		client_connection.flush

		expect(frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
		expect(frame.unpack).to be == "Hello World"
		expect(server_connection.read).to be == "Hello World"
	end

	it "does not let an abandoned trial change the context takeover dictionary" do
		repeated = "a" * 100
		random = Random.new(1).bytes(128)

		first_frame = client_connection.send_text(repeated)
		client_connection.flush
		skipped_frame = client_connection.send_binary(random)
		client_connection.flush
		third_frame = client_connection.send_text(repeated)
		client_connection.flush

		expect(client_connection.writer.context_takeover).to be == true
		expect(first_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true
		expect(skipped_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
		expect(third_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true

		expect(skipped_frame.payload.bytesize).to be == random.bytesize
		expect(third_frame.payload.bytesize).to be < first_frame.payload.bytesize

		expect(server_connection.read).to be == repeated
		expect(server_connection.read).to be == random
		expect(server_connection.read).to be == repeated
	end

	it "does not reset context takeover for every message" do
		payload = "a" * 100

		first_frame = client_connection.send_text(payload)
		client_connection.flush
		second_frame = client_connection.send_text(payload)
		client_connection.flush

		expect(first_frame.payload.bytesize).to be > second_frame.payload.bytesize
		expect(server_connection.read).to be == payload
		expect(server_connection.read).to be == payload
	end

	it "does not compress control frames" do
		ping_frame = client_connection.send_ping("Hello World")
		client_connection.flush

		expect(ping_frame.control?).to be == true
		expect(ping_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
		expect(ping_frame.unpack).to be == "Hello World"

		received_frame = server_connection.read_frame
		expect(received_frame).to be_a(Protocol::WebSocket::PingFrame)
		expect(received_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
	end

	with "minimum size" do
		it "does not trial messages shorter than the configured minimum size" do
			connection = Protocol::WebSocket::Connection.new(
				Protocol::WebSocket::Framer.new(StringIO.new)
			)
			writer = subject::Deflate.client(connection, minimum_size: 12)

			automatic_frame = writer.pack_text_frame("Hello World")
			expect(automatic_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == false
			expect(automatic_frame.payload).to be == "Hello World"

			forced_frame = writer.pack_text_frame("Hello World", compress: true)
			expect(forced_frame.flag?(Protocol::WebSocket::Frame::RSV1)).to be == true
			expect(forced_frame.payload.bytesize).to be > 11
		end
	end

	with "no context takeover" do
		it "uses a fresh compression context for every message" do
			client = Protocol::WebSocket::Connection.new(
				Protocol::WebSocket::Framer.new(sockets.first), mask: true
			)
			server = Protocol::WebSocket::Connection.new(
				Protocol::WebSocket::Framer.new(sockets.last)
			)

			subject.client(client, client_no_context_takeover: true)
			subject.server(server, client_no_context_takeover: true)

			payload = "a" * 100

			first_frame = client.send_text(payload)
			client.flush
			second_frame = client.send_text(payload)
			client.flush

			expect(client.writer.context_takeover).to be == false
			expect(first_frame.payload.bytesize).to be == second_frame.payload.bytesize
			expect(server.read).to be == payload
			expect(server.read).to be == payload
		end
	end
end
