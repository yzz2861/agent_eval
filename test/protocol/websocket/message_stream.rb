# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "socket"
require "protocol/websocket/connection"

describe Protocol::WebSocket::MessageStream do
	let(:sockets) {Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)}

	let(:client) {Protocol::WebSocket::Framer.new(sockets.first)}
	let(:server) {Protocol::WebSocket::Framer.new(sockets.last)}
	let(:connection) {Protocol::WebSocket::Connection.new(server)}

	with "a text message" do
		it "can read the message type before reading data" do
			frame = Protocol::WebSocket::TextFrame.new(true)
			frame.pack("Hello world!")
			client.write_frame(frame)

			stream = connection.read_stream
			expect(stream.type).to be == :text
			expect(stream).to be(:text?)
			expect(stream).not.to be(:binary?)
			expect(stream.read_partial).to be == "Hello world!"
			expect(stream.read_partial).to be == nil
		end

		it "preserves multi-byte UTF-8 characters across chunk boundaries" do
			frame = Protocol::WebSocket::TextFrame.new(true)
			frame.pack("é🙂")
			client.write_frame(frame)

			stream = connection.read_stream
			chunks = []

			while chunk = stream.read_partial(1)
				chunks << chunk
				expect(chunk.encoding).to be == Encoding::UTF_8
			end

			expect(chunks.join).to be == "é🙂"
		end

		it "rejects invalid UTF-8 and closes the connection" do
			frame = Protocol::WebSocket::TextFrame.new(true, "\xff")
			client.write_frame(frame)

			stream = connection.read_stream

			expect do
				stream.read_partial
			end.to raise_exception(Protocol::WebSocket::ProtocolError)

			expect(connection).to be(:closed?)
			expect(client.read_frame).to be_a(Protocol::WebSocket::CloseFrame)
		end
	end

	with "a binary message" do
		it "returns binary chunks" do
			frame = Protocol::WebSocket::BinaryFrame.new(true)
			frame.pack("Hello world!")
			client.write_frame(frame)

			stream = connection.read_stream
			expect(stream.type).to be == :binary
			expect(stream).to be(:binary?)
			expect(stream.read_partial).to be == "Hello world!".b
		end
	end

	with "fragmented frames" do
		let(:first_frame) do
			Protocol::WebSocket::TextFrame.new(false).tap do |frame|
				frame.pack("Hello ")
			end
		end

		let(:ping_frame) do
			Protocol::WebSocket::PingFrame.new.tap do |frame|
				frame.pack("Yo")
			end
		end

		let(:final_frame) do
			Protocol::WebSocket::ContinuationFrame.new(true).tap do |frame|
				frame.pack("world!")
			end
		end

		it "handles control frames between data fragments" do
			client.write_frame(first_frame)
			client.write_frame(ping_frame)
			client.write_frame(final_frame)

			stream = connection.read_stream
			chunks = []

			while chunk = stream.read_partial
				chunks << chunk
			end

			expect(chunks.join).to be == "Hello world!"
			expect(client.read_frame).to be_a(Protocol::WebSocket::PongFrame)
		end
	end

	with "masked frames" do
		it "unmasks chunks with the correct mask offset" do
			frame = Protocol::WebSocket::BinaryFrame.new(true, mask: true)
			frame.pack("Hello world!")
			client.write_frame(frame)

			stream = connection.read_stream
			chunks = []

			while chunk = stream.read_partial(3)
				chunks << chunk
			end

			expect(chunks.join).to be == "Hello world!"
		end
	end

	with "discarding the remainder" do
		it "can continue to the next message" do
			first_frame = Protocol::WebSocket::TextFrame.new(false)
			first_frame.pack("Hello ")
			final_frame = Protocol::WebSocket::ContinuationFrame.new(true)
			final_frame.pack("world!")
			next_frame = Protocol::WebSocket::BinaryFrame.new(true)
			next_frame.pack("next")

			client.write_frame(first_frame)
			client.write_frame(final_frame)
			client.write_frame(next_frame)

			stream = connection.read_stream
			expect(stream.read_partial(5)).to be == "Hello"
			stream.discard

			next_stream = connection.read_stream
			expect(next_stream.type).to be == :binary
			expect(next_stream.read_partial).to be == "next"
		end

		it "discards automatically when given a block" do
			first_frame = Protocol::WebSocket::TextFrame.new(true)
			first_frame.pack("first")
			next_frame = Protocol::WebSocket::TextFrame.new(true)
			next_frame.pack("second")

			client.write_frame(first_frame)
			client.write_frame(next_frame)

			connection.read_stream do |stream|
				expect(stream.read_partial(2)).to be == "fi"
			end

			expect(connection.read).to be == "second"
		end
	end

	with "interleaved readers" do
		it "does not allow starting another read before the message is consumed" do
			frame = Protocol::WebSocket::TextFrame.new(true)
			frame.pack("Hello")
			client.write_frame(frame)

			stream = connection.read_stream
			expect(stream.read_partial(2)).to be == "He"

			expect do
				connection.read
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /currently being read/)

			expect do
				connection.read_stream
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /currently being read/)
		end
	end

	with "corrupted message fragments" do
		it "closes the connection when another data frame interrupts a fragmented message" do
			first_frame = Protocol::WebSocket::TextFrame.new(false)
			first_frame.pack("Hello")
			invalid_frame = Protocol::WebSocket::TextFrame.new(true)
			invalid_frame.pack("world")

			client.write_frame(first_frame)
			client.write_frame(invalid_frame)

			stream = connection.read_stream
			expect(stream.read_partial).to be == "Hello"

			expect do
				stream.read_partial
			end.to raise_exception(Protocol::WebSocket::ProtocolError)

			expect(connection).to be(:closed?)
			expect(client.read_frame).to be_a(Protocol::WebSocket::CloseFrame)
		end

		it "closes the connection when the frame payload is truncated" do
			client.write_frame(Protocol::WebSocket::TextFrame.new(false, "Hello"))
			sockets.first.write("\x80\x10more")
			sockets.first.close

			stream = connection.read_stream
			expect(stream.read_partial).to be == "Hello"

			expect do
				stream.read_partial
				stream.read_partial
			end.to raise_exception(EOFError)

			expect(connection).to be(:closed?)
			sockets.last.close
			end
		end

		it "does not allow a different fiber to interleave with the same message" do
			frame = Protocol::WebSocket::TextFrame.new(true)
			frame.pack("Hello")
			client.write_frame(frame)

			stream = connection.read_stream
			expect(stream.read_partial(2)).to be == "He"

			fiber = Fiber.new do
				expect do
					stream.read_partial
				end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /another reader/)
			end

			fiber.resume
			expect(stream.read_partial(3)).to be == "llo"
		end
	end
