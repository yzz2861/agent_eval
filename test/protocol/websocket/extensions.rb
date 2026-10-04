# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.

require "protocol/websocket/extensions"
require "protocol/websocket/connection"

require "socket"

describe Protocol::WebSocket::Extensions do
	# A wrapper used by the fake extensions to record the reader/writer transform chain.
	class FakeTransform
		attr :inner
		attr :name
		
		def initialize(inner, name)
			@inner = inner
			@name = name
		end
	end
	
	# Shared behaviour for the fake extensions below.
	module FakeExtension
		def reserved_bits(**options)
			self::BITS
		end
		
		def offer(**options)
			[self::NAME]
		end
		
		def accept(arguments, **options)
			options[:parameters] = arguments
			options
		end
		
		def negotiate(arguments, **options)
			options[:parameters] = arguments
			[[self::NAME], options]
		end
		
		def client(connection, **options)
			install(connection, **options)
		end
		
		def server(connection, **options)
			install(connection, **options)
		end
		
		private
		
		def install(connection, **options)
			connection.reserve!(reserved_bits)
			connection.reader = FakeTransform.new(connection.reader, self::NAME)
			connection.writer = FakeTransform.new(connection.writer, self::NAME)
		end
	end
	
	module FakeExtensionA
		extend FakeExtension
		
		NAME = "x-fake-a"
		BITS = Protocol::WebSocket::Frame::RSV2
	end
	
	module FakeExtensionB
		extend FakeExtension
		
		NAME = "x-fake-b"
		BITS = Protocol::WebSocket::Frame::RSV3
	end
	
	# Claims the same reserved bit as FakeExtensionA.
	module ConflictingExtension
		extend FakeExtension
		
		NAME = "x-conflicting"
		BITS = Protocol::WebSocket::Frame::RSV2
	end
	
	# Fails part-way through installation, after modifying the connection.
	module BrokenExtension
		extend FakeExtension
		
		NAME = "x-broken"
		BITS = Protocol::WebSocket::Frame::RSV3
		
		def self.install(connection, **options)
			connection.reserve!(reserved_bits)
			connection.reader = FakeTransform.new(connection.reader, NAME)
			
			raise "Simulated install failure!"
		end
	end
	
	it "can parse headers" do
		extensions = subject.parse([
			"permessage-deflate; client_max_window_bits=10",
		]).to_a
		
		expect(extensions).to be == [
			["permessage-deflate", [["client_max_window_bits", "10"]]]
		]
	end
	
	with "client" do
		let(:client) do
			Protocol::WebSocket::Extensions::Client.new([
				[FakeExtensionA, {}],
				[FakeExtensionB, {}],
			])
		end
		
		let(:connection) {Protocol::WebSocket::Connection.new(nil)}
		
		it "builds an inspectable plan before modifying the connection" do
			client.accept(["x-fake-a; level=3", "x-fake-b"])
			
			plan = client.plan
			
			expect(plan.names).to be == ["x-fake-a", "x-fake-b"]
			expect(plan.reserved).to be == (Protocol::WebSocket::Frame::RSV2 | Protocol::WebSocket::Frame::RSV3)
			
			entry = plan.entries.first
			expect(entry.extension).to be == FakeExtensionA
			expect(entry.options[:parameters]).to be == [["level", "3"]]
			expect(entry.bits).to be == Protocol::WebSocket::Frame::RSV2
		end
		
		it "rejects extensions that were not offered" do
			expect do
				client.accept(["x-surprise"])
			end.to raise_exception(Protocol::WebSocket::Extensions::NegotiationError, message: be =~ /x-surprise.*not offered/)
		end
		
		it "rejects extensions accepted more than once" do
			expect do
				client.accept(["x-fake-a", "x-fake-a"])
			end.to raise_exception(Protocol::WebSocket::Extensions::NegotiationError, message: be =~ /x-fake-a.*more than once/)
		end
		
		it "rejects extensions with conflicting reserved bits" do
			conflicting = Protocol::WebSocket::Extensions::Client.new([
				[FakeExtensionA, {}],
				[ConflictingExtension, {}],
			])
			
			expect do
				conflicting.accept(["x-fake-a", "x-conflicting"])
			end.to raise_exception(Protocol::WebSocket::Extensions::NegotiationError, message: be =~ /x-conflicting.*RSV2.*x-fake-a/)
		end
		
		it "rejects out of range permessage-deflate parameters" do
			client = Protocol::WebSocket::Extensions::Client.default
			
			expect do
				client.accept(["permessage-deflate; server_max_window_bits=20"])
			end.to raise_exception(ArgumentError, message: be =~ /out of range/)
			
			expect do
				client.accept(["permessage-deflate; client_max_window_bits=7"])
			end.to raise_exception(ArgumentError, message: be =~ /out of range/)
		end
		
		it "installs extensions in order of acceptance" do
			client.accept(["x-fake-a", "x-fake-b"])
			client.apply(connection)
			
			expect(connection.reader.name).to be == "x-fake-b"
			expect(connection.reader.inner.name).to be == "x-fake-a"
			expect(connection.writer.name).to be == "x-fake-b"
			expect(connection.writer.inner.name).to be == "x-fake-a"
		end
		
		it "restores the connection if an extension fails to install" do
			broken = Protocol::WebSocket::Extensions::Client.new([
				[FakeExtensionA, {}],
				[BrokenExtension, {}],
			])
			broken.accept(["x-fake-a", "x-broken"])
			
			reader = connection.reader
			writer = connection.writer
			reserved = connection.reserved
			
			expect do
				broken.apply(connection)
			end.to raise_exception(RuntimeError, message: be =~ /Simulated install failure/)
			
			expect(connection.reader).to be_equal(reader)
			expect(connection.writer).to be_equal(writer)
			expect(connection.reserved).to be == reserved
		end
	end
	
	with "server" do
		let(:server) do
			Protocol::WebSocket::Extensions::Server.new([
				[FakeExtensionA, {}],
				[FakeExtensionB, {}],
			])
		end
		
		let(:connection) {Protocol::WebSocket::Connection.new(nil)}
		
		it "installs extensions in reverse order of acceptance" do
			headers = []
			
			server.accept(["x-fake-a", "x-fake-b"]) do |header|
				headers << header
			end
			
			expect(headers).to be == [["x-fake-a"], ["x-fake-b"]]
			expect(server.plan.names).to be == ["x-fake-b", "x-fake-a"]
			
			server.apply(connection)
			
			expect(connection.reader.name).to be == "x-fake-a"
			expect(connection.reader.inner.name).to be == "x-fake-b"
			expect(connection.writer.name).to be == "x-fake-a"
			expect(connection.writer.inner.name).to be == "x-fake-b"
		end
		
		it "rejects extensions with conflicting reserved bits" do
			conflicting = Protocol::WebSocket::Extensions::Server.new([
				[FakeExtensionA, {}],
				[ConflictingExtension, {}],
			])
			
			expect do
				conflicting.accept(["x-fake-a", "x-conflicting"])
			end.to raise_exception(Protocol::WebSocket::Extensions::NegotiationError, message: be =~ /x-fake-a.*RSV2.*x-conflicting/)
		end
	end
	
	with "permessage-deflate" do
		let(:sockets) {Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)}
		
		let(:client_connection) {Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.first))}
		let(:server_connection) {Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.last))}
		
		it "negotiates and exchanges compressed messages" do
			client_extensions = Protocol::WebSocket::Extensions::Client.default
			server_extensions = Protocol::WebSocket::Extensions::Server.default
			
			# Client offers extensions to the server:
			offers = []
			client_extensions.offer do |header|
				offers << header.join("; ")
			end
			
			# Server negotiates a response:
			responses = []
			server_extensions.accept(offers) do |header|
				responses << header.join("; ")
			end
			
			# Client accepts the negotiated response:
			client_extensions.accept(responses)
			
			client_extensions.apply(client_connection)
			server_extensions.apply(server_connection)
			
			expect(client_connection.writer).to be_a(Protocol::WebSocket::Extension::Compression::Deflate)
			expect(client_connection.reader).to be_a(Protocol::WebSocket::Extension::Compression::Inflate)
			expect(server_connection.writer).to be_a(Protocol::WebSocket::Extension::Compression::Deflate)
			expect(server_connection.reader).to be_a(Protocol::WebSocket::Extension::Compression::Inflate)
			
			client_connection.send_text("Hello World")
			client_connection.flush
			
			expect(server_connection.read).to be == "Hello World"
			
			server_connection.send_text("Hello Client")
			server_connection.flush
			
			expect(client_connection.read).to be == "Hello Client"
		end
	end
end
