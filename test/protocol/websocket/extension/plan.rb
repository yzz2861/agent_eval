# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "socket"

require "protocol/websocket/extensions"
require "protocol/websocket/connection"

# Base transformation used by the fake extensions below. Writers prefix outgoing payloads, readers strip the prefix from incoming payloads.
class FakeExtensionTransform
	def initialize(parent, prefix)
		@parent = parent
		@prefix = prefix
	end
	
	attr :parent
	attr :prefix
end

class FakeReader < FakeExtensionTransform
	FLAG = Protocol::WebSocket::Frame::RSV2
	
	def unpack_frames(frames, **options)
		buffer = @parent.unpack_frames(frames, **options)
		
		frame = frames.first
		if frame.flag?(FLAG)
			raise RuntimeError, "Missing prefix #{@prefix.inspect}!" unless buffer.start_with?(@prefix)
			buffer = buffer.byteslice(@prefix.bytesize, buffer.bytesize - @prefix.bytesize)
			frame.flags &= ~FLAG
		end
		
		return buffer
	end
end

class FakeWriter < FakeExtensionTransform
	FLAG = Protocol::WebSocket::Frame::RSV2
	
	def pack_text_frame(buffer, **options)
		frame = @parent.pack_text_frame(@prefix + buffer, **options)
		frame.flags |= FLAG
		return frame
	end
	
	def pack_binary_frame(buffer, **options)
		frame = @parent.pack_binary_frame(@prefix + buffer, **options)
		frame.flags |= FLAG
		return frame
	end
end

# A minimal extension which negotiates a string prefix parameter and marks transformed frames with RSV2.
module FakeExtension
	NAME = "fake-extension"
	RESERVED_BITS = Protocol::WebSocket::Frame::RSV2
	
	VALID_PREFIX = /\A[a-z]+\z/
	
	def self.offer(prefix: "alpha", **options)
		[NAME, "prefix=#{prefix}"]
	end
	
	def self.validate(arguments, options)
		arguments.each do |key, value|
			case key
			when "prefix"
				unless value =~ VALID_PREFIX
					raise Protocol::WebSocket::NegotiationError, "Extension #{NAME} parameter prefix=#{value.inspect} is out of bounds!"
				end
				options[:prefix] = value
			else
				raise ArgumentError, "Unknown option: #{key}!"
			end
		end
		
		return options
	end
	
	def self.negotiate(arguments, **options)
		options = validate(arguments, options)
		
		return [NAME, "prefix=#{options.fetch(:prefix, "alpha")}"], options
	end
	
	def self.accept(arguments, **options)
		return validate(arguments, options)
	end
	
	def self.reader(parent, options, default_prefix)
		FakeReader.new(parent, options.fetch(:prefix, default_prefix))
	end
	
	def self.writer(parent, options, default_prefix)
		FakeWriter.new(parent, options.fetch(:prefix, default_prefix))
	end
	
	def self.server_reader(parent, **options)
		reader(parent, options, "alpha")
	end
	
	def self.server_writer(parent, **options)
		writer(parent, options, "alpha")
	end
	
	def self.client_reader(parent, **options)
		reader(parent, options, "alpha")
	end
	
	def self.client_writer(parent, **options)
		writer(parent, options, "alpha")
	end
end

# A second extension contending for the same reserved frame bit as FakeExtension.
module ConflictingExtension
	NAME = "conflicting-extension"
	RESERVED_BITS = Protocol::WebSocket::Frame::RSV2
	
	def self.offer(**options)
		[NAME]
	end
	
	def self.negotiate(arguments, **options)
		return [NAME], options
	end
	
	def self.accept(arguments, **options)
		return options
	end
	
	def self.server_reader(parent, **options)
		FakeReader.new(parent, "conflict")
	end
	
	def self.server_writer(parent, **options)
		FakeWriter.new(parent, "conflict")
	end
	
	def self.client_reader(parent, **options)
		FakeReader.new(parent, "conflict")
	end
	
	def self.client_writer(parent, **options)
		FakeWriter.new(parent, "conflict")
	end
end

# An extension whose writer always fails while being constructed.
module BrokenWriterExtension
	NAME = "broken-writer-extension"
	RESERVED_BITS = Protocol::WebSocket::Frame::RSV3
	
	class BrokenWriter
		def initialize(parent, **options)
			raise RuntimeError, "Writer construction failed!"
		end
	end
	
	def self.offer(**options)
		[NAME]
	end
	
	def self.negotiate(arguments, **options)
		return [NAME], options
	end
	
	def self.accept(arguments, **options)
		return options
	end
	
	def self.server_reader(parent, **options)
		FakeReader.new(parent, "broken")
	end
	
	def self.server_writer(parent, **options)
		BrokenWriter.new(parent, **options)
	end
	
	def self.client_reader(parent, **options)
		FakeReader.new(parent, "broken")
	end
	
	def self.client_writer(parent, **options)
		BrokenWriter.new(parent, **options)
	end
end

describe Protocol::WebSocket::Extension::Compression do
	with ".window_bits" do
		it "clamps values below the zlib minimum to 9" do
			expect(subject.window_bits(8, "client_max_window_bits")).to be == 9
			expect(subject.window_bits("8", "client_max_window_bits")).to be == 9
		end
		
		it "accepts values within the valid range" do
			expect(subject.window_bits(9, "server_max_window_bits")).to be == 9
			expect(subject.window_bits(15, "server_max_window_bits")).to be == 15
		end
		
		it "rejects values outside the protocol range" do
			expect do
				subject.window_bits(20, "server_max_window_bits")
		end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /out of bounds/)
			
			expect do
				subject.window_bits(7, "server_max_window_bits")
		end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /out of bounds/)
		end
	end
	
	with ".negotiate" do
		it "clamps window bits below the zlib minimum in the response header" do
			header, options = subject.negotiate([["client_max_window_bits", "8"]])
			
			expect(options[:client_max_window_bits]).to be == 9
			expect(header).to be == ["permessage-deflate", "client_max_window_bits=9"]
		end
	end
end

describe Protocol::WebSocket::Extension::Plan do
	let(:framer_pair) do
		sockets = Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)
		[
			Protocol::WebSocket::Framer.new(sockets.first),
			Protocol::WebSocket::Framer.new(sockets.last)
		]
	end
	
	with "client negotiation" do
		let(:client) {Protocol::WebSocket::Extensions::Client.new([[FakeExtension, prefix: "alpha"], [ConflictingExtension, {}]])}
		
		it "builds a complete inspectable plan before modifying a connection" do
			plan = client.accept(["fake-extension; prefix=beta"])
			
			expect(plan).to be_a(subject)
			expect(plan.role).to be == :client
			expect(plan.entries.map(&:extension)).to be == [FakeExtension]
			expect(plan.entries.first.options).to be == {prefix: "beta"}
			expect(plan.entries.first.reserved_bits).to be == Protocol::WebSocket::Frame::RSV2
			expect(plan.reserved_bits).to be == Protocol::WebSocket::Frame::RSV2
			
			expect(client.accepted).to be == [[FakeExtension, {prefix: "beta"}]]
		end
		
		it "records the read and write transformation order" do
			other = Module.new
			def other.const_get(name)
				case name
				when :NAME then "other-extension"
				when :RESERVED_BITS then Protocol::WebSocket::Frame::RSV3
				else super
				end
			end
			
			plan = subject.new(:client)
			plan.add(FakeExtension, {})
			plan.add(other, {})
			
			expect(plan.readers.map(&:extension)).to be == [FakeExtension, other]
			expect(plan.writers.map(&:extension)).to be == [FakeExtension, other]
			expect(plan.to_s).to be =~ /read: fake-extension -> other-extension/
			expect(plan.to_s).to be =~ /write: fake-extension -> other-extension/
		end
		
		it "rejects an extension that was not offered" do
			expect do
				client.accept(["unknown-extension"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /not offered/)
		end
		
		it "rejects a duplicate selection of the same extension" do
			expect do
				client.accept(["fake-extension; prefix=alpha", "fake-extension; prefix=beta"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /more than once/)
		end
		
		it "rejects out of bounds parameters" do
			expect do
				client.accept(["fake-extension; prefix=INVALID"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /out of bounds/)
		end
		
		it "rejects out of bounds permessage-deflate window bits" do
			deflate_client = Protocol::WebSocket::Extensions::Client.new([
				[Protocol::WebSocket::Extension::Compression, {}]
			])
			
			expect do
				deflate_client.accept(["permessage-deflate; server_max_window_bits=20"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /out of bounds/)
		end
	end
	
	with "server negotiation" do
		let(:server) {Protocol::WebSocket::Extensions::Server.new([[FakeExtension, {}], [ConflictingExtension, {}]])}
		
		it "builds a plan and yields the negotiated response header" do
			headers = []
			plan = server.accept(["fake-extension; prefix=beta"]) do |header|
				headers << header
			end
			
			expect(headers).to be == [["fake-extension", "prefix=beta"]]
			expect(plan.entries.map(&:extension)).to be == [FakeExtension]
			expect(plan.entries.first.options).to be == {prefix: "beta"}
			expect(plan.entries.first.reserved_bits).to be == Protocol::WebSocket::Frame::RSV2
		end
		
		it "ignores unknown extensions" do
			plan = server.accept(["unknown-extension", "fake-extension; prefix=beta"])
			
			expect(plan.extensions).to be == [FakeExtension]
		end
		
		it "rejects a duplicated offer of the same extension" do
			expect do
				server.accept(["fake-extension; prefix=alpha", "fake-extension; prefix=beta"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /more than once/)
		end
		
		it "rejects two extensions contending for the same reserved bit" do
			expect do
				server.accept(["fake-extension; prefix=alpha", "conflicting-extension"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /contends for reserved frame bit/)
		end
		
		it "rejects out of bounds parameters" do
			expect do
				server.accept(["fake-extension; prefix=9"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /out of bounds/)
		end
		
		it "rejects out of bounds permessage-deflate window bits" do
			deflate_server = Protocol::WebSocket::Extensions::Server.new([
				[Protocol::WebSocket::Extension::Compression, {}]
			])
			
			expect do
				deflate_server.accept(["permessage-deflate; server_max_window_bits=20"])
			end.to raise_exception(Protocol::WebSocket::NegotiationError, message: be =~ /out of bounds/)
		end
	end
	
	with "installation" do
		let(:server_framer) {framer_pair.last}
		let(:connection) {Protocol::WebSocket::Connection.new(server_framer)}
		
		it "does not leave a half replaced reader or writer when an extension fails" do
			plan = subject.new(:server)
			plan.add(BrokenWriterExtension, {})
			
			original_reader = connection.reader
			original_writer = connection.writer
			original_reserved = connection.reserved
			
			expect do
				plan.apply(connection)
			end.to raise_exception(RuntimeError, message: be =~ /Writer construction failed/)
			
			expect(connection.reader).to be_equal(original_reader)
			expect(connection.writer).to be_equal(original_writer)
			expect(connection.reserved).to be == original_reserved
		end
		
		it "applies a single extension and reserves its bits" do
			plan = subject.new(:server)
			plan.add(FakeExtension, {prefix: "beta"})
			
			plan.apply(connection)
			
			expect(connection.reader).to be_a(FakeReader)
			expect(connection.writer).to be_a(FakeWriter)
			expect(connection.reader.prefix).to be == "beta"
			expect(connection.writer.prefix).to be == "beta"
			expect(connection.reserved & Protocol::WebSocket::Frame::RSV2).to be(:zero?)
		end
		
		it "rejects extensions contending for a bit already used on the connection" do
			connection.reserve!(Protocol::WebSocket::Frame::RSV2)
			
			plan = subject.new(:server)
			plan.add(FakeExtension, {})
			
			expect do
				plan.apply(connection)
			end.to raise_exception(Protocol::WebSocket::ExtensionError, message: be =~ /cannot use reserved frame bit/)
			
			expect(connection.reader).not.to be_a(FakeReader)
			expect(connection.writer).not.to be_a(FakeWriter)
		end
		
		it "nests the transformations in the negotiated order" do
			other_reader = Class.new do
				def initialize(parent)
					@parent = parent
				end
				
				attr_reader :parent
				
				def unpack_frames(frames, **options)
					@parent.unpack_frames(frames, **options)
				end
			end
			
			other_writer = Class.new do
				def initialize(parent)
					@parent = parent
				end
				
				attr_reader :parent
				
				def pack_text_frame(buffer, **options)
					@parent.pack_text_frame(buffer, **options)
				end
				
				def pack_binary_frame(buffer, **options)
					@parent.pack_binary_frame(buffer, **options)
				end
			end
			
			extension = Module.new
			extension.const_set(:NAME, "other-extension")
			extension.const_set(:RESERVED_BITS, Protocol::WebSocket::Frame::RSV3)
			extension.define_singleton_method(:server_reader) { |parent, **| other_reader.new(parent) }
			extension.define_singleton_method(:server_writer) { |parent, **| other_writer.new(parent) }
			extension.define_singleton_method(:client_reader) { |parent, **| other_reader.new(parent) }
			extension.define_singleton_method(:client_writer) { |parent, **| other_writer.new(parent) }
			
			plan = subject.new(:server)
			plan.add(FakeExtension, {})
			plan.add(extension, {})
			
			plan.apply(connection)
			
			# Reading: the first negotiated extension is outermost on the wire and decodes first:
			expect(connection.reader).to be_a(FakeReader)
			expect(connection.reader.parent).to be_a(other_reader)
			expect(connection.reader.parent.parent).to be_equal(connection)
			
			# Writing: the first negotiated extension is outermost and encodes last, the later extension is inner and encodes first:
			expect(connection.writer).to be_a(FakeWriter)
			expect(connection.writer.parent).to be_a(other_writer)
			expect(connection.writer.parent.parent).to be_equal(connection)
		end
	end
	
	with "permessage-deflate interoperability" do
		it "can negotiate and round-trip fake extensions in matching order over a socket pair" do
			client_framer, server_framer = framer_pair
			
			other_reader_class = Class.new do
				def initialize(parent)
					@parent = parent
				end
				
				def unpack_frames(frames, **options)
					buffer = @parent.unpack_frames(frames, **options)
					frame = frames.first
					if frame.flag?(Protocol::WebSocket::Frame::RSV3)
						raise RuntimeError, "missing zeta!" unless buffer.start_with?("zeta")
						buffer = buffer.byteslice(4, buffer.bytesize - 4)
						frame.flags &= ~Protocol::WebSocket::Frame::RSV3
					end
					return buffer
				end
			end
			
			other_writer_class = Class.new do
				def initialize(parent)
					@parent = parent
				end
				
				def pack_text_frame(buffer, **options)
					frame = @parent.pack_text_frame("zeta" + buffer, **options)
					frame.flags |= Protocol::WebSocket::Frame::RSV3
					return frame
				end
				
				def pack_binary_frame(buffer, **options)
					frame = @parent.pack_binary_frame("zeta" + buffer, **options)
					frame.flags |= Protocol::WebSocket::Frame::RSV3
					return frame
				end
			end
			
			extension = Module.new
			extension.const_set(:NAME, "other-extension")
			extension.const_set(:RESERVED_BITS, Protocol::WebSocket::Frame::RSV3)
			extension.define_singleton_method(:offer) { |**| ["other-extension"] }
			extension.define_singleton_method(:negotiate) { |arguments, **options| [ ["other-extension"], options ] }
			extension.define_singleton_method(:accept) { |arguments, **options| options }
			extension.define_singleton_method(:server_reader) { |parent, **| other_reader_class.new(parent) }
			extension.define_singleton_method(:server_writer) { |parent, **| other_writer_class.new(parent) }
			extension.define_singleton_method(:client_reader) { |parent, **| other_reader_class.new(parent) }
			extension.define_singleton_method(:client_writer) { |parent, **| other_writer_class.new(parent) }
			
			client_extensions = Protocol::WebSocket::Extensions::Client.new([
				[FakeExtension, {prefix: "alpha"}],
				[extension, {}]
			])
			server_extensions = Protocol::WebSocket::Extensions::Server.new([
				[FakeExtension, {}],
				[extension, {}]
			])
			
			offers = []
			client_extensions.offer { |header| offers << header.join("; ") }
			server_headers = []
			server_extensions.accept(offers) { |header| server_headers << header.join("; ") }
			client_extensions.accept(server_headers)
			
			client_connection = Protocol::WebSocket::Connection.new(client_framer)
			server_connection = Protocol::WebSocket::Connection.new(server_framer)
			client_extensions.apply(client_connection)
			server_extensions.apply(server_connection)
			
			message = "hello nested extensions"
			
			client_connection.send_text(message)
			client_connection.flush
			expect(server_connection.read).to be == message
			
			server_connection.send_text(message)
			server_connection.flush
			expect(client_connection.read).to be == message
		end
		
		it "can negotiate and round-trip messages over a socket pair" do
			client_framer, server_framer = framer_pair
			
			client_extensions = Protocol::WebSocket::Extensions::Client.default
			offers = []
			client_extensions.offer { |header| offers << header.join("; ") }
			
			server_extensions = Protocol::WebSocket::Extensions::Server.default
			server_headers = []
			server_extensions.accept(offers) { |header| server_headers << header.join("; ") }
			
			client_extensions.accept(server_headers)
			
			client_connection = Protocol::WebSocket::Connection.new(client_framer)
			server_connection = Protocol::WebSocket::Connection.new(server_framer)
			
			client_extensions.apply(client_connection)
			server_extensions.apply(server_connection)
			
			expect(client_connection.writer).to be_a(Protocol::WebSocket::Extension::Compression::Deflate)
			expect(client_connection.reader).to be_a(Protocol::WebSocket::Extension::Compression::Inflate)
			expect(server_connection.writer).to be_a(Protocol::WebSocket::Extension::Compression::Deflate)
			expect(server_connection.reader).to be_a(Protocol::WebSocket::Extension::Compression::Inflate)
			
			message = "Hello World" * 10
			
			client_connection.send_text(message)
			client_connection.flush
			expect(server_connection.read).to be == message
			
			server_connection.send_text(message)
			server_connection.flush
			expect(client_connection.read).to be == message
		end
		
		it "clamps window bits below the zlib minimum on both sides" do
			client_extensions = Protocol::WebSocket::Extensions::Client.new([
				[Protocol::WebSocket::Extension::Compression, {client_max_window_bits: 8, server_max_window_bits: 8}]
			])
			offers = []
			client_extensions.offer { |header| offers << header.join("; ") }
			
			server_extensions = Protocol::WebSocket::Extensions::Server.default
			headers = []
			server_extensions.accept(offers) { |header| headers << header.join("; ") }
			
			client_extensions.accept(headers)
			
			options = client_extensions.plan.entries.first.options
			expect(options[:client_max_window_bits]).to be == 9
			expect(options[:server_max_window_bits]).to be == 9
		end
	end
end
