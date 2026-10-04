# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "../frame"

module Protocol
	module WebSocket
		module Extension
			# Represents a single extension selected during negotiation.
			class Entry
				# Create a new plan entry.
				# @parameter extension [Module] The selected extension module.
				# @parameter options [Hash] The final negotiated extension parameters.
				# @parameter reserved_bits [Integer] The reserved frame bits claimed by the extension.
				# @parameter header [Array(String) | Nil] The negotiated header tokens sent back to the remote end, if any.
				def initialize(extension, options, reserved_bits, header = nil)
					@extension = extension
					@options = options
					@reserved_bits = reserved_bits
					@header = header
				end
				
				# @attribute [Module] The selected extension module.
				attr :extension
				
				# @attribute [Hash] The final negotiated extension parameters.
				attr :options
				
				# @attribute [Integer] The reserved frame bits claimed by the extension.
				attr :reserved_bits
				
				# @attribute [Array(String) | Nil] The negotiated header tokens sent back to the remote end, if any.
				attr :header
				
				# Convert the entry into a `[klass, options]` pair for backwards compatibility.
				# @returns [Array(Module, Hash)] The extension module and its negotiated parameters.
				def to_ary
					[@extension, @options]
				end
				
				# @returns [String] A human readable representation of the entry.
				def to_s
					"#{extension_name}(#{@options.map { |key, value| "#{key}=#{value}" }.join("; ")})"
				end
				
				private
				
				def extension_name
					@extension.const_get(:NAME)
				rescue NameError
					@extension.name || @extension.inspect
				end
			end
			
			# Holds the complete result of extension negotiation before anything is installed on a connection.
			#
			# A plan records which extensions were selected, their final parameters, the reserved frame bits they claim and the order of the read/write transformations. Installing a plan either applies every extension or leaves the connection untouched.
			class Plan
				# Construct a new empty negotiation plan.
				# @parameter role [Symbol] Whether the plan is installed for a `:client` or a `:server`.
				def initialize(role)
					@role = role
					@entries = []
					
					# Reserved bits already assigned to earlier extensions:
					@reserved_bits = 0
				end
				
				# @attribute [Symbol] The role (`:client` or `:server`) the plan is installed for.
				attr :role
				
				# @attribute [Array(Entry)] The selected extensions in negotiation order.
				attr :entries
				
				# @returns [Boolean] Whether no extensions were selected.
				def empty?
					@entries.empty?
				end
				
				# @returns [Array(Module)] The selected extension modules in negotiation order.
				def extensions
					@entries.map(&:extension)
				end
				
				# The reserved frame bits claimed by every selected extension.
				# @returns [Integer] The combined reserved bit mask.
				attr :reserved_bits
				
				# The entries in negotiation order. The first selected extension is outermost on the wire, so it is installed as the outermost reader and decodes incoming frames first.
				# @returns [Array(Entry)] The reader transformation order.
				def readers
					@entries
				end
				
				# The entries in negotiation order. The first selected extension is outermost on the wire; locally it is the outermost writer and encodes last, after the inner extensions have encoded first.
				# @returns [Array(Entry)] The writer entries in wire order.
				def writers
					@entries
				end
				
				# Record a selected extension.
				#
				# Raises {NegotiationError} if the extension contends for a reserved frame bit already claimed by an earlier extension.
				#
				# @parameter extension [Module] The selected extension module.
				# @parameter options [Hash] The final negotiated extension parameters.
				# @parameter header [Array(String) | Nil] The negotiated header tokens sent back to the remote end, if any.
				# @returns [Entry] The newly recorded plan entry.
				def add(extension, options, header = nil)
					requested_bits = reserved_bits_of(extension)
					
					unless (requested_bits & @reserved_bits).zero?
						raise NegotiationError, "Extension #{name_of(extension)} contends for reserved frame bit #{bit_name(requested_bits & @reserved_bits)} already used by another extension!"
					end
					
					entry = Entry.new(extension, options, requested_bits, header)
					
					@entries << entry
					@reserved_bits |= requested_bits
					
					return entry
				end
				
				# Install every selected extension onto the given connection.
				#
				# All reader/writer transformations are constructed before the connection is touched, so a failure in any extension cannot leave the connection with a half replaced reader or writer. Reserved bits are likewise pre-checked before the connection is modified.
				#
				# @parameter connection [Connection] The WebSocket connection to configure.
				def apply(connection)
					return if @entries.empty?
					
					# Validate that every required reserved bit is available before mutating the connection:
					available_bits = connection.reserved
					@entries.each do |entry|
						unless (entry.reserved_bits & available_bits) == entry.reserved_bits
							used_bits = entry.reserved_bits & ~available_bits
							raise ExtensionError, "Extension #{name_of(entry.extension)} cannot use reserved frame bit #{bit_name(used_bits)}!"
						end
					end
					
					# Construct the complete transformation chains before touching the connection:
					reader = build_reader_chain(connection)
					writer = build_writer_chain(connection)
					
					# Commit the reserved bits. The pre-check above guarantees these calls succeed:
					[Frame::RSV1, Frame::RSV2, Frame::RSV3].each do |bit|
						connection.reserve!(bit) unless (@reserved_bits & bit).zero?
					end
					
					# Atomically replace the reader and writer:
					connection.reader = reader
					connection.writer = writer
				end
				
				# Convert the plan into the legacy list of accepted `[klass, options]` pairs.
				# @returns [Array(Array(Module, Hash))] The accepted extensions.
				def to_a
					@entries.map(&:to_ary)
				end
				
				# @returns [String] A human readable representation of the plan.
				def to_s
					"Plan(#{@role}): #{@entries.map(&:to_s).join(", ")} [read: #{readers.map { |entry| name_of(entry.extension) }.join(" -> ")}; write: #{writers.map { |entry| name_of(entry.extension) }.join(" -> ")}]"
				end
				
				private
				
				def reserved_bits_of(extension)
					extension.const_get(:RESERVED_BITS)
				rescue NameError
					0
				end
				
				def name_of(extension)
					extension.const_get(:NAME)
				rescue NameError
					extension.name || extension.inspect
				end
				
				def bit_name(bits)
					names = []
					names << "RSV1" unless (bits & Frame::RSV1).zero?
					names << "RSV2" unless (bits & Frame::RSV2).zero?
					names << "RSV3" unless (bits & Frame::RSV3).zero?
					names.join("|")
				end
				
				# Build the reader chain. The first selected extension is outermost on the wire and decodes first. Both peers build the same chain for the same negotiation order, so they interoperate.
				def build_reader_chain(connection)
					parent = connection
					
					# Wrap in reverse negotiation order so the first selected extension ends up outermost and decodes first:
					@entries.reverse_each do |entry|
						parent = install_reader(entry, parent)
					end
					
					return parent
				end
				
				# Build the writer chain. The first selected extension is outermost on the wire for both peers; it is installed around the others and encodes last when a message is sent.
				def build_writer_chain(connection)
					parent = connection
					
					# Wrap in reverse negotiation order so the first selected extension ends up outermost and encodes last:
					@entries.reverse_each do |entry|
						parent = install_writer(entry, parent)
					end
					
					return parent
				end
				
				def install_reader(entry, parent)
					if @role == :client
						entry.extension.client_reader(parent, **entry.options)
					else
						entry.extension.server_reader(parent, **entry.options)
					end
				end
				
				def install_writer(entry, parent)
					if @role == :client
						entry.extension.client_writer(parent, **entry.options)
					else
						entry.extension.server_writer(parent, **entry.options)
					end
				end
			end
		end
	end
end
