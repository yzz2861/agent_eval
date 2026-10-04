# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "../error"
require_relative "../frame"

module Protocol
	module WebSocket
		module Extensions
			# Raised when extension negotiation fails, e.g. an extension was accepted
			# that was never offered, or two extensions tried to reserve the same
			# frame bit.
			class NegotiationError < ProtocolError
			end
			
			# A complete, inspectable record of an extension negotiation: the selected
			# extensions, their parameters, the reserved frame bits they claim, and the
			# order in which they transform the reader/writer. The plan is validated as
			# it is built, and can be installed onto a connection atomically: if any
			# extension fails to install, the connection is restored to its previous
			# state.
			class Plan
				# A single negotiated extension within a plan.
				class Entry
					def initialize(extension, options, bits)
						@extension = extension
						@options = options
						@bits = bits
					end
					
					# @attribute [Module] The extension module.
					attr :extension
					
					# @attribute [Hash] The negotiated parameters.
					attr :options
					
					# @attribute [Integer] The reserved frame bits claimed by this extension.
					attr :bits
					
					# The name of the extension.
					def name
						@extension::NAME
					end
				end
				
				# Human readable names for the reserved frame bits.
				BIT_NAMES = {
					Frame::RSV1 => "RSV1",
					Frame::RSV2 => "RSV2",
					Frame::RSV3 => "RSV3",
				}.freeze
				
				# @parameter role [Symbol] How the extensions are installed, e.g. `:client` or `:server`.
				def initialize(role)
					@role = role
					@entries = []
					@reserved = 0
				end
				
				# @attribute [Symbol] The role this plan applies to.
				attr :role
				
				# @attribute [Array(Entry)] The selected extensions, in transform order.
				attr :entries
				
				# @attribute [Integer] The reserved frame bits claimed by all extensions in the plan.
				attr :reserved
				
				# The names of the selected extensions, in transform order.
				# @returns [Array(String)]
				def names
					@entries.map(&:name)
				end
				
				# Add a negotiated extension to the plan.
				# @parameter extension [Module] The extension module.
				# @parameter options [Hash] The negotiated parameters.
				# @returns [Entry] The recorded entry.
				def add(extension, options)
					bits = bits_for(extension, options)
					
					if conflict = @entries.find{|entry| (entry.bits & bits) != 0}
						raise NegotiationError, "Extension #{extension::NAME} cannot reserve #{self.class.bit_names(conflict.bits & bits)}: already reserved by #{conflict.name}!"
					end
					
					entry = Entry.new(extension, options, bits)
					
					@entries << entry
					@reserved |= bits
					
					return entry
				end
				
				# Install the plan onto a connection. If any extension fails to install,
				# the connection is restored to its previous state: no extension is left
				# partially applied.
				# @parameter connection [Connection] The connection to configure.
				def install(connection)
					reader = connection.reader
					writer = connection.writer
					reserved = connection.reserved
					
					@entries.each do |entry|
						entry.extension.public_send(@role, connection, **entry.options)
					end
				rescue Exception
					connection.reader = reader
					connection.writer = writer
					connection.reserved = reserved
					
					raise
				end
				
				# Format reserved bits as human readable names.
				# @parameter bits [Integer] The bitmask of reserved frame bits.
				# @returns [String] The names of the reserved bits, e.g. `"RSV1"`.
				def self.bit_names(bits)
					BIT_NAMES.filter_map{|bit, name| name if (bits & bit) != 0}.join("|")
				end
				
				private
				
				# The reserved frame bits claimed by an extension, if declared.
				def bits_for(extension, options)
					if extension.respond_to?(:reserved_bits)
						extension.reserved_bits(**options)
					else
						0
					end
				end
			end
		end
	end
end
