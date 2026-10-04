# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.
# Copyright, 2026, by William T. Nelson.

require_relative "extension/compression"
require_relative "extension/plan"
require_relative "headers"

module Protocol
	module WebSocket
		# Manages WebSocket extensions negotiated during the handshake.
		module Extensions
			# Parse a list of extension header values into name and argument pairs.
			# @parameter headers [Array(String)] The raw extension header values.
			# @yields {|name, arguments| ...} Each parsed extension.
			# 	@parameter name [String] The name of the extension.
			# 	@parameter arguments [Array] The key-value argument pairs.
			def self.parse(headers)
				return to_enum(:parse, headers) unless block_given?
				
				headers.each do |header|
					name, *arguments = header.split(/\s*;\s*/)
					
					arguments = arguments.map do |argument|
						argument.split("=", 2)
					end
					
					yield name, arguments
				end
			end
			
			# Manages extensions on the client side, offering and accepting server responses.
			class Client
				# Create a default client with permessage-deflate compression enabled.
				# @returns [Client] A new client with the default compression extension.
				def self.default
					self.new([
						[Extension::Compression, {}]
					])
				end
				
				# Initialize a new client extension manager.
				# @parameter extensions [Array] The list of extensions to offer, each as `[klass, options]`.
				def initialize(extensions = [])
					@extensions = extensions
					@plan = Extension::Plan.new(:client)
				end
				
				# @attribute [Array] The list of extensions to offer.
				attr :extensions
				
				# @attribute [Extension::Plan] The negotiation plan built while accepting the server response.
				attr :plan
				
				# The extensions accepted after negotiation, as `[klass, options]` pairs.
				# @returns [Array(Array(Module, Hash))]
				def accepted
					@plan.to_a
				end
				
				# Build a lookup table of extensions keyed by their name.
				# @returns [Hash] A hash mapping extension names to their `[klass, options]` pairs.
				def named
					@extensions.map do |extension|
						[extension.first::NAME, extension]
					end.to_h
				end
				
				# Yield extension offer headers for each registered extension.
				# @yields {|header| ...} Each offer header string.
				# 	@parameter header [Array(String)] The extension offer header tokens.
				def offer
					@extensions.each do |extension, options|
						if header = extension.offer(**options)
							yield header
						end
					end
				end
				
				# Accept server extension responses and build the negotiation plan.
				#
				# The server may only accept extensions that were offered, may only accept each extension once, and the negotiated parameters are validated by the extension. Two accepted extensions contending for the same reserved frame bit is also rejected.
				#
				# @parameter headers [Array(String)] The `Sec-WebSocket-Extensions` response header values.
				# @raises [NegotiationError] If an unoffered or duplicate extension is accepted, or reserved bits conflict.
				# @returns [Extension::Plan] The complete negotiation plan.
				def accept(headers)
					available = self.named
					offered_names = available.keys
					plan = Extension::Plan.new(:client)
					
					Extensions.parse(headers) do |name, arguments|
						extension = available.delete(name)
						
						if extension.nil?
							if offered_names.include?(name)
								raise NegotiationError, "Server accepted extension #{name.inspect} more than once!"
							else
								raise NegotiationError, "Server accepted extension #{name.inspect} which was not offered!"
							end
						end
						
						klass, options = extension
						options = klass.accept(arguments, **options)
						
						plan.add(klass, options)
					end
					
					@plan = plan
					
					return @plan
				end
				
				# Apply the negotiated plan to the given connection as a client.
				# @parameter connection [Connection] The WebSocket connection to configure.
				def apply(connection)
					@plan.apply(connection)
				end
			end
			
			# Manages extensions on the server side, negotiating client offers and applying the agreed extensions.
			class Server
				# Create a default server with permessage-deflate compression enabled.
				# @returns [Server] A new server with the default compression extension.
				def self.default
					self.new([
						[Extension::Compression, {}]
					])
				end
				
				# Initialize a new server extension manager.
				# @parameter extensions [Array] The list of supported extensions, each as `[klass, options]`.
				def initialize(extensions)
					@extensions = extensions
					@plan = Extension::Plan.new(:server)
				end
				
				# @attribute [Array] The list of supported extensions.
				attr :extensions
				
				# @attribute [Extension::Plan] The negotiation plan built while accepting client offers.
				attr :plan
				
				# The extensions accepted after negotiation, as `[klass, options]` pairs.
				# @returns [Array(Array(Module, Hash))]
				def accepted
					@plan.to_a
				end
				
				# Build a lookup table of extensions keyed by their name.
				# @returns [Hash] A hash mapping extension names to their `[klass, options]` pairs.
				def named
					@extensions.map do |extension|
						[extension.first::NAME, extension]
					end.to_h
				end
				
				# Negotiate client extension offers and build the negotiation plan.
				#
				# Each supported extension is accepted at most once, negotiated parameters are validated by the extension, and two accepted extensions contending for the same reserved frame bit is rejected.
				#
				# @parameter headers [Array(String)] The `Sec-WebSocket-Extensions` request header values.
				# @yields {|header| ...} Each accepted extension header to include in the response.
				# 	@parameter header [Array(String)] The negotiated extension header tokens.
				# @raises [NegotiationError] If an extension is offered twice or two accepted extensions contend for the same reserved frame bit.
				# @returns [Extension::Plan] The complete negotiation plan.
				def accept(headers)
					supported = self.named
					selected = {}
					plan = Extension::Plan.new(:server)
					
					Extensions.parse(headers) do |name, arguments|
						extension = supported[name]
						
						if extension.nil?
							if selected.key?(name)
								raise NegotiationError, "Extension #{name.inspect} was offered more than once!"
							end
							
							# The extension is unknown to this server, so ignore the offer:
							next
						end
						
						klass, options = extension
						
						if result = klass.negotiate(arguments, **options)
							header, options = result
							
							# Record the selection first: this raises a clear error if the extension contends for a reserved bit already in use:
							entry = plan.add(klass, options, header)
							
							# The extension is accepted and no further offers will be considered:
							supported.delete(name)
							selected[name] = entry
							
							yield entry.header if block_given?
						end
					end
					
					@plan = plan
					
					return @plan
				end
				
				# Apply the negotiated plan to the given connection as a server.
				# @parameter connection [Connection] The WebSocket connection to configure.
				def apply(connection)
					@plan.apply(connection)
				end
			end
		end
	end
end
