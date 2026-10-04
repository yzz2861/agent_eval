# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.

require_relative "compression/constants"
require_relative "compression/inflate"
require_relative "compression/deflate"

module Protocol
	module WebSocket
		# @namespace
		module Extension
			# Provides support for the permessage-deflate extension.
			module Compression
				# Client offer to server, construct a list of requested compression parameters suitable for the `Sec-WebSocket-Extensions` header.
				# @returns [Array(String)] a list of compression parameters suitable to send to the server.
				def self.offer(client_max_window_bits: true, server_max_window_bits: true, client_no_context_takeover: false, server_no_context_takeover: false)
					header = [NAME]
					
					case client_max_window_bits
					when 8..15
						header << "client_max_window_bits=#{client_max_window_bits}"
					when true
						header << "client_max_window_bits"
					else
						raise ArgumentError, "Invalid local maximum window bits!"
					end
					
					if client_no_context_takeover
						header << "client_no_context_takeover"
					end
					
					case server_max_window_bits
					when 8..15
						header << "server_max_window_bits=#{server_max_window_bits}"
					when true
						# Default (unspecified) to the server maximum window bits.
					else
						raise ArgumentError, "Invalid remote maximum window bits!"
					end
					
					if server_no_context_takeover
						header << "server_no_context_takeover"
					end
					
					return header
				end
				
				# Negotiate on the server a response to client based on the incoming client offer.
				# @parameter options [Hash] a hash of options which are accepted by the server.
				# @returns [Array(String)] a list of compression parameters suitable to send back to the client.
				def self.negotiate(arguments, **options)
					header = [NAME]
					
					arguments.each do |key, value|
						case key
						when "server_no_context_takeover"
							options[:server_no_context_takeover] = true
							header << key
						when "client_no_context_takeover"
							options[:client_no_context_takeover] = true
							header << key
						when "server_max_window_bits"
							value = self.window_bits(value, "server_max_window_bits")
							options[:server_max_window_bits] = value
							header << "server_max_window_bits=#{value}"
						when "client_max_window_bits"
							value = self.window_bits(value, "client_max_window_bits")
							options[:client_max_window_bits] = value
							header << "client_max_window_bits=#{value}"
						else
							raise ArgumentError, "Unknown option: #{key}!"
						end
					end
					
					# The header which represents the final accepted/negotiated configuration.
					return header, options
				end
				
				# Accept on the client, the negotiated server response.
				# @parameter options [Hash] a hash of options which are accepted by the client.
				# @parameter arguments [Array(String)] a list of compression parameters as accepted/negotiated by the server.
				def self.accept(arguments, **options)
					arguments.each do |key, value|
						case key
						when "server_no_context_takeover"
							options[:server_no_context_takeover] = true
						when "client_no_context_takeover"
							options[:client_no_context_takeover] = true
						when "server_max_window_bits"
							options[:server_max_window_bits] = self.window_bits(value, "server_max_window_bits")
						when "client_max_window_bits"
							options[:client_max_window_bits] = self.window_bits(value, "client_max_window_bits")
						else
							raise ArgumentError, "Unknown option: #{key}!"
						end
					end
					
					return options
				end
				
				# Build the server side reader (inflates messages sent by the client).
				# @parameter parent [Object] The parent reader to wrap.
				# @parameter options [Hash] The negotiated extension parameters.
				# @returns [Inflate] The inflate reader.
				def self.server_reader(parent, **options)
					Inflate.server(parent, **options)
				end
				
				# Build the server side writer (deflates messages sent to the client).
				# @parameter parent [Object] The parent writer to wrap.
				# @parameter options [Hash] The negotiated extension parameters.
				# @returns [Deflate] The deflate writer.
				def self.server_writer(parent, **options)
					Deflate.server(parent, **options)
				end
				
				# Build the client side reader (inflates messages sent by the server).
				# @parameter parent [Object] The parent reader to wrap.
				# @parameter options [Hash] The negotiated extension parameters.
				# @returns [Inflate] The inflate reader.
				def self.client_reader(parent, **options)
					Inflate.client(parent, **options)
				end
				
				# Build the client side writer (deflates messages sent to the server).
				# @parameter parent [Object] The parent writer to wrap.
				# @parameter options [Hash] The negotiated extension parameters.
				# @returns [Deflate] The deflate writer.
				def self.client_writer(parent, **options)
					Deflate.client(parent, **options)
				end
				
				# Install the extension directly onto a server connection.
				# @parameter connection [Connection] The WebSocket connection to configure.
				# @parameter options [Hash] The negotiated extension parameters.
				# @deprecated Use a negotiation {Plan} which installs the reader and writer atomically.
				def self.server(connection, **options)
					connection.reserve!(Frame::RSV1)
					
					connection.reader = Inflate.server(connection.reader, **options)
					connection.writer = Deflate.server(connection.writer, **options)
				end
				
				# Install the extension directly onto a client connection.
				# @parameter connection [Connection] The WebSocket connection to configure.
				# @parameter options [Hash] The negotiated extension parameters.
				# @deprecated Use a negotiation {Plan} which installs the reader and writer atomically.
				def self.client(connection, **options)
					connection.reserve!(Frame::RSV1)
					
					connection.reader = Inflate.client(connection.reader, **options)
					connection.writer = Deflate.client(connection.writer, **options)
				end
				
				# Coerce and validate an LZ77 window size. Values below the minimum supported by zlib are clamped; values outside the protocol range are rejected.
				# @parameter value [String | Integer | Nil] The negotiated window size.
				# @parameter name [String] The parameter name, used in error messages.
				# @returns [Integer] The validated window size.
				def self.window_bits(value, name)
					value = Integer(value || 15)
					
					unless value.between?(8, MAXIMUM_WINDOW_BITS)
						raise NegotiationError, "Extension #{NAME} parameter #{name}=#{value} is out of bounds (8-15)!"
					end
					
					# Zlib is not capable of handling less than 9 window bits:
					value = MINIMUM_WINDOW_BITS if value < MINIMUM_WINDOW_BITS
					
					return value
				end
			end
		end
	end
end
