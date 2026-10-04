# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.

require "zlib"

require_relative "constants"

module Protocol
	module WebSocket
		module Extension
			module Compression
				# Compresses outgoing WebSocket messages using the DEFLATE algorithm.
				class Deflate
					# Client writing to server.
					def self.client(parent, client_max_window_bits: 15, client_no_context_takeover: false, **options)
						self.new(parent,
							window_bits: client_max_window_bits,
							context_takeover: !client_no_context_takeover,
							**options
						)
					end
					
					# Server writing to client.
					def self.server(parent, server_max_window_bits: 15, server_no_context_takeover: false, **options)
						self.new(parent,
							window_bits: server_max_window_bits,
							context_takeover: !server_no_context_takeover,
							**options
						)
					end
					
					# Initialize a new deflate compressor.
					# @parameter parent [Object] The parent framer to wrap.
					# @parameter level [Integer] The compression level. Defaults to `Zlib::DEFAULT_COMPRESSION`.
					# @parameter memory_level [Integer] The memory level for compression. Defaults to `Zlib::DEF_MEM_LEVEL`.
					# @parameter strategy [Integer] The compression strategy. Defaults to `Zlib::DEFAULT_STRATEGY`.
					# @parameter window_bits [Integer] The window size in bits for the DEFLATE algorithm.
					# @parameter context_takeover [Boolean] Whether to reuse the compression context across messages.
					# @parameter minimum_size [Integer] The minimum message size eligible for automatic compression.
					def initialize(parent, level: Zlib::DEFAULT_COMPRESSION, memory_level: Zlib::DEF_MEM_LEVEL, strategy: Zlib::DEFAULT_STRATEGY, window_bits: 15, context_takeover: true, minimum_size: 128, **options)
						@parent = parent
						
						@deflate = nil
						
						@level = level
						@memory_level = memory_level
						@strategy = strategy
						
						# This is handled during negotiation:
						# if window_bits < MINIMUM_WINDOW_BITS
						# 	window_bits = MINIMUM_WINDOW_BITS
						# end
						
						@window_bits = window_bits
						@context_takeover = context_takeover
						@minimum_size = minimum_size
					end
					
					# @returns [String] A string representation including window bits and context takeover settings.
					def to_s
						"#<#{self.class} window_bits=#{@window_bits} context_takeover=#{@context_takeover}>"
					end
					
					# @attribute [Integer] The window size in bits used for compression.
					attr :window_bits
					# @attribute [Boolean] Whether the compression context is reused across messages.
					attr :context_takeover
					# @attribute [Integer] The minimum message size eligible for automatic compression.
					attr :minimum_size
					
					# Pack a text frame, optionally compressing the buffer.
					# @parameter buffer [String] The text payload to pack.
					# @parameter compress [Boolean | Symbol] Whether to compress the buffer. When `:auto` (the default), compresses only eligible messages when compression reduces the payload size.
					# @returns [Frame] The packed (and optionally compressed) text frame.
					def pack_text_frame(buffer, compress: :auto, **options)
						pack_frame(buffer, compress) do |payload|
							@parent.pack_text_frame(payload, **options)
						end
					end
					
					# Pack a binary frame, optionally compressing the buffer.
					# @parameter buffer [String] The binary payload to pack.
					# @parameter compress [Boolean | Symbol] Whether to compress the buffer. When `:auto`, compresses only eligible messages when compression reduces the payload size.
					# @returns [Frame] The packed (and optionally compressed) binary frame.
					def pack_binary_frame(buffer, compress: false, **options)
						pack_frame(buffer, compress) do |payload|
							@parent.pack_binary_frame(payload, **options)
						end
					end

					private

					def pack_frame(buffer, policy)
						compressed_buffer = compress(buffer, policy)
						
						if compressed_buffer
							frame = yield(compressed_buffer)
							frame.flags |= Frame::RSV1
						else
							frame = yield(buffer)
						end
						
						return frame
					end
					
					def compress(buffer, policy)
						case policy
						when true
							return commit_deflate(@deflate || new_deflate, buffer)
						when false
							return nil
						when :auto
							return nil if buffer.bytesize < @minimum_size

							deflate = @deflate ? @deflate.dup : new_deflate
							compressed_buffer = finish_deflate(deflate, buffer)

							if compressed_buffer.bytesize < buffer.bytesize
								if @context_takeover
									@deflate = deflate
								end

								return compressed_buffer
							end

							return nil
						else
							raise ArgumentError, "Invalid compress policy: #{policy.inspect}!"
						end
					end

					def commit_deflate(deflate, buffer)
						compressed_buffer = finish_deflate(deflate, buffer)
						
						if @context_takeover
							@deflate = deflate
						end
						
						return compressed_buffer
					end

					def new_deflate
						Zlib::Deflate.new(@level, -@window_bits, @memory_level, @strategy)
					end

					def finish_deflate(deflate, buffer)
						deflate.deflate(buffer, Zlib::SYNC_FLUSH)[0...-4]
					end
				end
			end
		end
	end
end
