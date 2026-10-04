# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.

require_relative "constants"

module Protocol
	module WebSocket
		module Extension
			module Compression
				# Compresses outgoing WebSocket frames using the DEFLATE algorithm.
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
					# @parameter minimum_size [Integer] The minimum message size to consider for automatic compression.
					def initialize(parent, level: Zlib::DEFAULT_COMPRESSION, memory_level: Zlib::DEF_MEM_LEVEL, strategy: Zlib::DEFAULT_STRATEGY, window_bits: 15, context_takeover: true, minimum_size: 1, **options)
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
					
					# @returns [String] A string representation including window bits, context takeover and minimum size settings.
					def to_s
						"#<#{self.class} window_bits=#{@window_bits} context_takeover=#{@context_takeover} minimum_size=#{@minimum_size}>"
					end
					
					# @attribute [Integer] The window size in bits used for compression.
					attr :window_bits
					# @attribute [Boolean] Whether the compression context is reused across messages.
					attr :context_takeover
					# @attribute [Integer] The minimum message size to consider for automatic compression.
					attr :minimum_size
					
					# Pack a text frame, optionally compressing the buffer.
					# @parameter buffer [String] The text payload to pack.
					# @parameter compress [Boolean | Nil] Whether to compress the buffer. `nil` selects compression automatically.
					# @returns [Frame] The packed (and optionally compressed) text frame.
					def pack_text_frame(buffer, compress: nil, **options)
						compressed = self.compress(buffer, compress)
						buffer = compressed unless compressed.nil?
						
						frame = @parent.pack_text_frame(buffer, **options)
						frame.flags |= Frame::RSV1 unless compressed.nil?
						
						return frame
					end
					
					# Pack a binary frame, optionally compressing the buffer.
					# @parameter buffer [String] The binary payload to pack.
					# @parameter compress [Boolean | Nil] Whether to compress the buffer. `nil` selects compression automatically.
					# @returns [Frame] The packed (and optionally compressed) binary frame.
					def pack_binary_frame(buffer, compress: nil, **options)
						compressed = self.compress(buffer, compress)
						buffer = compressed unless compressed.nil?
						
						frame = @parent.pack_binary_frame(buffer, **options)
						frame.flags |= Frame::RSV1 unless compressed.nil?
						
						return frame
					end
					
					private
					
					def compress(buffer, mode)
						return nil if mode == false
						
						if mode == true
							deflate = self.acquire_deflate
							compressed = self.flush_deflate(buffer, deflate)
							deflate.close unless @context_takeover
							return compressed
						end
						return nil if buffer.bytesize < @minimum_size
						deflate = @context_takeover && @deflate ? @deflate.dup : self.new_deflate
						compressed = self.flush_deflate(buffer, deflate)
						if compressed.bytesize < buffer.bytesize
							if @context_takeover
								previous_deflate = @deflate
								@deflate = deflate
								previous_deflate.close unless previous_deflate.nil? || previous_deflate.equal?(deflate)
							else
								deflate.close
							end
							return compressed
						end
						deflate.close
						return nil
					end

					def acquire_deflate
						if @context_takeover
							@deflate ||= self.new_deflate
						else
							self.new_deflate
						end
					end

					def flush_deflate(buffer, deflate)
						compressed = deflate.deflate(buffer, Zlib::SYNC_FLUSH)[0...-4]
						return compressed
					end

					def new_deflate
						Zlib::Deflate.new(@level, -@window_bits, @memory_level, @strategy)
					end
				end
			end
		end
	end
end
