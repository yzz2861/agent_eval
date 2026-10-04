# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.

require_relative "constants"

require "zlib"

module Protocol
	module WebSocket
		module Extension
			module Compression
				# Decompresses incoming WebSocket frames using the DEFLATE algorithm.
				class Inflate
					# Client reading from server.
					def self.client(parent, server_max_window_bits: 15, server_no_context_takeover: false, **options)
						self.new(parent,
							window_bits: server_max_window_bits,
							context_takeover: !server_no_context_takeover,
						)
					end

					# Server reading from client.
					def self.server(parent, client_max_window_bits: 15, client_no_context_takeover: false, **options)
						self.new(parent,
							window_bits: client_max_window_bits,
							context_takeover: !client_no_context_takeover,
						)
					end

					TRAILER = [0x00, 0x00, 0xff, 0xff].pack("C*")

					# Initialize a new inflate decompressor.
					# @parameter parent [Object] The parent reader to wrap.
					# @parameter context_takeover [Boolean] Whether to reuse the decompression context across messages.
					# @parameter window_bits [Integer] The window size in bits for the DEFLATE algorithm.
					def initialize(parent, context_takeover: true, window_bits: 15)
						@parent = parent
						@inflate = nil
						@window_bits = window_bits
						@context_takeover = context_takeover
					end

					# @returns [String] A string representation including window bits and context takeover settings.
					def to_s
						"#<#{self.class} window_bits=#{@window_bits} context_takeover=#{@context_takeover}>"
					end

					# @attribute [Integer] The window size in bits used for decompression.
					attr :window_bits
					# @attribute [Boolean] Whether the decompression context is reused across messages.
					attr :context_takeover

					# Wrap a frame-oriented message stream with incremental decompression.
					def read_stream(parent, **options)
						source = DecompressingMessageStream.new(parent, self)
						return @parent.read_stream(source, **options)
					end

					# Unpack and decompress frames into a buffer.
					# @parameter frames [Array(Frame)] The frames to unpack.
					# @returns [String] The decompressed payload buffer.
					def unpack_frames(frames, **options)
						buffer = @parent.unpack_frames(frames, **options)
						frame = frames.first

						if frame.flag?(Frame::RSV1)
							buffer = inflate_data(buffer, true)
							frame.flags &= ~Frame::RSV1
						end

						return buffer
					end

					# Incrementally decompress one message chunk.
					# @parameter buffer [String] The compressed chunk.
					# @parameter finished [Boolean] Whether this is the last compressed chunk of the message.
					# @returns [String] The decompressed chunk.
					def inflate_data(buffer, finished)
						inflate = @inflate || Zlib::Inflate.new(-@window_bits)
						payload = finished ? buffer + TRAILER : buffer

						begin
							return inflate.inflate(payload)
						rescue Zlib::Error => error
							raise ProtocolError.new("invalid compressed payload: #{error.message}", Error::INVALID_PAYLOAD)
						ensure
							if finished
								if @context_takeover
									@inflate = inflate
								else
									inflate.close
									@inflate = nil
								end
							else
								@inflate = inflate
							end
						end
					end

					private

					def inflate(buffer)
						inflate_data(buffer, true)
					end

					class DecompressingMessageStream
						attr :frame

						def initialize(parent, inflate)
							@parent = parent
							@inflate = inflate
							@frame = parent.frame
							@compressed = parent.frame.flag?(Frame::RSV1)
						end

						def read_partial(maximum_size)
							data, finished = @parent.read_partial(maximum_size)
							data ||= String.new(encoding: Encoding::BINARY)

							if @compressed
								data = @inflate.inflate_data(data, finished)
							end

							return data, finished
						end
					end
				end
			end
		end
	end
end
