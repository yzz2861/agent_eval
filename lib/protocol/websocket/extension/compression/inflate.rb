# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.

require_relative "constants"

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
					# @parameter parent [Object] The parent framer to wrap.
					# @parameter context_takeover [Boolean] Whether to reuse the decompression context across messages.
					# @parameter window_bits [Integer] The window size in bits for the DEFLATE algorithm.
					def initialize(parent, context_takeover: true, window_bits: 15)
						@parent = parent

						@inflate = nil
						@stream_inflate = nil
						@stream_compressed = false

						# This is handled during negotiation:
						# if window_bits < MINIMUM_WINDOW_BITS
						# 	window_bits = MINIMUM_WINDOW_BITS
						# end

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

					# Unpack and decompress frames into a buffer.
					# @parameter frames [Array(Frame)] The frames to unpack.
					# @returns [String] The decompressed payload buffer.
					def unpack_frames(frames, **options)
						buffer = @parent.unpack_frames(frames, **options)

						frame = frames.first

						if frame.flag?(Frame::RSV1)
							begin
								buffer = inflate(buffer)
							ensure
								frame.flags &= ~Frame::RSV1
							end
						end

						return buffer
					end

					# Unpack and decompress one chunk of a message.
					# @parameter frame [Frame] The frame being read.
					# @parameter payload [String] The raw unmasked payload chunk.
					# @parameter first_message [Boolean] Whether this is the first frame of the message.
					# @parameter first_chunk [Boolean] Whether this is the first chunk of this frame.
					# @parameter finished [Boolean] Whether this is the last chunk of the message.
					# @returns [String] The decompressed payload chunk.
					def unpack_fragment(frame, payload, first_message: false, first_chunk: false, finished: false, **options)
						payload = @parent.unpack_fragment(
							frame,
							payload,
							first_message: first_message,
							first_chunk: first_chunk,
							finished: finished,
							**options
						)

						if first_chunk
							if first_message
								@stream_compressed = frame.flag?(Frame::RSV1)
							elsif frame.flag?(Frame::RSV1)
								raise ProtocolError, "Compression flag set on continuation frame!"
							end
						end

						if @stream_compressed
							if finished
								payload = payload + TRAILER

								begin
									return stream_inflate.inflate(payload)
								ensure
									finish_stream_inflate!
									@stream_inflate = nil
									@stream_compressed = false
								end
							else
								return stream_inflate.inflate(payload)
							end
						end

						return payload
					end

					private

					def inflate(buffer)
						current = @inflate ||= Zlib::Inflate.new(-@window_bits)

						begin
							return current.inflate(buffer + TRAILER)
						ensure
							unless @context_takeover
								@inflate.close
								@inflate = nil
							end
						end
					end

					def stream_inflate
						@stream_inflate ||= begin
							inflate = @inflate || Zlib::Inflate.new(-@window_bits)
							@inflate = nil
							inflate
						end
					end

					def finish_stream_inflate!
						if @context_takeover
							@inflate = @stream_inflate
						else
							@stream_inflate.close
						end
					end
				end
			end
		end
	end
end
