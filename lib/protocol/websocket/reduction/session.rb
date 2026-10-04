# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "../frame"
require_relative "../text_frame"
require_relative "../binary_frame"
require_relative "../continuation_frame"
require_relative "../close_frame"
require_relative "../ping_frame"
require_relative "../pong_frame"

module Protocol
	module WebSocket
		module Reduction
			# A captured WebSocket session offered to a failure oracle.
			#
			# A session is the input a reducer works on: the endpoint role which
			# produced the frames, the handshake configuration negotiated for the
			# connection, and the ordered frame sequence.
			#
			# @parameter role [Symbol] `:client` or `:server`. The role fixes the
			#   masking direction: client frames are masked, server frames are not.
			# @parameter frames [Array(Frame)] The ordered frame sequence.
			# @parameter extensions [Array(String)] Extension tokens negotiated
			#   during the handshake. A frame may only set an RSV bit whose extension
			#   was actually negotiated.
			class Session
				# Opcodes which carry message data and are allowed to start a message.
				DATA_OPCODES = [0x1, 0x2].freeze
				
				# The extension which owns the RSV1 bit (RFC 7692).
				COMPRESSION_EXTENSION = "permessage-deflate"
				
				# @returns [Symbol] `:client` or `:server`.
				attr :role
				
				# @returns [Array(Frame)] the ordered frame sequence.
				attr :frames
				
				# @returns [Array(String)] the negotiated handshake extensions.
				attr :extensions
				
				def initialize(role:, frames:, extensions: [])
					case role
					when :client, :server
						# OK
					else
						raise ArgumentError, "invalid role: #{role.inspect}!"
					end
					
					@role = role
					@frames = frames
					@extensions = extensions.map(&:to_s).freeze
				end
				
				# @returns [Boolean] whether this side must mask every frame it sends.
				def masked?
					@role == :client
				end
				
				# Build a session with the same role and handshake configuration.
				# Handshake configuration is never altered by reduction.
				def with(frames)
					self.class.new(role: @role, frames: frames, extensions: @extensions)
				end
				
				# Approximate on-the-wire size of the sequence, in bytes. Used as the
				# metric reduction minimizes.
				def wire_size
					@frames.sum do |frame|
						size = 2 + (frame.mask ? 4 : 0) + frame.payload.to_s.bytesize
						size += 2 if frame.payload && frame.payload.bytesize >= 126
						size += 6 if frame.payload && frame.payload.bytesize > 0xFFFF
						size
					end
				end
				
				# Validate the invariants a well-formed session must satisfy.
				# The reducer only submits structurally valid candidates to the oracle,
				# preserving mask direction, fragmentation, control frame rules, close
				# frame codes/reasons and UTF-8 text payloads.
				#
				# @returns [Boolean] whether the sequence is replayable as-is.
				def structurally_valid?
					fragment_open = false
					text_message = false
					buffer = String.new(encoding: Encoding::BINARY)
					
					@frames.each do |frame|
						if frame.control?
							return false unless frame.finished?
							return false if frame.payload.to_s.bytesize > 125
							
							if frame.opcode == 0x8
								return false unless valid_close_data?(self.class.unmasked(frame))
							end
						else
							case frame.opcode
							when *DATA_OPCODES
								return false if fragment_open
								
								text_message = frame.opcode == 0x1
								buffer = String.new(encoding: Encoding::BINARY)
								buffer << self.class.unmasked(frame)
								
								if frame.finished?
									return false if text_message && !utf8?(buffer)
									fragment_open = false
								else
									fragment_open = true
								end
							when 0x0
								return false unless fragment_open
								
								buffer << self.class.unmasked(frame)
								
								if frame.finished?
									return false if text_message && !utf8?(buffer)
									fragment_open = false
								end
							else
								return false
							end
						end
						
						return false unless mask_direction_ok?(frame)
						return false unless reserved_bits_negotiated?(frame)
					end
					
					return !fragment_open
				end
				
				# Remove masking and return the plain payload bytes of a frame.
				def self.unmasked(frame)
					data = frame.payload.to_s
					
					if frame.mask
						Frame.instance_method(:mask_xor).bind_call(frame, data, frame.mask)
					else
						data
					end
				end
				
				private
				
				def mask_direction_ok?(frame)
					if masked?
						frame.mask.is_a?(String) && frame.mask.bytesize == 4
					else
						!frame.mask
					end
				end
				
				def reserved_bits_negotiated?(frame)
					compression = @extensions.include?(COMPRESSION_EXTENSION)
					rsv1 = (frame.flags & Frame::RSV1) != 0
					rsv23 = (frame.flags & (Frame::RSV2 | Frame::RSV3)) != 0
					
					# RSV1 belongs to permessage-deflate; RSV2/RSV3 have no
					# negotiated extension in this implementation.
					return false if rsv1 && !compression
					return false if rsv23
					return true
				end
				
				def valid_close_data?(data)
					return true if data.empty?
					return false if data.bytesize == 1
					
					code = data.byteslice(0, 2).unpack1("n")
					return false if code < 1000 || code == 1004 || code == 1005 || code == 1006 || code == 1015
					return false if (1016 .. 2999).cover?(code) || code >= 5000
					
					reason = data.byteslice(2, data.bytesize).force_encoding(Encoding::UTF_8)
					return reason.valid_encoding?
				end
				
				def utf8?(buffer)
					buffer.dup.force_encoding(Encoding::UTF_8).valid_encoding?
				end
			end
		end
	end
end
