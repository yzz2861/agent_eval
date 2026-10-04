# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2019-2026, by Samuel Williams.
# Copyright, 2026, by William T. Nelson.

require_relative "frame"

require_relative "continuation_frame"
require_relative "text_frame"
require_relative "binary_frame"
require_relative "close_frame"
require_relative "ping_frame"
require_relative "pong_frame"

module Protocol
	module WebSocket
		# HTTP/2 frame type mapping as defined by the spec.
		FRAMES = {
			0x0 => ContinuationFrame,
			0x1 => TextFrame,
			0x2 => BinaryFrame,
			0x8 => CloseFrame,
			0x9 => PingFrame,
			0xA => PongFrame,
		}.freeze
		
		# The maximum allowed frame size in bytes.
		MAXIMUM_ALLOWED_FRAME_SIZE = 2**63
		
		# Wraps an underlying {Async::IO::Stream} for reading and writing binary data into structured frames.
		class Framer
			# Initialize a new framer wrapping the given stream.
			# @parameter stream [IO] The underlying stream to read from and write to.
			# @parameter frames [Hash] A mapping of opcodes to frame classes.
			# @parameter role [:client, :server, Nil] The role of the local endpoint. When set to `:client` or `:server`, strict masking enforcement is enabled (see {#read_frame} and {#write_frame}). When `nil`, masking is not enforced, which preserves the legacy behaviour.
			def initialize(stream, frames = FRAMES, role: nil)
				@stream = stream
				@frames = frames
				
				self.role = role
				
				# The RSV bits which have not been negotiated by any extension. Any frame setting these bits is rejected:
				@reserved = Frame::RESERVED
			end
			
			# @attribute [:client, :server, Nil] The role of the local endpoint, or `nil` for legacy (lenient) mode.
			attr :role
			
			# Set the role of the local endpoint.
			# @parameter role [:client, :server, Nil] The role to use for masking enforcement.
			def role=(role)
				case role
				when nil, :client, :server
					@role = role
				else
					raise ArgumentError, "Invalid role: #{role.inspect}! Expected :client, :server, or nil."
				end
			end
			
			# @attribute [Integer] Bitmask of RSV bits which are not allowed on incoming frames (i.e. not negotiated by any extension).
			attr_accessor :reserved
			
			# @returns [Boolean] Whether the framer enforces strict masking rules.
			def strict?
				!@role.nil?
			end
			
			# Close the underlying stream.
			def close
				@stream.close
			end
			
			# Flush the underlying stream.
			def flush
				@stream.flush
			end
			
			# Read a frame from the underlying stream.
			# All header level validation (opcode, RSV, FIN, masking and length) happens before any payload data is read.
			# @parameter maximum_frame_size [Integer] The maximum acceptable payload length in bytes.
			# @parameter reserved [Integer] Bitmask of RSV bits which must not be set unless an extension negotiated them.
			# @returns [Frame] the frame read from the stream.
			# @raises [ProtocolError] If the frame violates the WebSocket protocol; inspect `ProtocolError#code` for the WebSocket close code.
			def read_frame(maximum_frame_size = MAXIMUM_ALLOWED_FRAME_SIZE, reserved: @reserved)
				buffer = @stream.read(2)
				
				unless buffer and buffer.bytesize == 2
					raise EOFError, "Could not read frame header!"
				end
				
				first_byte = buffer.getbyte(0)
				second_byte = buffer.getbyte(1)
				
				finished = (first_byte & 0b1000_0000 != 0)
				flags = (first_byte & 0b0111_0000) >> 4
				opcode = first_byte & 0b0000_1111
				
				if opcode >= 0x3 && opcode <= 0x7
					raise ProtocolError, "Non-control opcode = #{opcode} is reserved!"
				elsif opcode >= 0xB
					raise ProtocolError, "Control opcode = #{opcode} is reserved!"
				end
				
				mask = (second_byte & 0b1000_0000 != 0)
				length_encoding = second_byte & 0b0111_1111
				length = length_encoding
				
				# RSV bits must only be set for extensions which were negotiated during the handshake:
				unless (flags & reserved).zero?
					raise ProtocolError, "Received frame with reserved flags set!"
				end
				
				if opcode & 0x8 != 0
					if !finished
						raise ProtocolError, "Fragmented control frame!"
					elsif length > 125
						raise ProtocolError, "Invalid control frame payload length: control frames must not exceed 125 bytes or use an extended length encoding!"
					end
				end
				
				# Strict masking enforcement based on the explicitly configured role, rather than guessing
				# the role from the locally configured outgoing mask:
				case @role
				when :server
					# Frames sent by a client to a server MUST be masked:
					raise ProtocolError, "Received unmasked frame from client!" unless mask
				when :client
					# Frames sent by a server to a client MUST NOT be masked:
					raise ProtocolError, "Received masked frame from server!" if mask
				end
				
				if length_encoding == 126
					if mask
						buffer = @stream.read(6) or raise EOFError, "Could not read length and mask!"
						length = buffer.unpack1("n")
						mask = buffer.byteslice(2, 4)
					else
						buffer = @stream.read(2) or raise EOFError, "Could not read length!"
						length = buffer.unpack1("n")
					end
					
					# The 16-bit encoding must only represent values which do not fit in 7 bits:
					if length <= 125
						raise ProtocolError, "Invalid payload length encoding: 16-bit length used for #{length} byte payload!"
					end
				elsif length_encoding == 127
					if mask
						buffer = @stream.read(12) or raise EOFError, "Could not read length and mask!"
						length = buffer.unpack1("Q>")
						mask = buffer.byteslice(8, 4)
					else
						buffer = @stream.read(8) or raise EOFError, "Could not read length!"
						length = buffer.unpack1("Q>")
					end
					
					# The high bit of the 64-bit length field must be zero, and only values which do not
					# fit in the previous length encoding tier are allowed:
					if length >= 2**63
						raise ProtocolError, "Invalid payload length: most significant bit must be zero!"
					elsif length <= 65535
						raise ProtocolError, "Invalid payload length encoding: 64-bit length used for #{length} byte payload!"
					end
				elsif mask
					# Short length encoding, only the 4-byte mask key (if any) remains:
					mask = @stream.read(4) or raise EOFError, "Could not read mask!"
				end
				
				if length > maximum_frame_size
					raise ProtocolError.new(
						"Invalid payload length: #{length} > #{maximum_frame_size}!",
						Error::MESSAGE_TOO_LARGE
					)
				end
				
				payload = @stream.read(length) or raise EOFError, "Could not read payload!"
				
				if payload.bytesize != length
					raise EOFError, "Incorrect payload length: #{length} != #{payload.bytesize}!"
				end
				
				klass = @frames[opcode] || Frame
				return klass.new(finished, payload, flags: flags, opcode: opcode, mask: mask)
			end
			
			# Write a frame to the underlying stream.
			# @parameter frame [Frame] The frame to serialize and write.
			# @raises [ProtocolError] If the frame has an invalid mask or violates the configured role.
			def write_frame(frame)
				if frame.mask and frame.mask.bytesize != 4
					raise ProtocolError, "Invalid mask length!"
				end
				
				case @role
				when :client
					raise ProtocolError, "Client frames must be masked!" unless frame.mask
				when :server
					raise ProtocolError, "Server frames must not be masked!" if frame.mask
				end
				
				length = frame.length
				
				if length <= 125
					short_length = length
				elsif length.bit_length <= 16
					short_length = 126
				else
					short_length = 127
				end
				
				buffer = [
					(frame.finished ? 0b1000_0000 : 0) | (frame.flags << 4) | frame.opcode,
					(frame.mask ? 0b1000_0000 : 0) | short_length,
				].pack("CC")
				
				if short_length == 126
					buffer << [length].pack("n")
				elsif short_length == 127
					buffer << [length].pack("Q>")
				end
				
				buffer << frame.mask if frame.mask
				
				@stream.write(buffer)
				@stream.write(frame.payload)
			end
		end
	end
end
