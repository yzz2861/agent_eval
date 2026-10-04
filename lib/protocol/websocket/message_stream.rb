# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "error"
require_relative "frame"
require_relative "text_frame"
require_relative "binary_frame"
require_relative "continuation_frame"

module Protocol
	module WebSocket
		# Represents the current message being read incrementally from a connection.
		class MessageStream
			DEFAULT_BLOCK_SIZE = 65_536

			# Reads a fragmented message without buffering the complete payload.
			class Framed
				attr :frame

				def initialize(connection, framer, frame)
					@connection = connection
					@framer = framer
					@frame = frame
				end

				def read_partial(maximum_size)
					if @frame.remaining_length.to_i > 0
						data = @framer.read_frame_partial(@frame, maximum_size)
						finished = @frame.finished? && @frame.remaining_length == 0

						return data, finished
					end

					return nil, true if @frame.finished?

					receive_next_frame
					return read_partial(maximum_size)
				end

				private

				def receive_next_frame
					loop do
						frame = @framer.begin_read_frame

						unless frame.flags.zero?
							raise ProtocolError, "Continuation frame has reserved flags set!"
						end

						if frame.control?
							@framer.read_frame_payload(frame, frame.remaining_length)
							frame.apply(@connection)

							if frame.is_a?(CloseFrame)
								raise ProtocolError, "Received close frame before message was complete!"
							end
						else
							frame.apply(@connection)
							@frame = frame
							return
						end
					end
				end
			end

			attr :frame
			attr :type
			attr_accessor :block_size

			def initialize(connection, source, block_size: DEFAULT_BLOCK_SIZE)
				@connection = connection
				@source = source
				@frame = source.frame
				@type = @frame.is_a?(TextFrame) ? :text : :binary
				@block_size = block_size

				@finished = false
				@closed = false
				@read_mutex = Mutex.new
				@output_buffer = String.new(encoding: Encoding::BINARY)
				@text_pending = String.new(encoding: Encoding::BINARY)
			end

			def text?
				@type == :text
			end

			def binary?
				@type == :binary
			end

			def finished?
				@finished
			end

			def closed?
				@closed
			end

			# Read at most the specified number of bytes from the message. Returns nil at the end.
			def readpartial(maximum_size = @block_size)
				raise IOError, "Message stream is closed!" if @closed
				return nil if @finished
				raise ArgumentError, "maximum size must be positive!" unless maximum_size.nil? || maximum_size > 0
				maximum_size ||= @block_size

				@read_mutex.synchronize do
					return buffered_chunk unless @output_buffer.empty?

					loop do
						data, finished = @source.read_partial(maximum_size)
						data ||= String.new(encoding: Encoding::BINARY)

						chunk = text? ? decode_text(data, finished) : data.b
						finish! if finished

						return nil if chunk.empty? && finished
						next if chunk.empty?

						return slice_output(chunk, maximum_size)
					end
				end
			rescue ProtocolError => error
				fail!(error.code, error.message)
				raise
			rescue => error
				fail!(Error::PROTOCOL_ERROR, error.message)
				raise
			end

			# Discard the remainder of the message so another message can be read.
			def discard
				return self if @closed

				until @finished
					break if readpartial.nil?
				end

				return self
			end

			def each(&block)
				return to_enum(:each) unless block_given?

				while chunk = readpartial
					yield chunk
				end
			end

			protected

			def finish!
				return if @finished
				@finished = true
				@connection.finish_message_stream(self)
			end

			def fail!(code, reason)
				@closed = true
				@connection.finish_message_stream(self)
				@connection.close(code, reason)
			end

			private

			def buffered_chunk
				chunk = @output_buffer
				@output_buffer = String.new(encoding: Encoding::BINARY)
				return chunk
			end

			def slice_output(chunk, maximum_size)
				if chunk.bytesize <= maximum_size
					return text? ? chunk.force_encoding(Encoding::UTF_8) : chunk
				end

				if text?
					maximum_size = next_utf8_boundary(chunk, maximum_size)
				end

				result = chunk.byteslice(0, maximum_size)
				@output_buffer = chunk.byteslice(maximum_size, chunk.bytesize - maximum_size)

				if text?
					return result.force_encoding(Encoding::UTF_8)
				end

				return result
			end

			def next_utf8_boundary(buffer, index)
				return buffer.bytesize if index >= buffer.bytesize

				byte = buffer.getbyte(index)
				return index + 1 if byte < 0x80

				if byte < 0xC0
					while index > 0
						index -= 1
						break if buffer.getbyte(index) >= 0xC0
					end
					byte = buffer.getbyte(index)
				end

				return [index + utf8_width(byte), buffer.bytesize].min
			end

			def decode_text(data, finished)
				combined = @text_pending.empty? ? data.b : @text_pending + data.b
				@text_pending.clear

				output = String.new(encoding: Encoding::BINARY)
				index = 0

				while index < combined.bytesize
					byte = combined.getbyte(index)
					width = utf8_width(byte)
					remaining = combined.bytesize - index

					if width > remaining
						if finished
							raise invalid_utf8
						end

						validate_partial_continuation(combined, index, remaining)
						@text_pending = combined.byteslice(index, remaining)
						break
					end

					validate_utf8_sequence(combined, index, width)
					output << combined.byteslice(index, width)
					index += width
				end

				if finished && !@text_pending.empty?
					raise invalid_utf8
				end

				return output
			end

			def invalid_utf8
				ProtocolError.new("invalid UTF-8 in text message!", Error::INVALID_PAYLOAD)
			end

			def utf8_width(byte)
				case byte
				when 0x00..0x7F then 1
				when 0xC2..0xDF then 2
				when 0xE0..0xEF then 3
				when 0xF0..0xF4 then 4
				else
					raise invalid_utf8
				end
			end

			def validate_partial_continuation(buffer, index, length)
				for offset in 1...length
					validate_continuation_byte(buffer.getbyte(index + offset))
				end
			end

			def validate_utf8_sequence(buffer, index, width)
				first = buffer.getbyte(index)
				second = buffer.getbyte(index + 1) if width >= 2

				if width == 3
					case first
					when 0xE0
						validate_byte(second, 0xA0..0xBF)
					when 0xED
						validate_byte(second, 0x80..0x9F)
					else
						validate_continuation_byte(second)
					end
				elsif width == 4
					case first
					when 0xF0
						validate_byte(second, 0x90..0xBF)
					when 0xF4
						validate_byte(second, 0x80..0x8F)
					else
						validate_continuation_byte(second)
					end
				elsif width == 2
					validate_continuation_byte(second)
				end

				for offset in 2...width
					validate_continuation_byte(buffer.getbyte(index + offset))
				end
			end

			def validate_continuation_byte(byte)
				validate_byte(byte, 0x80..0xBF)
			end

			def validate_byte(byte, range)
				unless range.include?(byte)
					raise invalid_utf8
				end
			end
		end
	end
end
