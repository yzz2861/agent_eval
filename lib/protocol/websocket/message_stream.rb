# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "binary_frame"
require_relative "continuation_frame"
require_relative "error"
require_relative "text_frame"

module Protocol
	module WebSocket
		# Represents one incoming message being read as a sequence of chunks.
		class MessageStream
			# The default maximum number of uncompressed bytes returned by one read.
			DEFAULT_CHUNK_SIZE = 16 * 1024

			def initialize(connection, frame, **options)
				@connection = connection
				@reader = connection.reader
				@frame = frame
				@options = options

				@type = case frame.opcode
					when TextFrame::OPCODE then :text
					when BinaryFrame::OPCODE then :binary
					else
						raise ProtocolError, "Unexpected message opcode: #{frame.opcode}!"
					end

				@first_message_frame = true
				@current_frame_started = false
				@message_finished = false
				@closed = false
				@reader_fiber = nil

				@buffer = String.new(encoding: Encoding::BINARY)
				@pending_text = String.new(encoding: Encoding::BINARY)
			end

			# @returns [Symbol] `:text` or `:binary`.
			attr :type

			# @returns [Boolean] Whether this is a text message.
			def text?
				@type == :text
			end

			# @returns [Boolean] Whether this is a binary message.
			def binary?
				@type == :binary
			end

			# @returns [Boolean] Whether all message data has been consumed.
			def closed?
				@closed
			end

			# Read at most the requested number of message bytes.
			# @parameter maximum_size [Integer] The maximum number of bytes to return.
			# @returns [String | Nil] A chunk of message data, or `nil` at the end of the message.
			def read_partial(maximum_size = DEFAULT_CHUNK_SIZE, buffer = nil)
				assert_reader!
				raise ArgumentError, "Maximum size must be positive!" unless maximum_size.positive?

				begin
					while @buffer.empty? && !@closed
						chunk = read_chunk(maximum_size)

						if chunk.nil?
							finish!
							return nil
						end

						@buffer << chunk unless chunk.empty?
					end

					chunk = consume_buffer(maximum_size, buffer)
					chunk.force_encoding(Encoding::UTF_8) if text?
					return chunk
				rescue => error
					fail!(error)
					raise
				end
			end

			# Iterate over chunks until the complete message has been consumed.
			def each(&block)
				return to_enum unless block_given?

				while chunk = read_partial
					yield chunk
				end
			end

			# Read and discard the remainder of this message so the next message can be read.
			def discard
				assert_reader!

				while read_partial
				end

				return nil
			end

			# Called by the connection when a continuation fragment is available.
			def receive_continuation(frame)
				raise ProtocolError, "Received unexpected continuation!" if @frame.finished? || @frame.remaining_payload_length.nonzero?

				@frame = frame
				@first_message_frame = false
				@current_frame_started = false
			end

			private

			def assert_reader!
				return if @closed

				@reader_fiber ||= Fiber.current

				unless @reader_fiber == Fiber.current
					raise ProtocolError, "Message is already being read by another reader!"
				end
			end

			def read_chunk(maximum_size)
				advance_frame! if @frame.remaining_payload_length.zero?
				return nil if @message_finished && @frame.remaining_payload_length.zero?

				first_chunk = !@current_frame_started
				@current_frame_started = true

				raw_maximum_size = [maximum_size, @frame.remaining_payload_length].min
				raw_payload = @connection.framer.read_payload_chunk(@frame, raw_maximum_size)
				raw_payload ||= ""
				fragment_finished = @frame.remaining_payload_length.zero? && @frame.finished?
				@message_finished = fragment_finished

				payload = @reader.unpack_fragment(
					@frame,
					raw_payload,
					first_message: @first_message_frame,
					first_chunk: first_chunk,
					finished: fragment_finished,
					**@options
				)

				if text?
					return split_text(payload, fragment_finished)
				else
					return payload.force_encoding(Encoding::BINARY)
				end
			end

			def advance_frame!
				return if @message_finished
				return if @frame.finished?

				@connection.read_continuation_frame!
			end

			def consume_buffer(maximum_size, buffer)
				if @buffer.bytesize <= maximum_size
					chunk = @buffer
					@buffer = String.new(encoding: Encoding::BINARY)
				else
					chunk = @buffer.byteslice(0, maximum_size)
					@buffer = @buffer.byteslice(maximum_size, @buffer.bytesize - maximum_size)
				end

				if buffer
					buffer.replace(chunk)
				else
					buffer = chunk
				end

				return buffer
			end

			def split_text(payload, fragment_finished)
				@pending_text << payload unless payload.empty?

				valid_size = valid_utf8_prefix_size(@pending_text)

				if valid_size == @pending_text.bytesize
					chunk = @pending_text
					@pending_text = String.new(encoding: Encoding::BINARY)
				else
					chunk = @pending_text.byteslice(0, valid_size)
					@pending_text = @pending_text.byteslice(valid_size, @pending_text.bytesize - valid_size)
				end

				if fragment_finished && !@pending_text.empty?
					raise ProtocolError.new("invalid UTF-8 in text message!", Error::INVALID_PAYLOAD)
				end

				return chunk.force_encoding(Encoding::UTF_8)
			end

			def valid_utf8_prefix_size(buffer)
				index = 0

				while index < buffer.bytesize
					byte = buffer.getbyte(index)
					size, minimum_next, maximum_next = utf8_character(byte)

					if size.nil?
						raise ProtocolError.new("invalid UTF-8 in text message!", Error::INVALID_PAYLOAD)
					end

					return index if index + size > buffer.bytesize

					(1...size).each do |offset|
						continuation = buffer.getbyte(index + offset)
						minimum = offset == 1 ? minimum_next : 0x80
						bound = offset == 1 ? maximum_next : 0xBF

						unless continuation.between?(minimum, bound)
							raise ProtocolError.new("invalid UTF-8 in text message!", Error::INVALID_PAYLOAD)
						end
					end

					index += size
				end

				return index
			end

			def utf8_character(byte)
				case byte
				when 0x00..0x7F then [1, 0x80, 0xBF]
				when 0xC2..0xDF then [2, 0x80, 0xBF]
				when 0xE0 then [3, 0xA0, 0xBF]
				when 0xE1..0xEC then [3, 0x80, 0xBF]
				when 0xED then [3, 0x80, 0x9F]
				when 0xEE..0xEF then [3, 0x80, 0xBF]
				when 0xF0 then [4, 0x90, 0xBF]
				when 0xF1..0xF3 then [4, 0x80, 0xBF]
				when 0xF4 then [4, 0x80, 0x8F]
				end
			end

			def finish!
				@closed = true
				@connection.finish_message_stream!(self)
			end

			def fail!(error)
				return if @closed

				@closed = true
				@connection.close_message_stream!(self, error)
			end
		end
	end
end
