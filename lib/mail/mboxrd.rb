# frozen_string_literal: true

module Mail
  # Read and write mboxrd archives without loading an entire archive into
  # memory. Messages are yielded one at a time while reading, and writers
  # accept any enumerable of Mail::Message objects.
  module Mboxrd
    ENVELOPE_PREFIX = "From ".freeze
    QUOTED_FROM_LINE = /\A>*From(?: |\r?\n|\z)/
    ENVELOPE_LINE = /\AFrom(?:[[:space:]]|\r?\n|\z)/
    DEFAULT_CHUNK_SIZE = 4096

    class << self
      def read(io, chunk_size = DEFAULT_CHUNK_SIZE, &emitter)
        unless chunk_size.is_a?(Integer) && chunk_size > 0
          raise ArgumentError, "chunk_size must be a positive integer"
        end

        return enum_for(:read, io, chunk_size) unless emitter

        envelope = nil
        message_data = binary_string
        leftover = binary_string
        seen_envelope = false

        each_line(io, chunk_size, leftover) do |line|
          envelope_content = envelope_content(line)

          if envelope_content
            yield_message(envelope, message_data, emitter) if seen_envelope
            envelope = envelope_content
            message_data = binary_string
            seen_envelope = true
          elsif seen_envelope
            message_data << unquote_line(line)
          end
        end

        yield_message(envelope, message_data, emitter) if seen_envelope

        nil
      end

      def write(io, messages)
        messages.each do |message|
          io.write("From #{envelope_for(message)}\n".b)
          write_message(io, message)
        end

        io
      end

      private

      def each_line(io, chunk_size, leftover)
        while (chunk = io.read(chunk_size))
          break if chunk.empty?

          leftover << chunk.dup.force_encoding(Encoding::BINARY)

          while (newline_index = leftover.index("\n".b))
            yield leftover.slice!(0, newline_index + 1)
          end
        end

        yield leftover.dup unless leftover.empty?
      end

      def envelope_content(line)
        return unless line.match?(ENVELOPE_LINE)

        content = line[ENVELOPE_PREFIX.length..-1].to_s
        content = content.sub(/\r?\n\z/, String.new.b)
        content unless content.empty? || content.start_with?(/\s/)
      end

      def unquote_line(line)
        return line unless line.start_with?(">".b) && line.match?(QUOTED_FROM_LINE)

        line = line.dup
        line.slice!(0)
        line
      end

      def yield_message(envelope, message_data, emitter)
        message = Message.new(message_data)
        message.set_envelope(envelope) if envelope
        emitter.call(message)
      end

      def write_message(io, message)
        source = message_source(message).b
        had_line_ending = false

        source.each_line do |line|
          had_line_ending = line.end_with?("\n".b)
          line = line.sub(/\r\n\z/, "\n".b)
          line = ">".b + line if line.match?(QUOTED_FROM_LINE)
          io.write(line)
        end

        io.write("\n".b) unless source.empty? || had_line_ending
      end

      def message_source(message)
        source = message.raw_source.to_s
        source = message.encoded if source.empty?
        source
      end

      def envelope_for(message)
        raw_envelope = message.raw_envelope
        unless raw_envelope.nil? || raw_envelope.empty?
          return raw_envelope.sub(/\r?\n\z/, String.new)
        end

        sender = message.smtp_envelope_from || Constants::NULL_SENDER
        date = message.envelope_date || message.date
        date_text = format_envelope_date(date)

        date_text.empty? ? sender : "#{sender} #{date_text}"
      end

      def format_envelope_date(date)
        return String.new if date.nil?

        if date.respond_to?(:new_offset)
          date.new_offset(0).ctime
        elsif date.respond_to?(:getutc)
          date.getutc.ctime
        else
          date.to_s
        end
      end

      def binary_string
        String.new.force_encoding(Encoding::BINARY)
      end
    end
  end
end
