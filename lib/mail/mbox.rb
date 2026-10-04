# encoding: utf-8
# frozen_string_literal: true

require 'time'

module Mail

  # Streaming reader and writer for the mboxrd mailbox format, intended for
  # offline import/export of whole archives without loading them into memory.
  #
  # Reading:
  #
  #   Mail::Mbox::Reader.new(File.open('archive.mbox', 'rb')).each do |message|
  #     message                      # => Mail::Message
  #     message.mbox_envelope_sender # envelope sender from the "From " line, if usable
  #     message.mbox_envelope_time   # envelope timestamp from the "From " line, if usable
  #   end
  #
  # Writing (accepts any enumerable of Mail::Message or raw message strings):
  #
  #   Mail::Mbox::Writer.new(File.open('archive.mbox', 'wb')).write(messages)
  module Mbox

    # An mbox "From " separator line: sender token plus a ctime-style date.
    ENVELOPE_FROM_LINE = /\AFrom (\S+)[ \t]+(.+?)\s*\z/

    # Body lines that would be mistaken for a separator, including lines
    # already quoted with one or more ">" prefixes, must be escaped.
    ESCAPABLE_LINE = /\A(>*From )/

    # Mixed into each Mail::Message produced by Reader to carry the envelope
    # data recovered from the mbox "From " separator line.
    module Envelope
      # The envelope sender token from the "From " line, or nil when the
      # separator carried no usable sender.
      attr_accessor :mbox_envelope_sender

      # The envelope timestamp (a Time) parsed from the "From " line, or nil
      # when the separator carried no usable timestamp.
      attr_accessor :mbox_envelope_time
    end

    # Reads an mboxrd archive from an IO, yielding one Mail::Message per
    # message. The archive is consumed in fixed-size chunks and split into
    # lines across chunk boundaries, so messages are never separated by
    # inspecting the start of a chunk and the whole archive is never held
    # in memory.
    class Reader
      include Enumerable

      DEFAULT_CHUNK_SIZE = 16 * 1024

      attr_reader :io, :chunk_size

      def initialize(io, chunk_size: DEFAULT_CHUNK_SIZE)
        @io = io
        @chunk_size = chunk_size < 1 ? DEFAULT_CHUNK_SIZE : chunk_size
      end

      # Yields each message in the archive as a Mail::Message. Messages are
      # extended with Mail::Mbox::Envelope when their separator line carried
      # a usable envelope sender or timestamp.
      def each
        return enum_for(:each) unless block_given?

        lines = nil
        envelope = nil
        each_line do |line|
          if line.start_with?('From ')
            yield build_message(lines, envelope) if lines
            lines = []
            envelope = parse_envelope_line(line)
          elsif lines
            lines << line
          end
          # Anything before the first "From " line is not part of any
          # message and is ignored.
        end
        yield build_message(lines, envelope) if lines
      end

      private

      # Yields lines (including their trailing newline) from the IO, no
      # matter where chunk boundaries fall. The final line is yielded even
      # when the archive does not end with a newline.
      def each_line
        buffer = +''
        while (chunk = io.read(chunk_size))
          buffer << chunk
          while (index = buffer.index("\n"))
            yield buffer.slice!(0..index)
          end
        end
        yield buffer unless buffer.empty?
      end

      def parse_envelope_line(line)
        match = ENVELOPE_FROM_LINE.match(line)
        return [nil, nil] unless match

        sender = match[1]
        time = begin
          Time.parse(match[2])
        rescue ArgumentError, TypeError
          nil
        end
        [sender, time]
      end

      def build_message(lines, envelope)
        # The blank line preceding a "From " separator (or terminating the
        # final message) belongs to the separator, not the message.
        lines.pop if lines.last && lines.last.strip.empty?

        raw = lines.map { |line| unescape(line) }.join
        message = Mail::Message.new(raw)

        sender, time = envelope
        if sender || time
          message.extend(Envelope)
          message.mbox_envelope_sender = sender
          message.mbox_envelope_time = time
        end
        message
      end

      # Reverses mboxrd quoting: a line of one or more ">" followed by
      # "From " loses exactly one ">". All other lines are untouched.
      def unescape(line)
        line.sub(/\A>(>*From )/, '\\1')
      end
    end

    # Writes messages to an IO in mboxrd format. Accepts any enumerable of
    # Mail::Message objects or raw message strings, streaming one message at
    # a time.
    class Writer
      attr_reader :io

      def initialize(io)
        @io = io
      end

      # Writes every message in the enumerable, in order.
      def write(messages)
        messages.each { |message| self << message }
        self
      end

      # Appends a single message and returns self so calls can be chained.
      def <<(message)
        raw = message.to_s
        io.write(envelope_line(message))
        io.write(raw.gsub(/^(>*From )/, '>\\1'))
        io.write("\n") unless raw.end_with?("\n")
        io.write("\n") # blank separator line before the next "From " line
        self
      end

      private

      def envelope_line(message)
        sender = envelope_value(message, :mbox_envelope_sender) || from_address(message) || 'MAILER-DAEMON'
        time = envelope_value(message, :mbox_envelope_time) || message_date(message) || Time.now
        "From #{sender} #{time.strftime('%a %b %e %H:%M:%S %Y')}\n"
      end

      def envelope_value(message, name)
        message.public_send(name) if message.respond_to?(name)
      end

      def from_address(message)
        addresses = message.from if message.respond_to?(:from)
        addresses.first if addresses && !addresses.empty?
      rescue StandardError
        nil
      end

      def message_date(message)
        message.date if message.respond_to?(:date)
      rescue StandardError
        nil
      end
    end
  end
end
