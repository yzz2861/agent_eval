# frozen_string_literal: true
require 'spec_helper'
require 'stringio'
require 'tmpdir'

RSpec.describe Mail::Mboxrd do
  let(:archive) do
    "From one@example.com Mon Aug 17 00:39:21 2009\r\n" \
      "From: one@example.com\r\n" \
      "\r\n" \
      "First line\r\n" \
      ">From quoted envelope\r\n" \
      ">>From doubly quoted envelope\r\n" \
      "From two@example.com Tue Aug 18 01:02:03 2009\n" \
      "From: two@example.com\n" \
      "\n" \
      "Last line without trailing newline"
  end

  class ChunkIO
    attr_reader :lengths, :maximum_length

    def initialize(data, chunk_size)
      @data = data.b
      @offset = 0
      @chunk_size = chunk_size
      @lengths = []
      @maximum_length = 0
    end

    def read(length)
      @lengths << length
      @maximum_length = [maximum_length, length].max
      return nil if @offset >= @data.length

      chunk = @data.byteslice(@offset, [length, @chunk_size].min)
      @offset += chunk.bytesize
      chunk
    end
  end

  def read_messages(chunk_size: 1)
    io = ChunkIO.new(archive, chunk_size)
    messages = described_class.read(io, chunk_size).to_a
    [messages, io]
  end

  describe '.read' do
    (1..16).each do |chunk_size|
      it "splits messages at line boundaries with #{chunk_size}-byte reads" do
        messages, io = read_messages(chunk_size: chunk_size)

        expect(messages.size).to eq(2)
        expect(messages.first.envelope_from).to eq('one@example.com')
        expect(messages.first.envelope_date).to eq(DateTime.parse('Mon Aug 17 00:39:21 2009'))
        expect(messages.last.envelope_from).to eq('two@example.com')
        expect(messages.last.envelope_date).to eq(DateTime.parse('Tue Aug 18 01:02:03 2009'))
        expect(io.maximum_length).to eq(chunk_size)
      end
    end

    it 'keeps a complete message in memory while reading' do
      messages, io = read_messages

      expect(messages.first.raw_source.b).to eq(
        "From: one@example.com\r\n" \
        "\r\n" \
        "First line\r\n" \
        "From quoted envelope\r\n" \
        ">From doubly quoted envelope\r\n"
      )
      expect(messages.first.body.decoded).to eq(
        "First line\n" \
        "From quoted envelope\n" \
        ">From doubly quoted envelope\n"
      )
      expect(messages.last.raw_source.b).to eq(
        "From: two@example.com\n\nLast line without trailing newline"
      )
      expect(messages.last.body.decoded).to eq('Last line without trailing newline')
      expect(io.lengths).not_to be_empty
      expect(io.lengths.max).to eq(1)
    end

    it 'preserves usable envelope sender and time after writing' do
      data = "From MAILER-DAEMON Mon Aug 17 00:39:21 2009\nFrom: a@example.com\n\nbody"
      message = described_class.read(StringIO.new(data), 2).first

      output = StringIO.new.tap { |io| described_class.write(io, [message]) }.string

      expect(output).to start_with("From MAILER-DAEMON Mon Aug 17 00:39:21 2009\n")
      expect(message.envelope_from).to eq('MAILER-DAEMON')
      expect(message.envelope_date).to eq(DateTime.parse('Mon Aug 17 00:39:21 2009'))
    end

    it 'keeps the sender when a malformed envelope date cannot be parsed' do
      data = "From foo@bar Mon Aug 17 99:99:99 2009\nFrom: foo@bar\n\nbody"
      message = described_class.read(StringIO.new(data), 2).first

      output = StringIO.new.tap { |io| described_class.write(io, [message]) }.string

      expect(message.envelope_from).to eq('foo@bar')
      expect(message.envelope_date).to be_nil
      expect(message.raw_envelope).to eq('foo@bar Mon Aug 17 99:99:99 2009')
      expect(output).to start_with(data.split("\n", 2).first + "\n")
    end

    it 'does not infer a date from an incomplete ctime timestamp' do
      data = "From foo@bar 00:39:21\nFrom: foo@bar\n\nbody"
      message = described_class.read(StringIO.new(data), 2).first

      expect(message.envelope_from).to eq('foo@bar')
      expect(message.envelope_date).to be_nil
      expect(message.raw_envelope).to eq('foo@bar 00:39:21')
    end

    it 'only treats an unquoted envelope line as a separator' do
      data = "From one@example.com\n" \
        "From: one@example.com\n\n" \
        ">>From keep one\n" \
        ">From keep two\n" \
        "From not a header and not quoted\n" \
        "From: second@example.com\n\nsecond"

      messages = described_class.read(StringIO.new(data), 1).to_a

      expect(messages.map(&:envelope_from)).to eq(
        ['one@example.com', 'not']
      )
      expect(messages.first.raw_source).to include(">From keep one\nFrom keep two\n")
      expect(messages.last.from).to eq(['second@example.com'])
    end

    it 'ignores data before the first envelope line' do
      data = "not an archive yet\nFrom a@example.com\nFrom: a@example.com\n\nbody"

      messages = described_class.read(StringIO.new(data), 2).to_a

      expect(messages.size).to eq(1)
      expect(messages.first.envelope_from).to eq('a@example.com')
      expect(messages.first.raw_source).to eq("From: a@example.com\n\nbody")
    end

    it 'does not treat a chunk that starts with From as an envelope' do
      chunks = [
        "From one@ex",
        "ample.com\n",
        "From: one@",
        "example.com\n\n",
        "body\n",
        "From two@",
        "example.com\n",
        "From: two@",
        "example.com\n\nsecond"
      ]
      io = Object.new
      index = 0
      io.define_singleton_method(:read) { |_| chunks[index].tap { index += 1 } }

      messages = described_class.read(io, 7).to_a

      expect(messages.map(&:envelope_from)).to eq(
        ['one@example.com', 'two@example.com']
      )
      expect(messages.last.raw_source).to end_with('second')
    end

    it 'yields messages lazily and returns an enumerator without a block' do
      messages = read_messages.first

      expect(described_class.read(StringIO.new(archive), 1)).to be_an(Enumerator)
      expect(messages.last.body.decoded).to eq('Last line without trailing newline')
    end

    it 'streams a real file without retaining previous messages' do
      message_archive = "From a@example.com Mon Aug 17 00:39:21 2009\nFrom: a@example.com\n\nbody\n"
      Dir.mktmpdir do |directory|
        path = File.join(directory, 'archive.mbox')
        File.binwrite(path, message_archive * 128)
        count = 0

        File.open(path, 'rb') do |file|
          described_class.read(file, 7) do |message|
            expect(message.envelope_from).to eq('a@example.com')
            count += 1
          end
        end

        expect(count).to eq(128)
      end
    end

    it 'rejects non-positive chunk sizes' do
      expect { described_class.read(StringIO.new(archive), 0) }
        .to raise_error(ArgumentError, 'chunk_size must be a positive integer')
    end
  end

  describe '.write' do
    it 'writes an enumerable of messages and terminates every message' do
      first = Mail::Message.new("From: one@example.com\n\nFirst\n")
      first.set_envelope('one@example.com Mon Aug 17 00:39:21 2009')
      second = Mail::Message.new("From: two@example.com\n\nLast")
      second.set_envelope('two@example.com Tue Aug 18 01:02:03 2009')
      io = StringIO.new

      described_class.write(io, [first, second])

      expect(io.string.b).to eq(
        "From one@example.com Mon Aug 17 00:39:21 2009\n" \
        "From: one@example.com\n" \
        "\n" \
        "First\n" \
        "From two@example.com Tue Aug 18 01:02:03 2009\n" \
        "From: two@example.com\n" \
        "\n" \
        "Last\n"
      )
    end

    it 'derives an envelope sender and UTC time without an existing envelope' do
      message = Mail::Message.new do
        from 'alice@example.com'
        date 'Mon, 17 Aug 2009 10:39:21 +1000'
        body 'body'
      end
      output = StringIO.new.tap { |io| described_class.write(io, [message]) }.string

      expect(output).to start_with(
        "From alice@example.com Mon Aug 17 00:39:21 2009\n"
      )
    end

    it 'does not add two newlines to a CRLF message with a trailing line ending' do
      message = Mail::Message.new("From: a@example.com\r\n\r\nbody\r\n")
      message.set_envelope('a@example.com Mon Aug 17 00:39:21 2009')

      output = StringIO.new.tap { |io| described_class.write(io, [message]) }.string

      expect(output).to end_with("body\n")
      expect(output).not_to end_with("body\n\n")
    end

    it 'escapes envelope-looking lines without double-escaping quoted lines' do
      message = Mail::Message.new(
        "From: a@example.com\n\n" \
        "From one\n" \
        ">From two\n" \
        ">>From three\n"
      )
      message.set_envelope('a@example.com Mon Aug 17 00:39:21 2009')

      output = StringIO.new.tap { |io| described_class.write(io, [message]) }.string

      expect(output).to include(
        ">From one\n" \
        ">>From two\n" \
        ">>>From three\n"
      )
    end

    it 'escapes a bare From line even at the end of the archive' do
      message = Mail::Message.new("From: a@example.com\n\nFrom")
      message.set_envelope('a@example.com Mon Aug 17 00:39:21 2009')

      output = StringIO.new.tap { |io| described_class.write(io, [message]) }.string
      reread = described_class.read(StringIO.new(output), 1).first

      expect(output).to end_with(">From\n")
      expect(reread.body.decoded).to eq("From\n")
    end

    it 'supports readers that signal EOF with an empty read' do
      data = "From a@example.com\nFrom: a@example.com\n\nbody"
      calls = 0
      io = Object.new
      io.define_singleton_method(:read) do |length|
        calls += 1
        calls == 1 ? data : String.new
      end

      messages = described_class.read(io, 32).to_a

      expect(messages.size).to eq(1)
      expect(messages.first.body.decoded).to eq('body')
    end

    it 'consumes an enumerable lazily' do
      first = Mail::Message.new("From: one@example.com\n\nfirst")
      first.set_envelope('one@example.com Mon Aug 17 00:39:21 2009')
      second = Mail::Message.new("From: two@example.com\n\nsecond")
      second.set_envelope('two@example.com Tue Aug 18 01:02:03 2009')
      yielded = []
      messages = Enumerator.new do |yielder|
        [first, second].each do |message|
          yielded << message
          yielder << message
        end
      end
      io = StringIO.new

      described_class.write(io, messages.take(1))

      expect(yielded).to eq([first])
      expect(io.string).to start_with('From one@example.com')
      expect(io.string).to end_with("first\n")
    end

    it 'round trips existing mboxrd quoting for every small chunk size' do
      first = Mail::Message.new("From: one@example.com\n\nbody")
      first.set_envelope('one@example.com Mon Aug 17 00:39:21 2009')
      second = Mail::Message.new("From: two@example.com\n\nFrom body\n>From quoted")
      second.set_envelope('two@example.com Tue Aug 18 01:02:03 2009')
      written = StringIO.new.tap { |io| described_class.write(io, [first, second]) }.string

      (1..16).each do |chunk_size|
        messages = described_class.read(StringIO.new(written), chunk_size).to_a
        rewrote = StringIO.new.tap { |io| described_class.write(io, messages) }.string

        expect(rewrote).to eq(written)
        expect(messages.map(&:envelope_from)).to eq(
          ['one@example.com', 'two@example.com']
        )
        expect(messages.last.body.decoded).to eq("From body\n>From quoted\n")
      end
    end
  end
end
