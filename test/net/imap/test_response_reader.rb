# frozen_string_literal: true

require "net/imap"
require "stringio"
require "test/unit"

class ResponseReaderTest < Net::IMAP::TestCase

  class FakeClient
    def config = @config ||= Net::IMAP.config.new
    def max_response_size = config.max_response_size
  end

class ChunkIO
    attr_reader :read_sizes, :requested_sizes, :partial_sizes

    def initialize(data, chunk_size = 1)
      @data = data.b
      @chunk_size = chunk_size
      @pos = 0
      @read_sizes = []
      @requested_sizes = []
      @partial_sizes = []
    end

    def gets(_separator, limit = nil)
      return nil if eof?
      window_limit = limit || @data.bytesize - @pos
      window_stop = [@pos + window_limit, @data.bytesize].min
      window = @data.byteslice(@pos...window_stop)
      ending = window.index("\r\n")
      stop = ending && ending + 2 <= window.bytesize ? @pos + ending + 2 : window_stop
      chunk = @data.byteslice(@pos...stop)
      @pos = stop
      chunk
    end

    def read(size, buffer = nil)
      return nil if eof?
      @requested_sizes << size
      size = [size, @data.bytesize - @pos].min
      @read_sizes << size
      chunk = @data.byteslice(@pos, size)
      @pos += size
      buffer&.replace(chunk) || chunk
    end

    def readpartial(size, buffer = nil)
      @partial_sizes << size
      read([size, @chunk_size].min, buffer)
    end

    def eof? = @pos >= @data.bytesize
    def closed? = false
  end

  class TrackingSink
    attr_reader :written, :closed

    def initialize(fail_after: nil)
      @written = String.new.b
      @fail_after = fail_after
      @closed = false
    end

    def write(chunk)
      raise "sink is full" if @fail_after && @written.bytesize >= @fail_after
      @written << chunk
      chunk.bytesize
    end

    def close
      @closed = true
    end
  end

  def literal(str) = "{#{str.bytesize}}\r\n#{str}"

  class LiteralReceiver
    attr_reader :events

    def initialize(sink)
      @sink = sink
      @events = []
    end

    def call(response:, field:, bytesize:, binary:)
      events << [response.class, response.seqno, response.attr.dup, field, bytesize, binary]
      @sink
    end
  end

  test "#read_response streams accepted FETCH literals in chunks" do
    content = "line\r\n( ) { } ~{}\0\xff".b + "x" * (64 << 10)
    response = "* 7 FETCH (UID 8 BODY[] #{literal content} FLAGS (\\Seen))\r\n"
    next_response = "* 9 EXPUNGE\r\n"
    io = ChunkIO.new(response + next_response, 3)
    sink = TrackingSink.new
    receiver = LiteralReceiver.new(sink)
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io)
    reader.literal_receiver = receiver

    parsed = reader.read_response
    ref = parsed.data.attr["BODY[]"]
    assert_instance_of Net::IMAP::FetchData::LiteralReference, ref
    assert_equal "BODY[]", ref.field
    assert_equal content.bytesize, ref.bytesize
    assert_same sink, ref.receiver
    refute ref.binary
    assert_equal 8, parsed.data.uid
    assert_equal [:Seen], parsed.data.flags
    assert_equal content, sink.written
    refute_operator parsed.raw_data, :include?, content
    assert_equal [
      Net::IMAP::FetchData, 7, {"UID" => 8}, "BODY[]", content.bytesize, false
    ], receiver.events.first
    assert_equal content.bytesize, io.read_sizes.sum
    assert(io.read_sizes.max <= 3)
    assert_equal Net::IMAP::ResponseReader::LITERAL_CHUNK_SIZE,
                 io.partial_sizes.max

    assert_equal next_response, reader.read_response.raw_data
    refute sink.closed
  end

  test "#read_response buffers literals that the receiver declines" do
    content = "keep\0me".b
    response = "* 1 FETCH (RFC822.TEXT #{literal content} UID 2)\r\n"
    io = ChunkIO.new(response + "* OK ready\r\n", 2)
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io)
    reader.literal_receiver = proc { nil }

    parsed = reader.read_response
    assert_equal content, parsed.data.attr["RFC822.TEXT"]
    assert_equal 2, parsed.data.uid
    assert_equal "* OK ready\r\n", reader.read_response.raw_data
  end

  test "#read_response handles consecutive accepted and buffered literals" do
    first = "first\0".b
    second = "second\r\n".b
    response =
      "* 1 FETCH (BODY[1] #{literal first} BODY[2] #{literal second} UID 3)\r\n"
    io = ChunkIO.new(response + "* OK next\r\n", 2)
    sink = TrackingSink.new
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io)
    reader.literal_receiver = proc do |field:, **|
      field == "BODY[1]" ? sink : nil
    end

    parsed = reader.read_response
    assert_instance_of Net::IMAP::FetchData::LiteralReference,
                       parsed.data.attr["BODY[1]"]
    assert_equal first, sink.written
    assert_equal second, parsed.data.attr["BODY[2]"]
    assert_equal 3, parsed.data.uid
    assert_equal "* OK next\r\n", reader.read_response.raw_data
  end

  test "#read_response drains a literal after a receiver error" do
    content = "abcdef".b
    response = "* 1 FETCH (BODY[] #{literal content} UID 2)\r\n"
    io = ChunkIO.new(response + "* OK still aligned\r\n", 1)
    sink = TrackingSink.new(fail_after: 1)
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io)
    reader.literal_receiver = proc { sink }

    assert_raise_with_message(RuntimeError, "sink is full") do
      reader.read_response
    end
    assert_equal "* OK still aligned\r\n", reader.read_response.raw_data
    refute sink.closed
  end

  test "#read_response drains a literal after a receiver selection error" do
    response = "* 1 FETCH (BODY[] {3}\r\nabc UID 2)\r\n"
    io = ChunkIO.new(response + "* OK aligned\r\n", 1)
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io)
    reader.literal_receiver = proc { raise "cannot select" }

    assert_raise_with_message(RuntimeError, "cannot select") do
      reader.read_response
    end
    assert_equal "* OK aligned\r\n", reader.read_response.raw_data
  end

  test "#read_response counts streamed literals against max_response_size" do
    content = "x" * 8
    response = "* 1 FETCH (BODY[] {8}\r\n#{content})\r\n"
    client = FakeClient.new
    client.config.max_response_size = response.bytesize
    reader = Net::IMAP::ResponseReader.new(client, ChunkIO.new(response, 2))
    reader.literal_receiver = proc { TrackingSink.new }
    assert_instance_of Net::IMAP::FetchData::LiteralReference,
                       reader.read_response.data.attr["BODY[]"]

    client.config.max_response_size = response.bytesize - 1
    reader = Net::IMAP::ResponseReader.new(client, ChunkIO.new(response, 2))
    reader.literal_receiver = proc { TrackingSink.new }
    assert_raise(Net::IMAP::ResponseTooLargeError) { reader.read_response }
  end

  test "#read_response supports empty literal8 and ignores non-FETCH literals" do
    response = "* 1 FETCH (BINARY[1] ~{0}\r\n UID 2)\r\n"
    nested_literal = "* 3 FETCH (X-GM-LABELS ({5}\r\nready) UID 4)\r\n"
    io = ChunkIO.new(response + nested_literal, 1)
    sink = TrackingSink.new
    receiver = LiteralReceiver.new(sink)
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io)
    reader.literal_receiver = receiver

    parsed = reader.read_response
    ref = parsed.data.attr["BINARY[1]"]
    assert_instance_of Net::IMAP::FetchData::LiteralReference, ref
    assert_equal 0, ref.bytesize
    assert_predicate ref, :binary
    assert_equal "", sink.written
    assert_equal [["BINARY[1]", 0, true]],
                 receiver.events.map { _1[3..] }
    nested = reader.read_response
    assert_equal ["ready"], nested.data.attr["X-GM-LABELS"]
    assert_equal 4, nested.data.uid
    assert_equal [["BINARY[1]", 0, true]],
                 receiver.events.map { _1[3..] }
  end

  test "#read_response_buffer" do
    client = FakeClient.new
    aaaaaaaaa    = "a" * (20 << 10)
    many_crs     = "\r" * 1000
    many_crlfs   = "\r\n" * 500
    simple       = "* OK greeting\r\n"
    long_line    = "tag ok #{aaaaaaaaa} #{aaaaaaaaa}\r\n"
    literal_aaaa = "* fake #{literal aaaaaaaaa}\r\n"
    literal_crlf = "tag ok #{literal many_crlfs} #{literal many_crlfs}\r\n"
    zero_literal = "tag ok #{literal ""} #{literal ""}\r\n"
    illegal_crs  = "tag ok #{many_crs} #{many_crs}\r\n"
    illegal_lfs  = "tag ok #{literal "\r"}\n#{literal "\r"}\n\r\n"
    zero_padded  = "+ {010}\r\n1234567890\r\n" # NOTE: it's decimal, not octal!
    goofy_zero   = "+ {000}\r\n\r\n"
    io = StringIO.new([
      simple,
      long_line,
      literal_aaaa,
      literal_crlf,
      zero_literal,
      illegal_crs,
      illegal_lfs,
      zero_padded,
      goofy_zero,
      simple,
    ].join)
    rcvr = Net::IMAP::ResponseReader.new(client, io)
    assert_equal simple,       rcvr.read_response_buffer.to_str
    assert_equal long_line,    rcvr.read_response_buffer.to_str
    assert_equal literal_aaaa, rcvr.read_response_buffer.to_str
    assert_equal literal_crlf, rcvr.read_response_buffer.to_str
    assert_equal zero_literal, rcvr.read_response_buffer.to_str
    assert_equal illegal_crs,  rcvr.read_response_buffer.to_str
    assert_equal illegal_lfs,  rcvr.read_response_buffer.to_str
    assert_equal zero_padded,  rcvr.read_response_buffer.to_str
    assert_equal goofy_zero,   rcvr.read_response_buffer.to_str
    assert_equal simple,       rcvr.read_response_buffer.to_str
    assert_equal "",           rcvr.read_response_buffer.to_str
  end

  test "#read_response_buffer with max_response_size" do
    client = FakeClient.new
    client.config.max_response_size = 10
    under = "+ 3456\r\n"
    exact = "+ 345678\r\n"
    very_over     = "+ 3456789 #{?a * (16<<10)}}\r\n"
    slightly_over = "+ 34567890\r\n" # CRLF after the limit
    io = StringIO.new([under, exact, very_over, slightly_over].join, "rb")
    rcvr = Net::IMAP::ResponseReader.new(client, io)
    assert_equal under, rcvr.read_response_buffer.to_str
    assert_equal exact, rcvr.read_response_buffer.to_str
    assert_raise Net::IMAP::ResponseTooLargeError do
      result = rcvr.read_response_buffer
      flunk "Got result: %p" % [result]
    end
    io = StringIO.new(slightly_over, "rb")
    rcvr = Net::IMAP::ResponseReader.new(client, io)
    assert_raise Net::IMAP::ResponseTooLargeError do
      result = rcvr.read_response_buffer
      flunk "Got result: %p" % [result]
    end
  end

  test "#read_response_buffer max_response_size straddling CRLF" do
    barely_over = "+ 3456789\r\n"  # CRLF straddles the boundary
    client = FakeClient.new
    client.config.max_response_size = 10
    io = StringIO.new(barely_over, "rb")
    rcvr = Net::IMAP::ResponseReader.new(client, io)
    assert_raise Net::IMAP::ResponseTooLargeError do
      result = rcvr.read_response_buffer
      flunk "Got result: %p" % [result]
    end
  end

  data(
    bad_int64: "+ {99999999999999999999}\r\ndon't even try to read this...",
  )
  test "#read_response_buffer with invalid literal size" do |invalid|
    client  = FakeClient.new
    client.config.max_response_size = nil # any size is allowed!
    io = StringIO.new(invalid, "rb")
    rcvr = Net::IMAP::ResponseReader.new(client, io)
    assert_raise Net::IMAP::DataFormatError do
      result = rcvr.read_response_buffer
      flunk "Got result: %p" % [result]
    end
    # assert io.closed?
  end

  test "linear performance detecting literal continuation" do
    omit_unless_cruby "flaky on different platforms"
    omit_if(ENV["CI"], "slow and flaky, skipping in CI")

    client = FakeClient.new
    io = StringIO.new "", "rb"
    rcvr = Net::IMAP::ResponseReader.new(client, io)

    sequence = [100, 1_000, 10_000]
    assert_strict_linear_time(sequence, prepare: ->(n) {
      parts = Array.new(n) {|i| "BODY[#{i.succ}] {1}\r\nX" }.join(" ")
      response = "* 1 FETCH (#{parts})\r\n"
      embedded = "#{response}* OK next response\r\n"
      io.string = embedded
      assert_equal response, rcvr.read_response_buffer
      io.rewind
      response
    }) do
      io.rewind
      rcvr.read_response_buffer
    end
  end
end
