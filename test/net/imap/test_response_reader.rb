# frozen_string_literal: true

require "net/imap"
require "stringio"
require "test/unit"

class ResponseReaderTest < Net::IMAP::TestCase

  class ChunkIO < StringIO
    def initialize(string, chunk_size, ...)
      super(string, ...)
      @chunk_size = chunk_size
    end

    def read(length, outbuf = nil)
      super([length, @chunk_size].min, outbuf)
    end
  end

  class WriteRaiser
    attr_reader :written

    def initialize(fail_after: nil)
      @written = String.new.b
      @fail_after = fail_after
    end

    def write(chunk)
      written << chunk
      raise "write failed" if @fail_after && written.bytesize > @fail_after
      chunk.bytesize
    end
  end

  class FakeClient
    def config = @config ||= Net::IMAP.config.new
    def max_response_size = config.max_response_size
  end

  def literal(str) = "{#{str.bytesize}}\r\n#{str}"

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

  test "diverts selected FETCH literals in small chunks and keeps parsing aligned" do
    content = "line1\r\n(x) \0\xff\r\nline2".b
    first  = "* 42 FETCH (UID 7 BODY[] {#{content.bytesize}}\r\n"
    suffix = " FLAGS (\\Seen))\r\n"
    second = "* OK next response\r\n"
    io = ChunkIO.new((first + content + suffix + second).b, 3)
    receiver_calls = []
    destination = StringIO.new.tap { _1.set_encoding(Encoding::BINARY) }
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io) do |response, field, size|
      receiver_calls << [response.class, response.seqno, field, size]
      destination if field == "BODY[]"
    end

    buffer = reader.read_response_buffer
    references = reader.consume_literal_references
    parsed = Net::IMAP::ResponseParser.new.parse(
      buffer, literal_references: references
    )
    reference = parsed.data.attr["BODY[]"]

    assert_equal content, destination.string
    assert_equal [[Net::IMAP::FetchData, 42, "BODY[]", content.bytesize]],
                 receiver_calls
    assert_instance_of Net::IMAP::FetchData::LiteralReference, reference
    assert_equal "BODY[]", reference.field
    assert_equal content.bytesize, reference.bytesize
    assert_same destination, reference.receiver
    assert_equal [:Seen], parsed.data.flags
    assert_equal 7, parsed.data.uid
    assert_equal second, reader.read_response_buffer
    refute destination.closed?
  end

  test "diverts literal8 and allows quoted literals with the same bytes" do
    content = "\0\"{3}".b
    response = "* 1 FETCH (BINARY[1] ~{#{content.bytesize}}\r\n#{content})\r\n"
    next_response = "* OK {0}\r\n\r\n"
    io = ChunkIO.new(response + next_response, 2)
    destination = StringIO.new.tap { _1.set_encoding(Encoding::BINARY) }
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io) do |_response, field, _size|
      destination if field == "BINARY[1]"
    end

    buffer = reader.read_response_buffer
    parsed = Net::IMAP::ResponseParser.new.parse(
      buffer, literal_references: reader.consume_literal_references
    )

    assert_equal content, destination.string
    assert_instance_of Net::IMAP::FetchData::LiteralReference,
                       parsed.data.attr["BINARY[1]"]
    assert_equal next_response, reader.read_response_buffer
  end

  test "skips preceding literals and only diverts the selected field" do
    label = "not selected".b
    message = "\0(){}\r\n".b
    response =
      "* 7 FETCH (X-GM-LABELS ({#{label.bytesize}}\r\n#{label}) " \
      "RFC822.SIZE 99 BINARY[1] ~{#{message.bytesize}}\r\n#{message})\r\n"
    io = ChunkIO.new(response + "* OK next\r\n", 5)
    destination = StringIO.new.tap { _1.set_encoding(Encoding::BINARY) }
    calls = []
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io) do |response, field, size|
      calls << [response.seqno, field, size]
      assert_equal 99, response.attr["RFC822.SIZE"]
      assert_equal [label], response.attr["X-GM-LABELS"]
      destination if field == "BINARY[1]"
    end

    parsed = Net::IMAP::ResponseParser.new.parse(
      reader.read_response_buffer,
      literal_references: reader.consume_literal_references,
    )

    assert_equal [[7, "BINARY[1]", message.bytesize]], calls
    assert_equal [label], parsed.data.attr["X-GM-LABELS"]
    assert_equal 99, parsed.data.attr["RFC822.SIZE"]
    assert_instance_of Net::IMAP::FetchData::LiteralReference,
                       parsed.data.attr["BINARY[1]"]
    assert_equal message, destination.string
    assert_equal "* OK next\r\n", reader.read_response_buffer
  end

  test "continues parsing normal fields when receiver rejects a field" do
    content = "message".b
    response = "* 1 FETCH (UID 9 RFC822.TEXT {#{content.bytesize}}\r\n#{content})\r\n"
    io = ChunkIO.new(response, 2)
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io) do |_response, field, _size|
      nil unless field == "BODY[]"
    end

    parsed = Net::IMAP::ResponseParser.new.parse(
      reader.read_response_buffer,
      literal_references: reader.consume_literal_references,
    )

    assert_equal content, parsed.data.attr["RFC822.TEXT"]
    assert_equal 9, parsed.data.uid
  end

  test "diverts zero byte literals and normalizes RFC822 brackets" do
    response = "* 1 FETCH (RFC822[] {0}\r\n)\r\n"
    io = ChunkIO.new(response + "* OK next\r\n", 2)
    calls = []
    destination = StringIO.new.tap { _1.set_encoding(Encoding::BINARY) }
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io) do |_response, field, size|
      calls << [field, size]
      destination if field == "RFC822"
    end

    parsed = Net::IMAP::ResponseParser.new.parse(
      reader.read_response_buffer,
      literal_references: reader.consume_literal_references,
    )

    assert_equal [["RFC822", 0]], calls
    assert_instance_of Net::IMAP::FetchData::LiteralReference,
                       parsed.data.attr["RFC822"]
    assert_equal "", destination.string
    assert_equal "* OK next\r\n", reader.read_response_buffer
  end

  test "receiver write errors drain the literal before raising at response end" do
    content = "abcdefghijklm".b
    first  = "* 1 FETCH (BODY[] {#{content.bytesize}}\r\n"
    suffix = ")\r\n* OK next\r\n"
    io = ChunkIO.new(first + content + suffix, 4)
    destination = WriteRaiser.new(fail_after: 5)
    reader = Net::IMAP::ResponseReader.new(FakeClient.new, io) do
      destination
    end

    assert_raise_with_message(RuntimeError, "write failed") do
      reader.read_response_buffer
    end
    assert_equal "abcdefgh", destination.written
    assert_equal "* OK next\r\n", reader.read_response_buffer
  end

  test "literal_receiver works through Net::IMAP without closing the receiver" do
    client_io, server_io = Socket.pair(:UNIX, :STREAM)
    content = "subject\r\n\r\nbody\r\n".b
    destination = StringIO.new
    destination.set_encoding(Encoding::BINARY)
    imap_class = Class.new(Net::IMAP) do
      define_method(:tcp_socket) { |_host, _port| client_io }
    end
    thread = Thread.new do
      server_io.write("* OK ready\r\n")
      server_io.readline
      server_io.write("* 1 FETCH (UID 3 BODY[] {#{content.bytesize}}\r\n")
      content.each_char.each_slice(3) { server_io.write(_1.join) }
      server_io.write(")\r\nRUBY0001 OK done\r\n")
    end

    imap = imap_class.new("localhost")
    result = imap.fetch(1, "BODY[]", literal_receiver: ->(response, field, size) do
      assert_instance_of Net::IMAP::FetchData, response
      assert_equal 1, response.seqno
      assert_equal "BODY[]", field
      assert_equal content.bytesize, size
      destination
    end).first
    thread.join

    reference = result.attr["BODY[]"]
    assert_instance_of Net::IMAP::FetchData::LiteralReference, reference
    assert_equal content, destination.string
    assert_equal 3, result.uid
    refute destination.closed?
  ensure
    imap&.disconnect
    server_io&.close
  end
end
