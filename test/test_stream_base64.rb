# frozen_string_literal: false
require "test/unit"
require "stringio"
require "xmlrpc/base64"
require "xmlrpc/create"
require "xmlrpc/parser"
require "xmlrpc/config"
require "xmlrpc/marshal"

class Test_StreamBase64 < Test::Unit::TestCase

  # A readable IO that refuses to return more than +limit+ bytes per
  # #read call, proving the encoder never asks for a giant buffer.
  class LimitedReader
    attr_reader :max_read, :close_count

    def initialize(data, limit, fail_after: nil)
      @data = data.b
      @offset = 0
      @limit = limit
      @max_read = 0
      @close_count = 0
      @fail_after = fail_after
      @reads = 0
    end

    def read(length)
      raise ArgumentError, "read of #{length} exceeds limit #{@limit}" if length > @limit
      @reads += 1
      raise "read failure" if @fail_after && @reads > @fail_after
      return nil if @offset >= @data.bytesize
      chunk = @data.byteslice(@offset, [length, @data.bytesize - @offset].min)
      @offset += chunk.bytesize
      @max_read = [@max_read, chunk.bytesize].max
      chunk
    end

    def close
      @close_count += 1
    end
  end

  # A writable IO that refuses single #write calls larger than +limit+
  # bytes, proving the decoder keeps its in-memory buffer bounded.
  class LimitedWriter
    attr_reader :max_written, :close_count

    def initialize(limit, fail_after_bytes: nil)
      @buf = String.new(encoding: Encoding::BINARY)
      @limit = limit
      @max_written = 0
      @close_count = 0
      @fail_after_bytes = fail_after_bytes
    end

    def string
      @buf
    end

    def write(chunk)
      raise ArgumentError, "write of #{chunk.bytesize} exceeds limit #{@limit}" if chunk.bytesize > @limit
      raise "write failure: sink full" if @fail_after_bytes && @buf.bytesize >= @fail_after_bytes
      n = [chunk.bytesize, @limit].min
      n = [1, n].max
      @buf << chunk.byteslice(0, n)
      @max_written = [@max_written, n].max
      n
    end

    def close
      @close_count += 1
    end
  end

  def setup
    @create = XMLRPC::Create.new
    @parser = XMLRPC::XMLParser::REXMLStreamParser.new
  end

  def random_bytes(count, seed = 1)
    n = seed
    bytes = []
    count.times do
      n = (n * 1103515245 + 12345) & 0x7fffffff
      bytes << (n % 256)
    end
    bytes.pack("C*")
  end

  def assert_sink_contents(data, sink, marker)
    assert_equal data.b, sink.string.b
    assert_same sink, marker
  end

  # Small data path: streaming output must be byte-identical to the
  # existing, fully-buffered output.
  def test_small_data_matches_existing_output
    samples = ["", "a", "ab", "abc", "abcd", "hello world",
               (0..255).map { |i| i.chr }.join]
    samples.each do |data|
      reader = LimitedReader.new(data, 64)
      stream = XMLRPC::Base64.stream(reader, read_size: 7)
      streamed = @create.methodCall_stream("m", stream).to_a.join
      existing = XMLRPC::Create.new.methodCall("m", XMLRPC::Base64.new(data))
      assert_equal existing, streamed, "streamed differs for #{data.bytesize} bytes"

      streamed2 = XMLRPC::Marshal.dump_call_stream("m",
        XMLRPC::Base64.stream(StringIO.new(data), read_size: 5)).to_a.join
      assert_equal existing, streamed2
    end
  end

  def test_stream_response_matches_existing_output
    data = random_bytes(300)
    streamed = @create.methodResponse_stream(true,
      XMLRPC::Base64.stream(StringIO.new(data), read_size: 13)).to_a.join
    existing = XMLRPC::Create.new.methodResponse(true, XMLRPC::Base64.new(data))
    assert_equal existing, streamed
  end

  # Bounded read buffer across arbitrary chunk sizes (including non
  # multiples of three) carries the 0-2 byte remainder over correctly.
  def test_encode_bounded_reads_various_chunk_sizes
    data = random_bytes(12_345)
    [1, 2, 3, 5, 7, 64, 255, 1024, 4096].each do |chunk_size|
      reader = LimitedReader.new(data, chunk_size)
      stream = XMLRPC::Base64.stream(reader, read_size: chunk_size)
      doc = @create.methodCall_stream("m",
        {"blob" => [stream, 42], "other" => "x"}).to_a.join
      ref = XMLRPC::Create.new.methodCall("m",
        {"blob" => [XMLRPC::Base64.new(data), 42], "other" => "x"})
      assert_equal ref, doc, "encoding differs with chunk size #{chunk_size}"
      assert_operator reader.max_read, :<=, chunk_size
    end
  end

  def test_encode_buffered_path_accepts_stream
    data = "streamed payload"
    doc = XMLRPC::Create.new.methodCall("m",
      XMLRPC::Base64.stream(StringIO.new(data), read_size: 4))
    assert_equal XMLRPC::Create.new.methodCall("m", XMLRPC::Base64.new(data)), doc
  end

  def test_decode_bounded_writes_with_split_events
    data = random_bytes(50_000)
    doc = XMLRPC::Create.new.methodCall("m",
      "before", XMLRPC::Base64.new(data),
      {"name" => "n", "blob" => XMLRPC::Base64.new(data + "!!"), "after" => 7},
      [XMLRPC::Base64.new("tiny")])

    big_sink   = LimitedWriter.new(1000)
    other_sink = LimitedWriter.new(37)
    big_target   = XMLRPC::Base64.sink(big_sink, write_size: 1000)
    other_target = XMLRPC::Base64.sink(other_sink, write_size: 37)

    name, params = @parser.parseMethodCall(doc, base64_sink: ->(path) {
      case path
      in [1] then big_target
      in [2, "blob"] then other_target
      else nil
      end
    })

    assert_equal "m", name
    assert_equal "before", params[0]
    assert_sink_contents data, big_sink, params[1]
    assert_equal "n", params[2]["name"]
    assert_equal 7, params[2]["after"]
    assert_sink_contents(data + "!!", other_sink, params[2]["blob"])
    assert_equal "tiny", params[3][0]
    assert_operator big_sink.max_written, :<=, 1000
    assert_operator other_sink.max_written, :<=, 37
  end

  def test_decode_response_sink
    data = random_bytes(9001, 7)
    doc = XMLRPC::Create.new.methodResponse(true, XMLRPC::Base64.new(data))
    sink = LimitedWriter.new(512)
    target = XMLRPC::Base64.sink(sink, write_size: 512)
    ok, value = XMLRPC::XMLParser::REXMLStreamParser.new.
      parseMethodResponse(doc, base64_sink: ->(path) { path == [0] ? target : nil })
    assert_equal true, ok
    assert_sink_contents data, sink, value
  end

  def test_decode_split_quanta_and_padding
    sizes = (0..20).to_a + [61, 62, 63, 64, 100, 4095, 4096]
    sizes.each do |n|
      data = n.times.map { |i| (i * 37 + 11) % 256 }.pack("C*")
      encoded = XMLRPC::Base64.encode(data).gsub(/\s+/, "")

      sink = LimitedWriter.new(3)
      decoder = XMLRPC::Base64::StrictDecoder.new(sink, write_size: 3)
      encoded.each_char { |c| decoder.decode(c) }
      decoder.finish
      assert_equal data, sink.string.b, "round trip differs for #{n} bytes"
    end
  end

  def test_decode_whitespace_between_every_character
    data = "binary stream data"
    spaced = XMLRPC::Base64.encode(data).gsub(/\s+/, "").
      chars.zip(["\n", " ", "\t"].cycle).map(&:join).join

    doc = %Q{<methodCall><methodName>m</methodName><params>
      <param><value><base64>#{spaced}</base64></value></param></params></methodCall>}
    sink = LimitedWriter.new(5)
    target = XMLRPC::Base64.sink(sink, write_size: 5)
    _, params = @parser.parseMethodCall(doc, base64_sink: ->(p) { p == [0] ? target : nil })
    assert_equal data, sink.string.b
    assert_same sink, params[0]
  end

  def test_decode_malformed_does_not_finish_value
    %w[!!!= A=AA AA=A ==AA AAAA== AB=X A].each do |bad|
      xml = %Q{<methodCall><methodName>m</methodName><params>
               <param><value><base64>#{bad}</base64></value></param>
             </params></methodCall>}
      sink = LimitedWriter.new(64)
      assert_raise(XMLRPC::Base64::FormatError) do
        @parser.parseMethodCall(xml, base64_sink: ->(p) { p == [0] ? sink : nil })
      end
      assert_equal Encoding::BINARY, sink.string.encoding
    end
  end

  def test_decode_single_character_tail_is_an_error
    sink = LimitedWriter.new(16)
    decoder = XMLRPC::Base64::StrictDecoder.new(sink, write_size: 16)
    decoder.decode("Q")
    assert_raise(XMLRPC::Base64::FormatError) { decoder.finish }
  end

  def test_sink_write_failure_aborts_and_closes_owned
    doc = XMLRPC::Create.new.methodCall("m", XMLRPC::Base64.new("x" * 10_000))
    sink = LimitedWriter.new(256, fail_after_bytes: 2000)
    owned = XMLRPC::Base64.sink(sink, close: true, write_size: 256)
    assert_raise(RuntimeError) do
      @parser.parseMethodCall(doc, base64_sink: ->(p) { p == [0] ? owned : nil })
    end
    assert_equal 1, sink.close_count
  end

  def test_resolver_cancellation_aborts
    doc = XMLRPC::Create.new.methodCall("m", XMLRPC::Base64.new("abc"))
    assert_raise(RuntimeError) do
      @parser.parseMethodCall(doc, base64_sink: ->(_path) { raise "cancelled" })
    end
  end

  def test_owned_sink_closed_on_malformed_document
    doc = %Q{<methodCall><methodName>m</methodName><params>
             <param><value><base64>@@@</base64></value></param></params></methodCall>}
    sink = LimitedWriter.new(16)
    owned = XMLRPC::Base64.sink(sink, close: true)
    assert_raise(XMLRPC::Base64::FormatError) do
      @parser.parseMethodCall(doc, base64_sink: ->(p) { p == [0] ? owned : nil })
    end
    assert_equal 1, sink.close_count
  end

  def test_unowned_sink_is_not_closed
    doc = XMLRPC::Create.new.methodCall("m", XMLRPC::Base64.new("abc"))
    sink = LimitedWriter.new(16)
    @parser.parseMethodCall(doc, base64_sink: ->(p) { p == [0] ? sink : nil })
    assert_equal 0, sink.close_count
  end

  def test_owned_source_closed_on_completion_abort_and_break
    data = "y" * 500

    reader = LimitedReader.new(data, 10)
    stream = XMLRPC::Base64.stream(reader, close: true, read_size: 10)
    @create.methodCall_stream("m", stream).to_a
    assert_equal 1, reader.close_count

    reader = LimitedReader.new(data, 10)
    stream = XMLRPC::Base64.stream(reader, close: true, read_size: 10)
    pieces = 0
    @create.methodCall_stream("m", stream) { pieces += 1; break if pieces > 2 }
    assert_equal 1, reader.close_count

    reader = LimitedReader.new(data, 5, fail_after: 3)
    stream = XMLRPC::Base64.stream(reader, close: true, read_size: 5)
    assert_raise(RuntimeError) { @create.methodCall_stream("m", stream).to_a }
    assert_equal 1, reader.close_count

    reader = LimitedReader.new(data, 10)
    stream = XMLRPC::Base64.stream(reader, close: false, read_size: 10)
    @create.methodCall_stream("m", stream).to_a
    assert_equal 0, reader.close_count
  end

  def test_owned_source_closed_when_consumer_raises
    data = "y" * 500
    reader = LimitedReader.new(data, 10)
    stream = XMLRPC::Base64.stream(reader, close: true, read_size: 10)
    assert_raise(RuntimeError) do
      @create.methodCall_stream("m", stream).each_with_index do |_piece, i|
        raise "consumer abort" if i > 18
      end
    end
    assert_equal 1, reader.close_count
  end

  def test_sink_wrapper_requires_write_io
    assert_raise(ArgumentError) { XMLRPC::Base64.sink(Object.new) }
    assert_raise(ArgumentError) { XMLRPC::Base64.sink(StringIO.new(""), write_size: 0) }
  end

  def test_stream_wrapper_requires_read_io
    assert_raise(ArgumentError) { XMLRPC::Base64.stream(Object.new) }
    assert_raise(ArgumentError) { XMLRPC::Base64.stream(StringIO.new(""), read_size: -1) }
  end

  def test_non_stream_base64_values_still_parse_normally
    data = "\x00\xff\x7fabc".b
    doc = XMLRPC::Create.new.methodCall("m", [XMLRPC::Base64.new(data), 1])
    name, params = @parser.parseMethodCall(doc)
    assert_equal "m", name
    assert_equal [[data, 1]], params
  end

  def test_marshal_facade_streams_into_sinks
    data = "facade data " * 100
    doc = XMLRPC::Marshal.dump_call("m", XMLRPC::Base64.new(data))
    sink = LimitedWriter.new(50)
    target = XMLRPC::Base64.sink(sink, write_size: 50)
    name, params = XMLRPC::Marshal.new.load_call(doc,
      base64_sink: ->(p) { p == [0] ? target : nil })
    assert_equal "m", name
    assert_sink_contents data, sink, params[0]

    sink2 = LimitedWriter.new(50)
    target2 = XMLRPC::Base64.sink(sink2, write_size: 50)
    doc2 = XMLRPC::Marshal.dump_response(XMLRPC::Base64.new(data))
    value = XMLRPC::Marshal.new.load_response(doc2,
      base64_sink: ->(p) { p == [0] ? target2 : nil })
    assert_same sink2, value
    assert_equal data, sink2.string.b
  end
end
