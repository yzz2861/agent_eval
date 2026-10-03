# frozen_string_literal: false
require 'net/http'
require 'test/unit'
require 'stringio'
require 'zlib'

class TestNetHTTPBodyStream < Test::Unit::TestCase
  BODY = 'hello streaming world ' * 50 # 1100 bytes

  # An IO-like object with separate read/write buffers, so that a full
  # request/response cycle can be driven through Net::BufferedIO without
  # opening a real socket.
  class FakeConnectionIO
    def initialize(read_data)
      @in = StringIO.new(read_data)
      @written = StringIO.new
      @closed = false
    end

    attr_reader :written

    def read_nonblock(len, buf = nil, exception: false)
      str = @in.read(len)
      raise EOFError, 'end of file reached' if str.nil?
      buf ? buf.replace(str) : str
    end

    def write_nonblock(str, exception: false)
      @written.write(str)
    end

    def eof?
      @in.eof?
    end

    def closed?
      @closed
    end

    def close
      @closed = true
    end

    def to_io
      self
    end

    def wait_readable(*)
      nil
    end

    def wait_writable(*)
      true
    end
  end

  def ok_response(body, headers = {})
    head = headers.map {|key, value| "#{key}: #{value}\r\n" }.join
    "HTTP/1.1 200 OK\r\n#{head}Content-Length: #{body.bytesize}\r\n\r\n#{body}"
  end

  def chunked_response(body, headers = {})
    head = headers.map {|key, value| "#{key}: #{value}\r\n" }.join
    raw = +"HTTP/1.1 200 OK\r\n#{head}Transfer-Encoding: chunked\r\n\r\n"
    body.scan(/.{1,97}/m) {|chunk| raw << "#{chunk.bytesize.to_s(16)}\r\n#{chunk}\r\n" }
    raw << "0\r\nX-Trailer: ignored\r\n\r\n"
    raw
  end

  def gzip(data)
    Zlib::Deflate.deflate(data, Zlib::DEFAULT_COMPRESSION)
  end

  # Parses a response from +raw+ and takes its body stream, as a client
  # would inside a Net::HTTP#request block.
  def stream_for(raw, decode_content: true, body_permitted: true)
    io = Net::BufferedIO.new(StringIO.new(raw))
    res = Net::HTTPResponse.read_new(io)
    res.decode_content = decode_content
    stream = nil
    res.reading_body(io, body_permitted) { stream = res.body_stream }
    [res, stream, io]
  end

  def read_all(stream, chunk = 777)
    data = +''
    begin
      data << stream.readpartial(chunk) until stream.eof?
    rescue EOFError
    end
    data
  end

  def http_over(io)
    http = Net::HTTP.new('example.org', 80)
    http.instance_variable_set(:@started, true)
    http.instance_variable_set(:@socket, Net::BufferedIO.new(io))
    http
  end

  def test_readpartial_content_length
    _res, stream, = stream_for(ok_response(BODY))
    assert_equal BODY[0, 100], stream.readpartial(100)
    assert_equal BODY[100, 100], stream.readpartial(100)
    assert_equal BODY[200..], stream.readpartial(10_000)
    assert_raise(EOFError) { stream.readpartial(1) }
    stream.close
  end

  def test_readpartial_returns_binary_strings
    _res, stream, = stream_for(ok_response(BODY))
    assert_equal Encoding::ASCII_8BIT, stream.readpartial(10).encoding
    stream.close
  end

  def test_readpartial_zero_and_negative_length
    _res, stream, = stream_for(ok_response(BODY))
    assert_equal '', stream.readpartial(0)
    assert_raise(ArgumentError) { stream.readpartial(-1) }
    stream.close
  end

  def test_readpartial_chunked
    _res, stream, = stream_for(chunked_response(BODY))
    assert_equal BODY, read_all(stream, 63)
    stream.close
  end

  def test_readpartial_gzip
    res, stream, = stream_for(ok_response(gzip(BODY), 'Content-Encoding' => 'gzip'))
    assert_equal BODY, read_all(stream, 999)
    assert_nil res['content-encoding']
    assert_equal BODY.bytesize.to_s, res['content-length']
    stream.close
  end

  def test_readpartial_chunked_gzip
    res, stream, = stream_for(chunked_response(gzip(BODY), 'Content-Encoding' => 'gzip'))
    assert_equal BODY, read_all(stream, 31)
    assert_nil res['content-encoding']
    stream.close
  end

  def test_readpartial_gzip_not_decoded_when_decode_content_is_false
    compressed = gzip(BODY)
    _res, stream, = stream_for(ok_response(compressed, 'Content-Encoding' => 'gzip'),
                               decode_content: false)
    assert_equal compressed, read_all(stream)
    stream.close
  end

  def test_readpartial_unknown_content_encoding_passes_through
    _res, stream, = stream_for(ok_response(BODY, 'Content-Encoding' => 'br'))
    assert_equal BODY, read_all(stream)
    stream.close
  end

  def test_readpartial_close_delimited_body
    raw = "HTTP/1.1 200 OK\r\n\r\n#{BODY}"
    _res, stream, = stream_for(raw)
    assert_equal BODY, read_all(stream)
    stream.close
  end

  def test_response_without_body_is_immediately_at_eof
    _res, stream, = stream_for(ok_response(''), body_permitted: false)
    assert_predicate stream, :eof?
    assert_raise(EOFError) { stream.readpartial(1) }
    stream.close
  end

  def test_eof?
    _res, stream, = stream_for(ok_response(BODY))
    assert_not_predicate stream, :eof?
    read_all(stream)
    assert_predicate stream, :eof?
    stream.close
  end

  def test_readpartial_with_string_outbuf
    _res, stream, = stream_for(ok_response(BODY))
    outbuf = +'stale'
    assert_same outbuf, stream.readpartial(5, outbuf)
    assert_equal BODY[0, 5], outbuf
    stream.close
  end

  def test_readpartial_with_io_outbuf_is_not_closed_by_stream
    _res, stream, = stream_for(ok_response(BODY))
    io = StringIO.new
    assert_same io, stream.readpartial(5, io)
    assert_equal BODY[0, 5], io.string
    stream.close
    assert_not_predicate io, :closed?
  end

  def test_close_is_idempotent_and_disallows_further_reads
    _res, stream, = stream_for(ok_response(BODY))
    stream.close
    assert_predicate stream, :closed?
    assert_nothing_raised { stream.close }
    assert_raise(IOError) { stream.readpartial(1) }
    assert_raise(IOError) { stream.eof? }
  end

  def test_body_stream_returns_the_same_stream
    io = Net::BufferedIO.new(StringIO.new(ok_response(BODY)))
    res = Net::HTTPResponse.read_new(io)
    res.reading_body(io, true) do
      assert_same res.body_stream, res.body_stream
      res.body_stream.close
    end
  end

  def test_body_stream_after_body_was_read_raises
    io = Net::BufferedIO.new(StringIO.new(ok_response(BODY)))
    res = Net::HTTPResponse.read_new(io)
    res.reading_body(io, true) do
      res.read_body
      assert_raise(IOError) { res.body_stream }
    end
  end

  def test_body_stream_out_of_request_block_raises
    io = Net::BufferedIO.new(StringIO.new(ok_response(BODY)))
    res = Net::HTTPResponse.read_new(io)
    res.reading_body(io, true) {}
    assert_raise(IOError) { res.body_stream }
  end

  def test_close_drains_small_remainder_and_keeps_connection
    _res, stream, io = stream_for(ok_response(BODY))
    stream.readpartial(10)
    reusable = nil
    stream.on_close = proc {|value| reusable = value }
    stream.close
    assert_equal true, reusable
    assert_not_predicate io, :closed?
  end

  def test_close_disconnects_when_remainder_exceeds_drain_limit
    body = 'a' * (Net::HTTPResponse::BodyStream::DRAIN_LIMIT + 100)
    _res, stream, io = stream_for(ok_response(body))
    stream.readpartial(1)
    reusable = nil
    stream.on_close = proc {|value| reusable = value }
    stream.close
    assert_equal false, reusable
    assert_predicate io, :closed?
  end

  def test_connection_is_busy_until_stream_is_closed
    io = FakeConnectionIO.new(ok_response('first') + ok_response('second'))
    http = http_over(io)
    stream = nil
    http.request(Net::HTTP::Get.new('/')) {|res| stream = res.body_stream }

    assert_raise(IOError) { http.get('/') }
    assert_not_predicate http.instance_variable_get(:@socket), :closed?

    stream.close
    res = assert_nothing_raised { http.get('/') }
    assert_equal 'second', res.body
  end

  def test_connection_is_reused_after_stream_is_fully_read_and_closed
    io = FakeConnectionIO.new(ok_response(BODY) + ok_response('second'))
    http = http_over(io)
    socket = http.instance_variable_get(:@socket)
    stream = nil
    http.request(Net::HTTP::Get.new('/')) {|res| stream = res.body_stream }

    assert_nil http.instance_variable_get(:@last_communicated)
    assert_equal BODY, read_all(stream)
    stream.close

    assert_not_nil http.instance_variable_get(:@last_communicated)
    assert_same socket, http.instance_variable_get(:@socket)
    assert_equal 'second', http.get('/').body
    assert_same socket, http.instance_variable_get(:@socket)
  end

  def test_connection_is_reused_after_early_close_within_drain_limit
    io = FakeConnectionIO.new(ok_response(BODY) + ok_response('second'))
    http = http_over(io)
    socket = http.instance_variable_get(:@socket)
    stream = nil
    http.request(Net::HTTP::Get.new('/')) {|res| stream = res.body_stream }

    stream.readpartial(10)
    stream.close

    assert_not_predicate socket, :closed?
    assert_equal 'second', http.get('/').body
    assert_same socket, http.instance_variable_get(:@socket)
  end

  def test_connection_is_shutdown_when_early_close_exceeds_drain_limit
    body = 'a' * (Net::HTTPResponse::BodyStream::DRAIN_LIMIT + 100)
    io = FakeConnectionIO.new(ok_response(body))
    http = http_over(io)
    socket = http.instance_variable_get(:@socket)
    stream = nil
    http.request(Net::HTTP::Get.new('/')) {|res| stream = res.body_stream }

    stream.readpartial(1)
    stream.close

    assert_predicate socket, :closed?
  end

  def test_connection_close_header_shuts_connection_down_on_stream_close
    raw = ok_response(BODY).sub("\r\n\r\n", "\r\nConnection: close\r\n\r\n")
    io = FakeConnectionIO.new(raw)
    http = http_over(io)
    socket = http.instance_variable_get(:@socket)
    stream = nil
    http.request(Net::HTTP::Get.new('/')) {|res| stream = res.body_stream }

    assert_equal BODY, read_all(stream)
    stream.close

    assert_predicate socket, :closed?
  end
end
