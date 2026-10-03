# frozen_string_literal: false
require 'net/http'
require 'stringio'
require 'test/unit'

class HTTPRequestTest < Test::Unit::TestCase

  class Waiter
    def initialize(read_io, write_io)
      @read_io = read_io
      @write_io = write_io
    end

    def wait_readable(timeout = nil)
      @read_io.wait_readable(timeout)
    end

    def wait_writable(timeout = nil)
      @write_io.wait_writable(timeout)
    end
  end

  # Bidirectional fake connection built from two IO.pipe pairs so it works
  # without binding to a network port.
  class FakeSocketIO
    def initialize(write_io, read_io)
      @write_io = write_io
      @read_io = read_io
    end

    def to_io
      Waiter.new(@read_io, @write_io)
    end

    def write_nonblock(str, exception: true)
      @write_io.write_nonblock(str, exception: exception)
    end

    def read_nonblock(maxlen, buf = nil, exception: true)
      @read_io.read_nonblock(maxlen, buf, exception: exception)
    end

    def shutdown(how)
      @write_io.close unless @write_io.closed?
    end

    # Simulates the peer shutting down the read half: writes by the other end
    # then fail with EPIPE, while the final response already queued in the
    # opposite pipe stays readable.
    def close_read
      @write_io.close unless @write_io.closed?
    end

    def close
      @write_io.close unless @write_io.closed?
      @read_io.close unless @read_io.closed?
    end

    def closed?
      @read_io.closed?
    end

    def eof?
      @read_io.eof?
    end

    def write(*strs)
      @write_io.write(*strs)
    end
  end

  # Upload source that counts consumed bytes; reading stops permanently once
  # the requested number of bytes has been consumed, simulating a source much
  # larger than what the server is willing to accept.
  class CountingSource
    def initialize(size)
      @size = size
      @sent = 0
    end

    attr_reader :sent

    def read(len, buf = nil)
      return nil if @sent >= @size
      chunk = [len, @size - @sent].min
      @sent += chunk
      chunk = 'a' * chunk
      if buf
        buf.replace(chunk)
        buf
      else
        chunk
      end
    end
  end

  def make_sockets
    client_read, server_write = IO.pipe
    server_read, client_write = IO.pipe
    server_io = FakeSocketIO.new(server_write, server_read)
    client_io = FakeSocketIO.new(client_write, client_read)
    [server_io, client_io]
  end

  def buffered(io)
    Net::BufferedIO.new(io, read_timeout: 5, write_timeout: 5)
  end

  def read_request_head(server_io)
    head = +''
    deadline = Time.now + 2
    until head.end_with?("\r\n\r\n")
      begin
        head << server_io.read_nonblock(4096)
      rescue IO::WaitReadable
        flunk('timed out waiting for request head') if Time.now > deadline
        server_io.to_io.wait_readable(0.1)
        retry
      end
    end
    head
  end

  def drain_upload(server_io, amount)
    total = 0
    deadline = Time.now + 2
    while total < amount
      chunk = server_io.read_nonblock(amount - total)
      total += chunk.bytesize
    end
    total
  rescue IO::WaitReadable
    raise if Time.now > deadline
    server_io.to_io.wait_readable(0.1)
    retry
  end

  def reject_upload(server_io, status, informational = 0)
    read_request_head(server_io)
    drain_upload(server_io, 65536)
    informational.times do
      server_io.write("HTTP/1.1 100 Continue\r\n\r\n")
      drain_upload(server_io, 65536)
    end
    server_io.write("HTTP/1.1 #{status}\r\nContent-Length: 9\r\n" +
                    "Connection: close\r\n\r\ntoo large")
  end

  # Runs the request on the current thread and the given server script on a
  # background thread so the two sides proceed concurrently (required because
  # pipes have bounded buffers).
  def run_early_request(sock, req)
    result = nil
    server_error = nil
    server = Thread.new do
      Thread.current.report_on_exception = false
      begin
        yield
      rescue StandardError => error
        server_error = error
      end
    end
    result = catch(:response) { req.exec(sock, '1.1', '/') }
    assert server.join(5), 'server script did not finish'
    raise server_error if server_error
    result
  end

  def test_early_response_defaults_to_disabled
    req = Net::HTTP::Post.new('/')
    assert_not_predicate req, :early_response?
    assert_not_predicate req, :early_response_aborted?
  end

  def test_early_response_requires_length_or_chunked
    server_io, client_io = make_sockets
    sock = buffered(client_io)
    req = Net::HTTP::Post.new('/')
    req.body_stream = StringIO.new('abc')
    req.early_response = true
    assert_raise(ArgumentError) do
      req.exec(sock, '1.1', '/')
    end
  ensure
    server_io&.close
    client_io&.close
  end

  def test_early_response_returns_final_response_and_stops_source
    server_io, client_io = make_sockets
    sock = buffered(client_io)
    source = CountingSource.new(50 * 1024 * 1024)
    req = Net::HTTP::Post.new('/')
    req.content_length = 50 * 1024 * 1024
    req.body_stream = source
    req.early_response = true

    response = run_early_request(sock, req) do
      reject_upload(server_io, '413 Payload Too Large')
    end

    assert_kind_of Net::HTTPPayloadTooLarge, response
    assert_predicate req, :early_response_aborted?
    assert_operator source.sent, :<, 2 * 1024 * 1024
  ensure
    server_io&.close
    client_io&.close
  end

  def test_early_response_continues_after_informational_response
    server_io, client_io = make_sockets
    sock = buffered(client_io)
    source = CountingSource.new(50 * 1024 * 1024)
    req = Net::HTTP::Post.new('/')
    req.content_length = 50 * 1024 * 1024
    req.body_stream = source
    req.early_response = true

    response = run_early_request(sock, req) do
      reject_upload(server_io, '413 Payload Too Large', 2)
    end

    assert_kind_of Net::HTTPPayloadTooLarge, response
    assert_predicate req, :early_response_aborted?
  ensure
    server_io&.close
    client_io&.close
  end

  def test_early_response_with_chunked_streaming
    server_io, client_io = make_sockets
    sock = buffered(client_io)
    source = CountingSource.new(50 * 1024 * 1024)
    req = Net::HTTP::Post.new('/', 'Transfer-Encoding' => 'chunked')
    req.body_stream = source
    req.early_response = true

    response = run_early_request(sock, req) do
      reject_upload(server_io, '413 Payload Too Large')
    end

    assert_kind_of Net::HTTPPayloadTooLarge, response
    assert_predicate req, :early_response_aborted?
    assert_operator source.sent, :<, 2 * 1024 * 1024
  ensure
    server_io&.close
    client_io&.close
  end

  def test_early_response_normal_completion_marks_connection_reusable
    server_io, client_io = make_sockets
    sock = buffered(client_io)
    body = 'hello world'
    req = Net::HTTP::Post.new('/')
    req.content_length = body.bytesize
    req.body_stream = StringIO.new(body)
    req.early_response = true

    response = run_early_request(sock, req) do
      read_request_head(server_io)
      drain_upload(server_io, body.bytesize)
      server_io.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" +
                      "Connection: keep-alive\r\n\r\nok")
    end

    assert_kind_of Net::HTTPOK, response
    assert_not_predicate req, :early_response_aborted?
  ensure
    server_io&.close
    client_io&.close
  end

  # When the sender dies with a broken pipe (server stopped reading after its
  # final response), a fully parseable final response still wins.
  def test_early_response_prefers_final_response_over_broken_pipe
    server_io, client_io = make_sockets
    sock = buffered(client_io)
    source = CountingSource.new(50 * 1024 * 1024)
    req = Net::HTTP::Post.new('/')
    req.content_length = 50 * 1024 * 1024
    req.body_stream = source
    req.early_response = true

    response = run_early_request(sock, req) do
      read_request_head(server_io)
      drain_upload(server_io, 65536)
      server_io.write("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 9\r\n" +
                      "Connection: close\r\n\r\ntoo large")
      # Close the server read end so the sender gets a write error while it is
      # still streaming the remaining body.
      server_io.close_read
    end

    assert_kind_of Net::HTTPPayloadTooLarge, response
    assert_predicate req, :early_response_aborted?
  ensure
    server_io&.close
    client_io&.close
  end

  def test_early_response_raises_without_final_response
    server_io, client_io = make_sockets
    sock = buffered(client_io)
    source = CountingSource.new(50 * 1024 * 1024)
    req = Net::HTTP::Post.new('/')
    req.content_length = 50 * 1024 * 1024
    req.body_stream = source
    req.early_response = true

    assert_raise(Errno::EPIPE, EOFError) do
      run_early_request(sock, req) do
        read_request_head(server_io)
        drain_upload(server_io, 65536)
        server_io.close_read
        sleep 0.2
      end
    end
  ensure
    server_io&.close
    client_io&.close
  end

  def test_initialize_GET
    req = Net::HTTP::Get.new '/'

    assert_equal 'GET', req.method
    assert_not_predicate req, :request_body_permitted?
    assert_predicate req, :response_body_permitted?

    expected = {
      'accept'     => %w[*/*],
      'user-agent' => %w[Ruby],
    }

    expected['accept-encoding'] = %w[gzip;q=1.0,deflate;q=0.6,identity;q=0.3] if
      Net::HTTP::HAVE_ZLIB

    assert_equal expected, req.to_hash
  end

  def test_initialize_GET_range
    req = Net::HTTP::Get.new '/', 'Range' => 'bytes=0-9'

    assert_equal 'GET', req.method
    assert_not_predicate req, :request_body_permitted?
    assert_predicate req, :response_body_permitted?

    expected = {
      'accept'     => %w[*/*],
      'user-agent' => %w[Ruby],
      'range'      => %w[bytes=0-9],
    }

    assert_equal expected, req.to_hash
  end

  def test_initialize_HEAD
    req = Net::HTTP::Head.new '/'

    assert_equal 'HEAD', req.method
    assert_not_predicate req, :request_body_permitted?
    assert_not_predicate req, :response_body_permitted?

    expected = {
      'accept'          => %w[*/*],
      "accept-encoding" => %w[gzip;q=1.0,deflate;q=0.6,identity;q=0.3],
      'user-agent'      => %w[Ruby],
    }

    assert_equal expected, req.to_hash
  end

  def test_initialize_accept_encoding
    req1 = Net::HTTP::Get.new '/'

    assert req1.decode_content, 'Bug #7831 - automatically decode content'

    req2 = Net::HTTP::Get.new '/', 'accept-encoding' => 'identity'

    assert_not_predicate req2, :decode_content,
                         'Bug #7381 - do not decode content if the user overrides'
  end if Net::HTTP::HAVE_ZLIB

  def test_initialize_GET_uri
    req = Net::HTTP::Get.new(URI("http://example.com/foo"))
    assert_equal "/foo", req.path
    assert_equal "example.com", req['Host']

    req = Net::HTTP::Get.new(URI("https://example.com/foo"))
    assert_equal "/foo", req.path
    assert_equal "example.com", req['Host']

    req = Net::HTTP::Get.new(URI("https://203.0.113.1/foo"))
    assert_equal "/foo", req.path
    assert_equal "203.0.113.1", req['Host']

    req = Net::HTTP::Get.new(URI("https://203.0.113.1:8000/foo"))
    assert_equal "/foo", req.path
    assert_equal "203.0.113.1:8000", req['Host']

    req = Net::HTTP::Get.new(URI("https://[2001:db8::1]:8000/foo"))
    assert_equal "/foo", req.path
    assert_equal "[2001:db8::1]:8000", req['Host']

    assert_raise(ArgumentError){ Net::HTTP::Get.new(URI("urn:ietf:rfc:7231")) }
    assert_raise(ArgumentError){ Net::HTTP::Get.new(URI("http://")) }
  end

  def test_header_set
    req = Net::HTTP::Get.new '/'

    assert req.decode_content, 'Bug #7831 - automatically decode content'

    req['accept-encoding'] = 'identity'

    assert_not_predicate req, :decode_content,
                         'Bug #7831 - do not decode content if the user overrides'
  end if Net::HTTP::HAVE_ZLIB

  def test_update_uri
    req = Net::HTTP::Get.new(URI.parse("http://203.0.113.1"))
    req.update_uri("test", 8080, false)
    assert_equal "203.0.113.1", req.uri.host
    assert_equal 8080, req.uri.port

    req = Net::HTTP::Get.new(URI.parse("http://203.0.113.1:2020"))
    req.update_uri("test", 8080, false)
    assert_equal "203.0.113.1", req.uri.host
    assert_equal 8080, req.uri.port

    req = Net::HTTP::Get.new(URI.parse("http://[2001:db8::1]"))
    req.update_uri("test", 8080, false)
    assert_equal "[2001:db8::1]", req.uri.host
    assert_equal 8080, req.uri.port

    req = Net::HTTP::Get.new(URI.parse("http://[2001:db8::1]:2020"))
    req.update_uri("test", 8080, false)
    assert_equal "[2001:db8::1]", req.uri.host
    assert_equal 8080, req.uri.port
  end
end
