# frozen_string_literal: true

require_relative "helper"

require 'socket'
require 'puma/client'
require 'puma/server'
require 'puma/events'

# Tests the `header_admission` hook: a lightweight check that runs after the
# request headers are parsed, but before `100 Continue` is sent and before
# the request body is read. Uses socketpairs, so no network is needed.
#
class TestHeaderAdmissionBase < PumaTest

  include Puma::Const

  HTTP_METHODS = SUPPORTED_HTTP_METHODS.sort.product([nil]).to_h.freeze

  GET_11 = "GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"

  def setup
    @pairs = []
    @hook_requests = []
  end

  def teardown
    @pairs.each do |io|
      io.close unless io.closed?
    rescue IOError
    end
  end

  # Creates a Puma::Client wrapping one end of a socketpair; the other end
  # (@wr) is used to feed request bytes and to read anything the client
  # writes (e.g. 100 Continue).
  def new_client(hook)
    @rd, @wr = UNIXSocket.pair
    @pairs << @rd << @wr
    @rd.define_singleton_method(:peeraddr) { ["AF_INET", 80, "127.0.0.1", "127.0.0.1"] }
    client = Puma::Client.new @rd, {}
    client.supported_http_methods = HTTP_METHODS
    client.header_admission = hook
    client
  end

  # Writes +data+ to the socket and runs one read/parse cycle
  def feed(client, data)
    @wr.syswrite data
    client.try_to_finish
  end

  def recording_hook(result)
    ->(request) { @hook_requests << request; result }
  end

  def read_available(io)
    str = +""
    loop do
      str << io.read_nonblock(4096)
    rescue IO::WaitReadable
      break
    end
    str
  end
end

class TestHeaderAdmissionClient < TestHeaderAdmissionBase
  parallelize_me! if Puma::IS_MRI

  def test_allow_true_reads_request_normally
    client = new_client recording_hook(true)

    assert feed(client, "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhello")

    assert_nil client.admission_rejection
    assert_equal "hello", client.env['rack.input'].read
    refute_empty @hook_requests
  end

  def test_allow_nil_reads_request_normally
    client = new_client recording_hook(nil)

    assert feed(client, GET_11)

    assert_nil client.admission_rejection
    refute_empty @hook_requests
  end

  def test_hook_receives_read_only_snapshot
    client = new_client recording_hook(true)

    feed(client, "POST /upload?a=1 HTTP/1.1\r\nHost: test.com\r\nX-API-Key: sek\r\nContent-Length: 3\r\n\r\nabc")

    request = @hook_requests.first
    assert_kind_of Puma::AdmissionRequest, request
    assert_equal "POST", request.request_method
    assert_equal "/upload", request.path
    assert_equal "a=1", request.query_string
    assert_equal "HTTP/1.1", request.http_version
    assert_equal "sek", request["X-API-Key"]
    assert_equal "sek", request[:x_api_key]
    assert_equal "test.com", request["host"]
    assert_equal 3, request.content_length

    assert_predicate request, :frozen?
    assert_predicate request.headers, :frozen?
    assert_predicate request.headers["x-api-key"], :frozen?
    refute request.respond_to?(:io)
    refute request.respond_to?(:socket)
  end

  def test_reject_stores_rejection_and_readies_client
    client = new_client recording_hook([413, {}, ["too large"]])

    assert feed(client, "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 100\r\n\r\n")

    assert_equal [413, {}, ["too large"]], client.admission_rejection
    assert_predicate client, :ready
  end

  def test_reject_with_body_not_yet_sent_closes_connection
    client = new_client recording_hook([413, {}, ["too large"]])

    feed(client, "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 100\r\n\r\n")

    # the body may still arrive, so the connection must be closed: its bytes
    # cannot be allowed to become the next request
    assert_equal "close", client.env[HTTP_CONNECTION]
    assert_nil client.instance_variable_get(:@buffer)
  end

  def test_reject_with_chunked_body_closes_connection
    client = new_client recording_hook([413, {}, ["too large"]])

    feed(client, "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")

    assert_equal "close", client.env[HTTP_CONNECTION]
    assert_nil client.instance_variable_get(:@buffer)
  end

  def test_reject_with_invalid_content_length_closes_connection
    client = new_client recording_hook([413, {}, ["too large"]])

    feed(client, "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: abc\r\n\r\n")

    assert_equal "close", client.env[HTTP_CONNECTION]
    assert_nil client.instance_variable_get(:@buffer)
  end

  def test_reject_with_buffered_body_discards_it_and_keeps_alive
    client = new_client recording_hook([413, {}, ["too large"]])
    next_request = "GET /next HTTP/1.1\r\nHost: test.com\r\n\r\n"

    feed(client, "POST /upload HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhello#{next_request}")

    # the whole body already arrived; it is discarded and the pipelined
    # request is kept, so the connection can stay open
    refute_equal "close", client.env[HTTP_CONNECTION]
    assert_equal next_request, client.instance_variable_get(:@buffer)
    assert client.has_back_to_back_requests?
  end

  def test_reject_without_body_keeps_pipelined_request
    client = new_client recording_hook([403, {}, ["denied"]])
    next_request = "GET /next HTTP/1.1\r\nHost: test.com\r\n\r\n"

    feed(client, "GET /no HTTP/1.1\r\nHost: test.com\r\n\r\n#{next_request}")

    refute_equal "close", client.env[HTTP_CONNECTION]
    assert_equal next_request, client.instance_variable_get(:@buffer)
  end

  def test_reject_does_not_send_100_continue
    client = new_client recording_hook([413, {}, ["too large"]])

    feed(client, "POST / HTTP/1.1\r\nHost: test.com\r\nExpect: 100-continue\r\nContent-Length: 100\r\n\r\n")

    assert_raises(IO::WaitReadable) { @wr.read_nonblock(1) }
  end

  def test_allow_still_sends_100_continue
    client = new_client recording_hook(true)

    # body not sent yet, so the request is not ready
    refute feed(client, "POST / HTTP/1.1\r\nHost: test.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")

    assert_equal "HTTP/1.1 100 Continue\r\n\r\n", @wr.read_nonblock(64)
  end

  def test_hook_exception_raises_header_admission_error
    client = new_client ->(request) { raise "boom" }

    error = assert_raises(Puma::HeaderAdmissionError) { feed(client, GET_11) }

    assert_includes error.message, "boom"
    assert_equal "close", client.env[HTTP_CONNECTION]
    assert_nil client.instance_variable_get(:@buffer)
  end

  def test_invalid_hook_returns_raise_header_admission_error
    max_body = Puma::Client::MAX_ADMISSION_RESPONSE_BODY
    max_headers = Puma::Client::MAX_ADMISSION_RESPONSE_HEADERS

    cases = {
      "string"                => "nope",
      "false"                 => false,
      "incomplete triple"     => [413, {}],
      "status below 400"      => [200, {}, ["ok"]],
      "status above 599"      => [600, {}, ["no"]],
      "non-integer status"    => ["413", {}, ["no"]],
      "oversized body"        => [413, {}, ["x" * (max_body + 1)]],
      "too many headers"      => [413, (1..max_headers + 1).to_h { |i| ["x-h#{i}", "v"] }, ["no"]],
      "illegal header value"  => [413, { "x-bad" => "a\r\nb" }, ["no"]],
      "non-string body part"  => [413, {}, [123]],
    }

    cases.each do |name, result|
      client = new_client recording_hook(result)
      assert_raises(Puma::HeaderAdmissionError, name) { feed(client, GET_11) }
      assert_equal "close", client.env[HTTP_CONNECTION], name
      assert_nil client.admission_rejection, name
    end
  end

  def test_reset_clears_rejection
    client = new_client recording_hook([413, {}, ["too large"]])

    feed(client, GET_11)
    refute_nil client.admission_rejection

    client.reset
    assert_nil client.admission_rejection
  end
end

# Tests that Server#handle_request serves the hook's rejection response
# instead of calling the Rack app.
class TestHeaderAdmissionResponse < TestHeaderAdmissionBase
  parallelize_me! if Puma::IS_MRI

  def setup
    super
    @log_writer = Puma::LogWriter.strings
    @app_called = false
    app = ->(env) { @app_called = true; [200, {}, ["app"]] }
    @server = Puma::Server.new app, Puma::Events.new, { log_writer: @log_writer, min_threads: 1 }
    @server.instance_variable_set :@status, :run
  end

  def rejected_client(rejection, request)
    client = new_client recording_hook(rejection)
    feed(client, request)
    client
  end

  def test_handle_request_serves_rejection_and_skips_app
    client = rejected_client [403, { "x-reason" => "no" }, ["denied"]], GET_11

    result = @server.handle_request(nil, client, 1)

    assert_equal :keep_alive, result
    refute @app_called

    response = read_available @wr
    assert_start_with response, "HTTP/1.1 403 Forbidden\r\n"
    assert_includes response, "x-reason: no\r\n"
    assert_includes response, "content-length: 6\r\n"
    assert_includes response, "\r\n\r\ndenied"
    refute_includes response, "connection: close"
  end

  def test_handle_request_serves_rejection_with_connection_close
    client = rejected_client [413, {}, ["too large"]],
      "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 100\r\n\r\n"

    result = @server.handle_request(nil, client, 1)

    assert_equal :close, result
    refute @app_called

    response = read_available @wr
    assert_start_with response, "HTTP/1.1 413 Content Too Large\r\n"
    assert_includes response, "connection: close\r\n"
  end

  def test_server_passes_header_admission_to_clients
    hook = ->(request) { true }
    server = Puma::Server.new nil, nil, { log_writer: @log_writer, header_admission: hook }

    io, other = UNIXSocket.pair
    client = server.new_client io, nil

    assert_same hook, client.instance_variable_get(:@header_admission)
  ensure
    io&.close
    other&.close
  end
end
