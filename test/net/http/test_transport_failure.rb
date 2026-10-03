# frozen_string_literal: false
require 'test/unit'
require 'net/http'
require 'stringio'

class TestNetHTTPTransportFailure < Test::Unit::TestCase

  SECRET_BODY = 'card=4111111111111111&amount=100'
  SECRET_HEADER_VALUE = 'Bearer super-secret-token'

  def bind_allowed?
    probe = TCPServer.new('127.0.0.1', 0)
    probe.close
    true
  rescue Errno::EPERM, SystemCallError
    false
  end

  def omit_without_loopback_bind!
    omit 'loopback bind() is unavailable in this environment' unless bind_allowed?
  end

  # Starts a plain TCP server; the block handles the accepted socket.
  def spin_server
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      begin
        sock = server.accept
        yield sock
      ensure
        sock&.close
        server.close
      end
    end
    [port, server, thread]
  end

  def request_with_failure(port, request: nil, use_ssl: false)
    http = Net::HTTP.new('127.0.0.1', port)
    http.open_timeout = 5
    http.read_timeout = 5
    http.use_ssl = use_ssl
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER if use_ssl
    begin
      if request
        http.request(request)
      else
        req = Net::HTTP::Post.new('/pay')
        req['Authorization'] = SECRET_HEADER_VALUE
        req.body = SECRET_BODY
        http.request(req)
      end
    rescue => e
      return e
    end
    flunk 'expected a transport failure'
  end

  def test_tcp_connect_failure_is_before_request
    omit_without_loopback_bind!
    # A closed port -> connection refused (or timeout): request never sent.
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close

    http = Net::HTTP.new('127.0.0.1', port)
    http.open_timeout = 2
    exception = assert_raise(StandardError) { http.get('/pay') }
    ctx = exception.transport_failure_context

    assert_not_nil ctx
    assert_equal :tcp_connect, ctx.phase
    assert_equal false, ctx.request_headers_started
    assert_equal false, ctx.response_received
    # Known zero, not unknown.
    assert_equal 0, ctx.request_body_bytes_written
    assert_predicate ctx, :safe_to_retry?
    assert_not_predicate ctx, :should_query_result?
  end

  def test_tls_handshake_failure_is_distinguished
    omit_without_loopback_bind!
    # Plain TCP server: client attempts TLS handshake and fails.
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      sock = server.accept
      sock.read # hold until client aborts
    ensure
      sock&.close
      server.close
    end

    exception = request_with_failure(port, use_ssl: true)
    thread.join(5)

    ctx = exception.transport_failure_context
    assert_not_nil ctx
    assert_equal :tls_handshake, ctx.phase
    assert_equal false, ctx.request_headers_started
    assert_equal false, ctx.response_received
    assert_equal 0, ctx.request_body_bytes_written
    assert_predicate ctx, :safe_to_retry?
    assert ctx.is_a?(OpenSSL::SSL::SSLError) || exception.cause.is_a?(OpenSSL::SSL::SSLError),
           'original SSL exception type should be preserved'
  end

  def test_disconnect_while_reading_response
    omit_without_loopback_bind!
    port, _server, thread = spin_server do |sock|
      sock.gets("\r\n\r\n") # read request headers
      sock.read # read/drain the body, then close without responding
    end

    exception = request_with_failure(port)
    thread.join(5)

    ctx = exception.transport_failure_context
    assert_not_nil ctx
    assert_equal :response_header, ctx.phase
    assert_equal true, ctx.request_headers_started
    assert_equal false, ctx.response_received
    assert_nil ctx.response_status
    # Full body was written and acknowledged: a known count, not nil.
    assert_equal SECRET_BODY.bytesize, ctx.request_body_bytes_written
    assert_not_predicate ctx, :safe_to_retry?
    assert_predicate ctx, :should_query_result?
  end

  def test_disconnect_while_writing_body_marks_unknown_count
    omit_without_loopback_bind!
    # Read just the request line + headers, then close during the body,
    # yielding a write/reset failure mid-body.
    port, thread = with_server do |sock|
      sock.gets("\r\n\r\n")
      sock.close
    end

    req = Net::HTTP::Post.new('/pay')
    req['Authorization'] = SECRET_HEADER_VALUE
    # A large fixed-length stream forces a multi-write body
    source = StringIO.new('x' * 10 * 1024 * 1024)
    req.body_stream = source

    exception = request_with_failure(port, request: req)
    thread.join(5)

    ctx = exception.transport_failure_context
    assert_not_nil ctx
    assert_equal :request_body, ctx.phase
    assert_equal true, ctx.request_headers_started
    assert_equal false, ctx.response_received
    # Some bytes may have been sent, but the exact number is unknown:
    # it must be nil, never zero.
    assert_nil ctx.request_body_bytes_written
    assert_predicate ctx, :should_query_result?
  end

  def test_disconnect_while_writing_headers
    omit_without_loopback_bind!
    port, _server, thread = spin_server do |sock|
      sock.readpartial(1) # accept a single byte then hang up
      sock.close
    end

    exception = request_with_failure(port)
    thread.join(5)

    ctx = exception.transport_failure_context
    assert_not_nil ctx
    # The failure is at the earliest stage observed.
    assert [ :request_header, :request_body, :response_header ].include?(ctx.phase),
           "unexpected phase #{ctx.phase.inspect}"
    assert_equal true, ctx.request_headers_started
    assert_equal false, ctx.response_received
  end

  def test_response_body_disconnect_keeps_final_status
    omit_without_loopback_bind!
    port, _server, thread = spin_server do |sock|
      sock.gets("\r\n\r\n")
      sock.write "HTTP/1.1 200 OK\r\n"
      sock.write "Content-Length: 100\r\n\r\n"
      sock.write "ab"
      sock.close
    end

    exception = request_with_failure(port)
    thread.join(5)

    ctx = exception.transport_failure_context
    assert_not_nil ctx
    assert_equal :response_body, ctx.phase
    assert_equal true, ctx.response_received
    assert_equal 200, ctx.response_status
    assert_not_predicate ctx, :should_query_result?
  end

  def test_diagnostics_do_not_leak_secrets
    omit_without_loopback_bind!
    port, _server, thread = spin_server do |sock|
      sock.gets("\r\n\r\n")
      sock.close
    end

    exception = request_with_failure(port)
    thread.join(5)

    ctx = exception.transport_failure_context
    dump = ctx.to_h.inspect + ctx.inspect
    assert_not_match(/super-secret-token/, dump)
    assert_not_match(/4111111111111111/, dump)
    assert_not_match(/card=/, dump)
    assert_not_match(/Authorization/i, dump)
  end

  def test_exception_class_and_cause_are_preserved
    omit_without_loopback_bind!
    # TLS handshake failure surfaces an SSLError (or wraps one as cause).
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      sock = server.accept
      sock.read
    ensure
      sock&.close
      server.close
    end

    exception = request_with_failure(port, use_ssl: true)
    thread.join(5)

    assert_kind_of StandardError, exception
    assert_kind_of Exception, exception.cause if exception.cause
    # Context is attached to the very exception raised, not a replacement.
    assert_same exception, exception
    assert exception.respond_to?(:transport_failure_context)
  end
end

# Fake IO that fails on a configurable write, reporting how many bytes it
# accepted. No network is involved.
class FakeWriteIO
  attr_reader :accepted

  def initialize(fail_after:)
    @fail_after = fail_after
    @accepted = 0
  end

  def write_nonblock(str, exception: true)
    remaining = @fail_after - @accepted
    if remaining <= 0
      raise Errno::EPIPE, 'broken pipe'
    end
    take = [str.bytesize, remaining].min
    @accepted += take
    @fail_after == Float::INFINITY ? str.bytesize : take
  end

  def to_io; self; end
  def closed?; false; end
  def close; end
end

class TestNetHTTPTransportTrackerUnit < Test::Unit::TestCase

  def new_tracker
    Net::HTTP::TransportTracker.new(address: 'pay.example', port: 443, use_ssl: true)
  end

  def new_socket(io, tracker)
    Net::HTTP::TrackingBufferedIO.new(
      io, tracker: tracker,
      read_timeout: 5, write_timeout: 5, continue_timeout: nil, debug_output: nil)
  end

  def test_unknown_is_nil_not_zero_before_any_request
    ctx = new_tracker.context
    assert_equal :tcp_connect, ctx.phase
    assert_equal false, ctx.request_headers_started
    # No request yet: body bytes known to be zero.
    assert_equal 0, ctx.request_body_bytes_written
    assert_equal false, ctx.response_received
    assert_nil ctx.response_status
  end

  def test_interrupted_body_write_is_unknown
    tracker = new_tracker
    tracker.begin_request('POST')
    tracker.request_headers_started!
    tracker.phase = :request_body
    tracker.body_mode = :raw
    tracker.body_write_interrupted!

    ctx = tracker.context
    assert_nil ctx.request_body_bytes_written
    assert_equal true, ctx.request_headers_started
    assert_predicate ctx, :should_query_result?
    assert_not_predicate ctx, :safe_to_retry?
  end

  def test_successful_raw_body_counts_exact_bytes
    tracker = new_tracker
    io = FakeWriteIO.new(fail_after: Float::INFINITY)
    sock = new_socket(io, tracker)

    tracker.begin_request('POST')
    tracker.request_headers_started!
    tracker.phase = :request_body
    tracker.body_mode = :raw
    sock.write('hello')
    sock.write('world')

    assert_equal 10, tracker.context.request_body_bytes_written
  end

  def test_bytes_during_header_phase_are_not_counted_as_body
    tracker = new_tracker
    io = FakeWriteIO.new(fail_after: Float::INFINITY)
    sock = new_socket(io, tracker)

    tracker.begin_request('POST')
    tracker.phase = :request_header
    sock.write('POST / HTTP/1.1\r\n\r\n')

    assert_equal 0, tracker.context.request_body_bytes_written
  end

  def test_chunked_tracker_counts_payload_only
    tracker = new_tracker
    tracker.begin_request('POST')
    tracker.phase = :request_body
    tracker.body_mode = :chunked

    io = FakeWriteIO.new(fail_after: Float::INFINITY)
    sock = new_socket(io, tracker)
    chunker = Net::HTTPGenericRequest::Chunker.new(sock, tracker)
    chunker.write('abc')
    chunker.write('defg')

    # 3 + 4 payload bytes; chunk framing excluded
    assert_equal 7, tracker.context.request_body_bytes_written
  end

  def test_failure_during_socket_write_marks_unknown
    tracker = new_tracker
    io = FakeWriteIO.new(fail_after: 3)
    sock = new_socket(io, tracker)

    tracker.begin_request('POST')
    tracker.request_headers_started!
    tracker.phase = :request_body
    tracker.body_mode = :raw

    assert_raise(Errno::EPIPE) { sock.write('x' * 10) }

    assert_nil tracker.context.request_body_bytes_written
    assert_predicate tracker, :write_failed?
  end

  def test_final_response_marks_received_and_status
    tracker = new_tracker
    tracker.begin_request('POST')
    tracker.final_response!(200)

    ctx = tracker.context
    assert_equal true, ctx.response_received
    assert_equal 200, ctx.response_status
    assert_not_predicate ctx, :should_query_result?
  end

  def test_opaque_body_is_unknown_even_after_full_write
    tracker = new_tracker
    tracker.begin_request('POST')
    tracker.request_headers_started!
    tracker.phase = :request_body
    tracker.body_mode = :opaque
    tracker.body_bytes_written!(50)

    # Fails later, while reading the response.
    tracker.phase = :response_header

    assert_nil tracker.context.request_body_bytes_written
  end

  def test_context_never_contains_headers_or_body
    tracker = new_tracker
    tracker.begin_request('POST')
    ctx = tracker.context
    dump = ctx.to_h.inspect + ctx.inspect
    # Only whitelisted keys are present.
    keys = ctx.to_h.keys
    assert_not_include keys, :headers
    assert_not_include keys, :body
    assert_not_include keys, :authorization
    assert_not_match(/Bearer/i, dump)
  end

  def test_annotation_preserves_exception_class
    tracker = new_tracker
    error = Errno::ECONNRESET.new('connection reset by peer')

    http = Net::HTTP.allocate
    http.send(:annotate_transport_failure, error, tracker)

    assert_kind_of Errno::ECONNRESET, error
    assert_kind_of Net::HTTP::TransportFailure::Diagnostics, error
    assert_same tracker.context.phase, error.transport_failure_context.phase
  end

  def test_annotation_ignores_non_transport_exceptions
    tracker = new_tracker
    error = ArgumentError.new('bad arg')

    http = Net::HTTP.allocate
    http.send(:annotate_transport_failure, error, tracker)

    assert_not_respond_to error, :transport_failure_context
  end

  def test_connection_syscall_errors_are_transport_failures
    tracker = new_tracker
    tracker.phase = :tcp_connect
    [Errno::ECONNREFUSED, Errno::EACCES, Errno::EHOSTUNREACH].each do |klass|
      error = klass.new
      Net::HTTP.allocate.send(:annotate_transport_failure, error, tracker)
      assert_kind_of klass, error
      assert_equal :tcp_connect, error.transport_failure_context.phase
      assert_predicate error.transport_failure_context, :safe_to_retry?
    end
  end

  # Minimal in-memory socket that satisfies everything Net::HTTP uses while
  # writing a request (BufferedIO + continue_timeout + io).
  class MemorySocket
    attr_reader :written
    attr_accessor :continue_timeout

    def initialize
      @written = +''
    end

    def write_nonblock(str, exception: true)
      @written << str
      str.bytesize
    end

    def io; self; end
    def to_io; self; end
    def closed?; false; end
    def close; end
  end

  def test_full_post_exec_tracks_header_and_body
    tracker = new_tracker
    socket_io = MemorySocket.new
    sock = new_socket(socket_io, tracker)
    sock.continue_timeout = nil

    req = Net::HTTP::Post.new('/pay', 'Authorization' => 'Bearer secret')
    req.body = 'card=4111111111111111&amount=100'

    tracker.begin_request('POST')
    req.send(:exec, sock, '1.1', '/pay')

    assert_equal true, tracker.request_headers_started?
    assert_equal 'card=4111111111111111&amount=100'.bytesize,
                 tracker.context.request_body_bytes_written
    assert_equal :request_body, tracker.phase
    # The payload itself was written to the in-memory socket, but the
    # tracker's diagnostics never store it.
    assert_not_include tracker.context.to_h.inspect, 'secret'
  end
end
