# frozen_string_literal: false
require 'net/http'
require 'openssl'
require 'stringio'
require 'test/unit'

class TestNetHTTPTransportFailure < Test::Unit::TestCase
  class FailureIO
    def initialize(writes: [], reads: [], write_error: nil, read_error: nil)
      @writes = writes
      @reads = reads
      @write_error = write_error
      @read_error = read_error
      @closed = false
    end

    attr_reader :writes

    def write_nonblock(string, exception: false)
      if @write_error
        length = @writes.shift
        return string.bytesize if length == :full
        if length == :partial
          @writes.unshift(:wait)
          return 20
        end
        return :wait_writable if length == :wait
        unless length.nil?
          @write_error = nil if @writes.empty?
          return length
        end
        raise @write_error
      end
      length = @writes.shift
      return string.bytesize if length.nil? || length == :full
      length
    end

    def read_nonblock(length, buffer, exception: false)
      raise @read_error if @read_error
      chunk = @reads.shift
      return nil if chunk.nil?
      buffer&.replace('')
      buffer ? buffer << chunk[0, length] : chunk[0, length]
    end

    def to_io
      self
    end

    def wait_writable(_timeout)
      nil
    end

    def wait_readable(_timeout)
      nil
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  def socket(io)
    socket = Net::HTTP::TrackingBufferedIO.new(io, read_timeout: 1, write_timeout: 1)
    socket.http_transport_failure_context = Net::HTTP::TransportFailureContext.new(phase: :request_header)
    socket
  end

  def post(socket, body = 'request-body')
    request = Net::HTTP::Post.new('/pay', 'Authorization' => 'Bearer secret')
    request.body = body
    request.exec(socket, '1.1', '/pay')
  end

  def test_tls_handshake_failure_context
    http = Net::HTTP.new('example.com', 443)
    context = Net::HTTP::TransportFailureContext.new(phase: :tcp_connect)
    http.instance_variable_set(:@transport_failure_context, context)
    context.phase = :tls_handshake

    error = OpenSSL::SSL::SSLError.new('handshake failure')
    http.send(:attach_transport_failure, error)

    assert_kind_of OpenSSL::SSL::SSLError, error
    assert_same context, error.http_transport_failure_context
    assert_equal :tls_handshake, error.http_transport_failure_context.phase
    assert_not_predicate error.http_transport_failure_context, :request_headers_started?
    assert_nil error.http_transport_failure_context.request_body_bytes_written
    assert_not_predicate error.http_transport_failure_context, :final_response_received?
  end

  def test_connect_marks_tls_handshake_failures
    http = Net::HTTP.new('example.com', 443)
    http.use_ssl = true
    raw_socket = Object.new

    http.define_singleton_method(:timeouted_connect) do |_address, _port|
      raw_socket
    end

    raw_socket.define_singleton_method(:setsockopt) { |*| }
    raw_socket.define_singleton_method(:close) { }

    ssl_socket = Object.new
    ssl_socket.define_singleton_method(:sync_close=) { |_value| }
    ssl_socket.define_singleton_method(:hostname=) { |_value| }
    ssl_socket.define_singleton_method(:close) { }
    original_ssl_socket_new = OpenSSL::SSL::SSLSocket.method(:new)
    OpenSSL::SSL::SSLSocket.define_singleton_method(:new) { |_io, _context = nil| ssl_socket }

    http.define_singleton_method(:ssl_socket_connect) do |_socket, _timeout|
      raise OpenSSL::SSL::SSLError, 'handshake failure'
    end

    begin
      error = assert_raise(OpenSSL::SSL::SSLError) { http.start }
      context = error.http_transport_failure_context
    ensure
      OpenSSL::SSL::SSLSocket.define_singleton_method(:new, original_ssl_socket_new)
    end

    assert_kind_of OpenSSL::SSL::SSLError, error
    assert_equal :tls_handshake, context.phase
    assert_not_predicate context, :request_headers_started?
    assert_nil context.request_body_bytes_written
    assert_not_predicate context, :final_response_received?
  end

  def test_header_write_failure_keeps_body_count_unknown
    io = FailureIO.new(write_error: Errno::ECONNRESET.new)
    socket = socket(io)

    assert_raise(Errno::ECONNRESET) { post(socket) }

    context = socket.http_transport_failure_context
    assert_equal :request_header, context.phase
    assert_not_predicate context, :request_headers_started?
    assert_nil context.request_body_bytes_written
    assert_not_predicate context, :final_response_received?
    assert_empty io.writes
  end

  def test_partial_body_write_reports_confirmed_bytes
    io = FailureIO.new(writes: [:full, :partial], write_error: Net::WriteTimeout.new)
    socket = socket(io)

    assert_raise(Net::WriteTimeout) { post(socket, 'x' * 30) }

    context = socket.http_transport_failure_context
    assert_equal :request_body, context.phase
    assert_predicate context, :request_headers_started?
    assert_equal 20, context.request_body_bytes_written
    assert_not_predicate context, :final_response_received?
  end

  def test_first_body_write_failure_keeps_body_count_unknown
    io = FailureIO.new(writes: [:full], write_error: Errno::ECONNRESET.new)
    socket = socket(io)

    assert_raise(Errno::ECONNRESET) { post(socket) }

    context = socket.http_transport_failure_context
    assert_predicate context, :request_headers_started?
    assert_nil context.request_body_bytes_written
  end

  def test_request_without_body_reports_zero_body_bytes_after_header
    io = FailureIO.new
    socket = socket(io)
    request = Net::HTTP::Get.new('/pay')
    request.exec(socket, '1.1', '/pay')

    context = socket.http_transport_failure_context
    assert_predicate context, :request_headers_started?
    assert_equal 0, context.request_body_bytes_written
  end

  def test_response_read_failure_distinct_from_unprocessed_request
    io = FailureIO.new
    socket = socket(io)
    socket.http_transport_failure_context.phase = :response_header

    assert_raise(EOFError) do
      Net::HTTPResponse.read_new(socket)
    end

    context = socket.http_transport_failure_context

    assert_equal :response_header, context.phase
    assert_not_predicate context, :final_response_received?
    assert_nil context.request_body_bytes_written
  end

  def test_context_contains_no_headers_or_body_content
    io = FailureIO.new(writes: [:full, :partial], write_error: Net::WriteTimeout.new)
    socket = socket(io)

    assert_raise(Net::WriteTimeout) { post(socket, 'card-secret-token-abcdef') }

    dump = socket.http_transport_failure_context.inspect
    assert_not_match(/Authorization/i, dump)
    assert_not_match(/Bearer secret/, dump)
    assert_not_match(/card-secret-token-abcdef/, dump)
  end

  def test_transport_request_attaches_context_to_original_exception
    io = FailureIO.new(write_error: Errno::ECONNRESET.new)
    http = Net::HTTP.new('example.com')
    socket = socket(io)
    http.instance_variable_set(:@socket, socket)
    http.instance_variable_set(:@started, true)
    http.instance_variable_set(:@transport_failure_context, socket.http_transport_failure_context)

    error = assert_raise(Errno::ECONNRESET) do
      http.request(Net::HTTP::Post.new('/pay', 'Authorization' => 'Bearer secret'), 'body')
    end

    context = error.http_transport_failure_context
    assert_same context, error.transport_failure
    assert_same socket.http_transport_failure_context, context
    assert_equal :request_header, context.phase
    assert_not_predicate context, :request_headers_started?
    assert_nil context.request_body_bytes_written
    assert_not_predicate context, :final_response_received?
  end
end
