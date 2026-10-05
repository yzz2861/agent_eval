# frozen_string_literal: true

require_relative "helper"
require_relative "helpers/test_puma/puma_socket"
require "puma/events"
require "puma/server"

# Tests for the optional connection-level fair scheduling
# (`fair_connection_quota`).  When enabled, a keep-alive connection may only
# deliver a limited number of consecutive requests to the application per
# scheduling round before it is rotated behind the other ready connections.
#
# The application below is barrier-controlled: every request blocks until the
# test releases it, so at most one request is in flight and the observed
# scheduling order is fully deterministic without relying on sleeps.
class TestFairConnectionQuota < PumaTest
  parallelize_me!

  include TestPuma
  include TestPuma::PumaSocket

  HOST = HOST4

  QUOTA = 2

  def setup
    @host = HOST
    @log_writer = Puma::LogWriter.strings
    @events = Puma::Events.new

    # @started receives a token whenever a request begins processing.
    # @releases holds one barrier queue per connection; the app blocks on it
    # until the test releases the request.
    @started  = Queue.new
    @releases = Hash.new { |h, k| h[k] = Queue.new }

    @app = ->(env) do
      conn = env['HTTP_X_CONN']
      seq  = env['HTTP_X_SEQ']
      @started << "#{conn}#{seq}"
      @releases[conn].pop
      [200, {}, ["resp-#{conn}-#{seq}"]]
    end
  end

  def teardown
    @server&.stop(true)
    super
  end

  def server_run(**options)
    options[:log_writer] ||= @log_writer
    @server = Puma::Server.new @app, @events, {
      min_threads: 2,
      max_threads: 2,
    }.merge(options)
    @bind_port = (@server.add_tcp_listener @host, 0).addr[1]
    @server.run
  end

  def test_quota_disabled_by_default
    server = Puma::Server.new @app, @events, {log_writer: @log_writer}
    assert_nil server.instance_variable_get(:@fair_connection_quota)
  ensure
    server&.stop(true)
  end

  def test_quota_non_positive_disables
    server = Puma::Server.new @app, @events, {log_writer: @log_writer, fair_connection_quota: 0}
    assert_nil server.instance_variable_get(:@fair_connection_quota)
  ensure
    server&.stop(true)
  end

  def test_dsl_sets_option
    config = Puma::Configuration.new do |c|
      c.fair_connection_quota 4
    end
    config.clamp
    assert_equal 4, config.options[:fair_connection_quota]
  end

  def test_busy_and_sparse_connections_make_progress
    server_run fair_connection_quota: QUOTA

    # Two busy connections, each pipelines four requests.
    socket_a = send_http pipeline('a', 1..4)
    assert_started 'a1'

    socket_b = send_http pipeline('b', 1..4)
    assert_started 'b1'

    # A sparse client queues behind both busy connections.
    socket_c = send_http request('c', 1)
    wait_until { @server.backlog == 1 }

    # 'a' delivers its quota of two consecutive requests, then rotates
    # behind 'c' instead of monopolizing its thread.
    release 'a', socket_a, 'a-1', 'a2'
    release 'a', socket_a, 'a-2', 'c1'

    # Same for 'b'; the requeued 'a' waits behind no one but 'b'.
    release 'b', socket_b, 'b-1', 'b2'
    release 'b', socket_b, 'b-2', 'a3'

    # 'c' made progress while both busy connections still had requests
    # ready; it has no more data and is parked in the reactor.
    release 'c', socket_c, 'c-1', 'b3'

    # 'a' and 'b' each finish their second round and park.
    release 'a', socket_a, 'a-3', 'a4'
    release 'a', socket_a, 'a-4', nil
    release 'b', socket_b, 'b-3', 'b4'
    release 'b', socket_b, 'b-4', nil

    # The sparse client becomes ready again on its parked connection and is
    # scheduled without cutting in line.
    socket_c << request('c', 2)
    assert_started 'c2'
    release 'c', socket_c, 'c-2', nil
  end

  private

  def request(conn, seq)
    "GET / HTTP/1.1\r\nHost: test.com\r\nX-Conn: #{conn}\r\nX-Seq: #{seq}\r\n\r\n"
  end

  def pipeline(conn, seqs)
    seqs.map { |seq| request(conn, seq) }.join
  end

  def assert_started(expected)
    token = Timeout.timeout(10) { @started.pop }
    assert_equal expected, token, "expected request #{expected} to start next"
  end

  # Releases the blocked request on +conn+, asserts which request starts
  # next (nil when no request is expected to start), and reads the response
  # of the just-completed request, verifying per-connection response order.
  def release(conn, socket, completed, next_started)
    @releases[conn] << true
    assert_started next_started if next_started
    response = socket.read_response
    assert_equal "resp-#{completed}", response.body
  end

  # Condition-based wait; raises if the condition is not met in time.
  def wait_until(timeout: 10)
    Timeout.timeout(timeout) do
      sleep 0.001 until yield
    end
  end
end
