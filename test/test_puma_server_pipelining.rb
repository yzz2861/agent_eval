# frozen_string_literal: true

require_relative "helper"
require_relative "helpers/test_puma/response"
require "puma/events"
require "puma/server"
require "puma/client"
require "socket"

class TestPumaServerPipelining < PumaTest
  parallelize_me!

  def teardown
    @server&.stop(true)
  end

  def test_disabled_by_default_keeps_pipelined_requests_serial
    entered = Queue.new
    release = Queue.new
    server_for(lambda do |env|
      entered << env["PATH_INFO"]
      release.pop
      [200, {"Content-Length" => "1"}, ["x"]]
    end)

    client_io, server_io = UNIXSocket.pair
    client = new_client(server_io)
    client_io.write("GET /one HTTP/1.1\r\nHost: x\r\n\r\n" \
      "GET /two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    pool << client

    assert_equal "/one", entered.pop
    assert_raises(ThreadError) { entered.pop(true) }
    release << true
    assert_equal "/two", entered.pop
    release << true
    assert client_io.read.include?("xHTTP/1.1")
  ensure
    client_io&.close
    server_io&.close
  end

  def test_get_and_head_enter_application_in_parallel_and_responses_stay_ordered
    entered = Queue.new
    release = Queue.new
    server_for(lambda do |env|
      name = env["PATH_INFO"]
      entered << name
      release.pop
      [200, {"Content-Length" => name.bytesize.to_s}, [name]]
    end, parallel_pipelining: true, min_threads: 3, max_threads: 3)

    client_io, server_io = UNIXSocket.pair
    client = new_client(server_io)
    client_io.write("GET /one HTTP/1.1\r\nHost: x\r\n\r\n" \
      "HEAD /two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    pool << client

    Timeout.timeout(5) do
      assert_equal "/one", entered.pop
      assert_equal "/two", entered.pop
    end
    2.times { release << true }

    bytes = client_io.read
    one_at = bytes.index("\r\n\r\n/one")
    head_at = bytes.index("HTTP/1.1 200 OK")
    second_head_at = bytes.index("HTTP/1.1 200 OK", head_at + 1)
    refute_nil one_at
    refute_nil second_head_at
    assert_operator head_at, :<, one_at
    assert_operator one_at, :<, second_head_at
    refute bytes.end_with?("/two")
  ensure
    client_io&.close
    server_io&.close
  end

  def test_pipelining_limits_must_be_positive
    assert_raises ArgumentError do
      server_for(->(_) { [200, {}, []] }, parallel_pipelining: true, max_pipelined_requests: 0)
    end

    assert_raises ArgumentError do
      server_for(->(_) { [200, {}, []] }, parallel_pipelining: true, pipelined_buffer_bytes: 0)
    end
  end

  def test_non_get_methods_are_serialized_and_streaming_successor_cannot_interleave
    entered = Mutex.new.synchronize { [] }
    mutex = Mutex.new
    post_release = Queue.new
    stream_started = Queue.new
    stream_release = Queue.new
    short_started = Queue.new

    app = lambda do |env|
      name = env["PATH_INFO"]
      mutex.synchronize { entered << name }
      case name
      when "/post"
        post_release.pop
        [200, {"Content-Length" => "4"}, ["post"]]
      when "/after"
        [200, {"Content-Length" => "5"}, ["after"]]
      when "/stream"
        body = Enumerator.new do |yielder|
          stream_started << true
          stream_release.pop
          64.times { yielder << "abcdefgh" }
        end
        [200, {}, body]
      when "/short"
        short_started << true
        [200, {"Content-Length" => "5"}, ["short"]]
      end
    end

    server_for(app, parallel_pipelining: true, pipelined_buffer_bytes: 4_096,
      min_threads: 3, max_threads: 3)

    post_io, post_server = UNIXSocket.pair
    post_client = new_client(post_server)
    post_io.write("POST /post HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n" \
      "GET /after HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    pool << post_client
    sleep 0.1
    mutex.synchronize { assert_equal ["/post"], entered }
    post_release << true
    post_bytes = post_io.read
    assert_operator post_bytes.index("\r\n\r\npost"), :<, post_bytes.index("\r\n\r\nafter")

    stream_io, stream_server = UNIXSocket.pair
    stream_client = new_client(stream_server)
    stream_io.write("GET /stream HTTP/1.1\r\nHost: x\r\n\r\n" \
      "GET /short HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    pool << stream_client
    assert_equal true, stream_started.pop
    assert_equal true, short_started.pop
    stream_release << true
    stream_bytes = stream_io.read
    assert_operator stream_bytes.index("transfer-encoding: chunked"),
      :<, stream_bytes.index("\r\n\r\nshort")
  ensure
    post_io&.close
    post_server&.close
    stream_io&.close
    stream_server&.close
  end

  def test_predecessor_close_cancels_buffered_successor
    successor_started = false

    app = lambda do |env|
      if env["PATH_INFO"] == "/first"
        [200, {"Content-Length" => "5"}, ["first"]]
      else
        successor_started = true
        raise "successor must not run"
      end
    end

    server_for(app, parallel_pipelining: true, min_threads: 3, max_threads: 3)
    client_io, server_io = UNIXSocket.pair
    client = new_client(server_io)
    client_io.write("GET /first HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" \
      "POST /second HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
    pool << client

    bytes = client_io.read
    assert_equal "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 5\r\n\r\nfirst", bytes
    assert_empty client_io.read
    sleep 0.05
    refute successor_started
  ensure
    client_io&.close
    server_io&.close
  end

  def test_output_failure_closes_successor_response_resource
    first_started = Queue.new
    first_resume = Queue.new
    second_started = Queue.new
    second_closed = Queue.new

    successor_body = Object.new
    successor_body.define_singleton_method(:each) do
      raise "successor body must not be written after output failure"
    end
    successor_body.define_singleton_method(:close) { second_closed << true }

    app = lambda do |env|
      case env["PATH_INFO"]
      when "/first"
        body = Enumerator.new do |yielder|
          first_started << true
          yielder << "first"
          first_resume.pop
          yielder << "second chunk"
        end
        [200, {}, body]
      when "/second"
        second_started << true
        [200, {"Content-Length" => "6"}, successor_body]
      end
    end

    server_for(app, parallel_pipelining: true, min_threads: 3, max_threads: 3)
    client_io, server_io = UNIXSocket.pair
    client = new_client(server_io)
    client_io.write("GET /first HTTP/1.1\r\nHost: x\r\n\r\n" \
      "GET /second HTTP/1.1\r\nHost: x\r\n\r\n")
    pool << client

    assert_equal true, first_started.pop
    assert client_io.read_nonblock(64).include?("first")
    assert_equal true, second_started.pop
    client_io.close
    first_resume << true

    assert_equal true, second_closed.pop
  ensure
    client_io&.close unless client_io&.closed?
    server_io&.close
  end

  def test_parse_error_after_pipelined_request_waits_for_response_order
    started = Queue.new
    release = Queue.new

    app = lambda do |env|
      started << true
      release.pop
      [200, {"Content-Length" => "2"}, ["ok"]]
    end

    server_for(app, parallel_pipelining: true, min_threads: 2, max_threads: 2)
    client_io, server_io = UNIXSocket.pair
    client = new_client(server_io)
    client_io.write("GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nBAD\r\n\r\n")
    pool << client

    assert_equal true, started.pop
    release << true
    bytes = client_io.read

    assert_operator bytes.index("\r\n\r\nok"), :<, bytes.index("400 Bad Request")
    assert_predicate client_io, :eof
  ensure
    client_io&.close
    server_io&.close
  end

  private

  def server_for(app, **options)
    @server = Puma::Server.new(app, Puma::Events.new, **{
      log_writer: Puma::LogWriter.null,
      min_threads: 1,
      max_threads: 2
    }.merge(options))
    @server.run
  end

  def pool
    @server.instance_variable_get(:@thread_pool)
  end

  def new_client(io)
    client = Puma::Client.new(io, {})
    client.supported_http_methods = :any
    client.http_content_length_limit = nil
    client.allow_underscore_headers = true
    client
  end

end
