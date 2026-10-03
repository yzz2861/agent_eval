# frozen_string_literal: true
require 'test/unit'
require 'net/http'
require 'socket'
require 'tmpdir'
require 'fileutils'

class TestNetHTTPUnixSocket < Test::Unit::TestCase
  class RecordedRequest
    attr_reader :request_line, :method, :path, :headers

    def initialize(request_line, headers)
      @request_line = request_line
      @method, @path, = request_line.split(' ')
      @headers = headers
    end

    def [](key)
      @headers[key.downcase]
    end
  end

  # A minimal HTTP/1.1 server listening on a Unix domain socket.
  # Records the request line and header fields of every received request.
  class UnixHTTPServer
    attr_reader :requests, :accept_count

    def initialize(path)
      @server = UNIXServer.new(path)
      @requests = []
      @accept_count = 0
      @mutex = Mutex.new
    end

    def start
      @thread = Thread.new do
        loop do
          socket = @server.accept
          @mutex.synchronize { @accept_count += 1 }
          Thread.new(socket) { |s| serve(s) }
        end
      end
      self
    end

    def shutdown
      @thread.kill
      @thread.join
      @server.close
    end

    private

    def serve(socket)
      loop do
        request_line = socket.gets or break
        headers = {}
        while (line = socket.gets) && line != "\r\n"
          key, value = line.chomp.split(': ', 2)
          headers[key.downcase] = value.strip
        end
        request = RecordedRequest.new(request_line.strip, headers)
        @mutex.synchronize { @requests << request }
        socket.write "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
      end
    rescue IOError, SystemCallError
    ensure
      socket.close
    end
  end

  def setup
    omit 'UNIXSocket is not supported on this platform' unless defined?(UNIXServer)
    @dir = Dir.mktmpdir('net-http-unix')
    @socket_path = File.join(@dir, 'server.sock')
    @server = UnixHTTPServer.new(@socket_path).start
  end

  def teardown
    @server&.shutdown
    FileUtils.remove_entry(@dir) if @dir
  end

  def last_request
    @server.requests.last
  end

  def test_unix_constructor
    http = Net::HTTP.unix('logical.example', @socket_path)
    assert_equal 'logical.example', http.address
    assert_equal 80, http.port
    assert_equal @socket_path, http.unix_socket_path
    assert_true http.unix_socket?
    assert_false http.proxy?

    http = Net::HTTP.new('logical.example')
    assert_nil http.unix_socket_path
    assert_false http.unix_socket?
  end

  def test_get_over_unix_socket
    Net::HTTP.unix('logical.example', @socket_path).start do |http|
      res = http.get('/path?q=1')
      assert_equal '2', res['Content-Length']
      assert_equal 'ok', res.body
    end

    req = last_request
    assert_equal 'GET /path?q=1 HTTP/1.1', req.request_line
    assert_equal 'logical.example', req['host']
    assert_not_include req.request_line, @socket_path
    assert_not_include req['host'], @socket_path
  end

  def test_host_header_includes_non_default_port
    Net::HTTP.unix('logical.example', @socket_path, 8080).start do |http|
      http.get('/')
    end

    assert_equal 'logical.example:8080', last_request['host']
  end

  def test_two_logical_hosts_share_one_socket
    Net::HTTP.unix('a.example', @socket_path).start do |http|
      http.get('/from-a')
    end
    Net::HTTP.unix('b.example', @socket_path).start do |http|
      http.get('/from-b')
    end

    assert_equal 2, @server.requests.size
    first, second = @server.requests
    assert_equal 'GET /from-a HTTP/1.1', first.request_line
    assert_equal 'a.example', first['host']
    assert_equal 'GET /from-b HTTP/1.1', second.request_line
    assert_equal 'b.example', second['host']
  end

  def test_keep_alive_reuses_connection
    Net::HTTP.unix('logical.example', @socket_path).start do |http|
      3.times { |i| http.get("/req-#{i}") }
    end

    assert_equal 1, @server.accept_count
    assert_equal 3, @server.requests.size
    assert_equal 'GET /req-2 HTTP/1.1', last_request.request_line
  end

  def test_reconnect_after_server_close
    http = Net::HTTP.unix('logical.example', @socket_path)
    http.start
    http.get('/first')
    # Simulate the server side dropping the keep-alive connection.
    http.instance_variable_get(:@socket).close
    http.get('/second')
    http.finish

    assert_equal 2, @server.accept_count
    assert_equal 'GET /second HTTP/1.1', last_request.request_line
  end

  def test_proxy_settings_are_ignored
    with_env('http_proxy' => 'http://proxy.invalid:12345') do
      http = Net::HTTP.new('logical.example') # picks up proxy from ENV
      http.unix_socket_path = @socket_path
      assert_false http.proxy?
      http.start do |session|
        res = session.get('/direct')
        assert_equal 'ok', res.body
      end
    end

    req = last_request
    assert_equal 'GET /direct HTTP/1.1', req.request_line
    assert_equal 'logical.example', req['host']
  end

  def test_use_ssl_over_unix_socket_raises
    http = Net::HTTP.unix('logical.example', @socket_path)
    http.use_ssl = true
    assert_raise(ArgumentError) { http.start }
    assert_false http.started?
  end

  def test_unix_socket_path_not_mutable_while_started
    Net::HTTP.unix('logical.example', @socket_path).start do |http|
      assert_raise(IOError) { http.unix_socket_path = '/tmp/other.sock' }
    end
  end

  def test_connection_failure_message
    http = Net::HTTP.unix('logical.example', File.join(@dir, 'nosuch.sock'))
    error = assert_raise(SystemCallError) { http.start }
    assert_include error.message, 'Failed to open Unix socket connection'
  end

  private

  def with_env(vars)
    old = vars.keys.to_h { |key| [key, ENV[key]] }
    vars.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
    yield
  ensure
    old.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end
end
