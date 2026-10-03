# frozen_string_literal: true
require 'test/unit'
require 'net/http'
require_relative 'utils'

class TestNetHTTPUnixSocket < Test::Unit::TestCase
  def test_unix_socket_preserves_request_target_host_and_connection_lifecycle
    with_unix_server do |path, requests, connections, add_unix_connection|
      TestNetHTTPUtils.clean_http_proxy_env do
        ENV['http_proxy'] = 'http://proxy.example:8080'
        ENV['http_proxy_user'] = 'user'
        ENV['http_proxy_pass'] = 'password'

        http_one = Net::HTTP.new('a.example', nil, nil, unix_socket: path)
        received_paths_one = stub_unix_open(http_one, path, add_unix_connection)
        http_one.start
        assert_nil http_one.ipaddr
        assert_equal 'ok', http_one.get('/one').body
        assert_equal 'ok', http_one.get('/two').body
        assert_equal 1, connections.size

        http_two = Net::HTTP.new('b.example', nil, nil, unix_socket: path)
        received_paths_two = stub_unix_open(http_two, path, add_unix_connection)
        http_two.start
        assert_equal 'ok', http_two.get('/one').body
        assert_equal 2, connections.size

        first_socket = http_one.instance_variable_get(:@socket).io
        first_socket.close
        pending_client, pending_server = UNIXSocket.pair(:STREAM)
        Thread.start(pending_server, requests, &method(:handle_unix_client))
        connections << pending_client
        http_one.define_singleton_method(:timeouted_unix_connect) do |socket_path|
          received_paths_one << [socket_path, :reconnect]
          pending_client
        end
        assert_equal 'ok', http_one.get('/reconnect').body
        assert_equal 3, connections.size

        assert_equal [path, [path, :reconnect]], received_paths_one
        assert_equal [path], received_paths_two

        http_one.finish
        http_two.finish
      end

      recorded_requests = Array.new(requests.size) { requests.pop }
      assert_equal [
        'GET /one HTTP/1.1',
        'GET /two HTTP/1.1',
        'GET /one HTTP/1.1',
        'GET /reconnect HTTP/1.1',
      ], recorded_requests.map { |request| request[:line] }
      assert_equal %w[
        a.example
        a.example
        b.example
        a.example
      ], recorded_requests.map { |request| request[:host] }
      assert_nil recorded_requests.first['proxy-authorization']
      assert_not_equal path, recorded_requests.map { |request| request[:line] }.join(' ')
      assert_not_include recorded_requests.map { |request| request[:host] }.join(' '), path
    end
  end

  def test_unix_socket_bypasses_environment_proxy
    with_unix_server do |path, _requests, _connections, add_unix_connection|
      TestNetHTTPUtils.clean_http_proxy_env do
        ENV['http_proxy'] = 'http://proxy.example:8080'

        http = Net::HTTP.new('a.example', nil, nil, unix_socket: path)
        assert_not_predicate http, :proxy?
        stub_unix_open(http, path, add_unix_connection)
        assert_equal 'ok', http.get('/proxy').body
        assert_nil http.proxy_address
      end
    end
  end

  def test_unix_socket_ignores_explicit_proxy_class
    path = '/var/run/sidecar/http.sock'
    http = Net::HTTP.Proxy('proxy.example').new('a.example', nil, nil, unix_socket: path)
    assert_not_predicate http, :proxy?
    assert_nil http.proxy_address
  end

  def test_unix_socket_rejects_ipaddr
    http = Net::HTTP.new('a.example', nil, nil, unix_socket: '/var/run/sidecar/http.sock')
    assert_raise(ArgumentError) { http.ipaddr = '127.0.0.1' }
  end

  def test_unix_socket_rejects_empty_path
    http = Net::HTTP.new('a.example', nil)
    assert_raise(ArgumentError) { http.unix_socket = '' }
  end

  def test_unix_socket_rejects_tls
    path = '/var/run/sidecar/http.sock'
    http = Net::HTTP.new('a.example', nil, nil, unix_socket: path)
    assert_raise(ArgumentError) { http.use_ssl = true }

    http = Net::HTTP.new('a.example', nil)
    http.use_ssl = true
    assert_raise(ArgumentError) { http.unix_socket = path }

    assert_raise(ArgumentError) do
      Net::HTTP.start('a.example', nil, nil, unix_socket: path, use_ssl: true) { }
    end
  end

  private

  def with_unix_server
    path = '/var/run/sidecar/http.sock'
    requests = Queue.new
    connections = Queue.new

    add_unix_connection = lambda do
      client_socket, server_socket = UNIXSocket.pair(:STREAM)
      connections << client_socket
      Thread.start(server_socket, requests, &method(:handle_unix_client))
      client_socket
    end

    yield path, requests, connections, add_unix_connection
  end

  def stub_unix_open(http, path, add_unix_connection)
    received_paths = []
    http.define_singleton_method(:timeouted_unix_connect) do |socket_path|
      received_paths << socket_path
      add_unix_connection.call
    end
    received_paths
  end

  def handle_unix_client(socket, requests)
    loop do
      line = socket.gets
      break if line.nil? || line.strip.empty?

      headers = {}
      while (header = socket.gets)
        break if header.strip.empty?
        name, value = header.split(': ', 2)
        headers[name.downcase] = value.chomp
      end

      requests << {line: line.strip, host: headers['host']}
      socket.write "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    end
  rescue Errno::ECONNRESET, Errno::EPIPE, IOError
  ensure
    socket.close
  end
end
