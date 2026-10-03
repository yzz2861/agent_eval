# frozen_string_literal: false
begin
  require 'net/https'
rescue LoadError
end
require 'test/unit'

return unless defined?(OpenSSL::SSL)

class HTTPSProxyTest < Test::Unit::TestCase
  def test_https_proxy_authentication
    TCPServer.open("127.0.0.1", 0) {|serv|
      _, port, _, _ = serv.addr
      client_thread = Thread.new {
        proxy = Net::HTTP.Proxy("127.0.0.1", port, 'user', 'password')
        http = proxy.new("foo.example.org", 8000)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        begin
          http.start
        rescue EOFError
        end
      }
      server_thread = Thread.new {
        sock = serv.accept
        begin
          proxy_request = sock.gets("\r\n\r\n")
          assert_equal(
            "CONNECT foo.example.org:8000 HTTP/1.1\r\n" +
            "Host: foo.example.org:8000\r\n" +
            "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n" +
            "\r\n",
            proxy_request,
            "[ruby-dev:25673]")
        ensure
          sock.close
        end
      }
      assert_join_threads([client_thread, server_thread])
  }
  end

  def test_https_proxy_gate_checks_proxy_and_keeps_logical_target
    TCPServer.open("127.0.0.1", 0) {|serv|
      _, port, _, _ = serv.addr
      resolved = []
      checked = []
      client_thread = Thread.new {
        proxy = Net::HTTP.Proxy("proxy.example", port, 'user', 'password')
        http = proxy.new("destination.example", 8000)
        http.open_timeout = 5
        http.max_retries = 0
        http.resolver = lambda do |host, proxy_port, role:|
          resolved << [host, role]
          assert_equal :proxy, role
          [Addrinfo.tcp("127.0.0.1", proxy_port)]
        end
        http.address_gate = lambda do |address, role|
          checked << [address.ip_address, role]
          role == :proxy && address.ip_address == "127.0.0.1"
        end
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        begin
          http.start
        rescue EOFError, Errno::ECONNRESET, IOError, OpenSSL::SSL::SSLError
        end
      }
      server_thread = Thread.new {
        sock = serv.accept
        begin
          proxy_request = sock.gets("\r\n\r\n")
          assert_equal(
            "CONNECT destination.example:8000 HTTP/1.1\r\n" +
            "Host: destination.example:8000\r\n" +
            "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n" +
            "\r\n",
            proxy_request)
        ensure
          sock.close
        end
      }
      assert_join_threads([client_thread, server_thread])
      assert_equal [["proxy.example", :proxy]], resolved
      assert_equal [["127.0.0.1", :proxy]], checked
    }
  end


  def read_fixture(key)
    File.read(File.expand_path("../fixtures/#{key}", __dir__))
  end

  def test_https_proxy_ssl_connection
    TCPServer.open("127.0.0.1", 0) {|tcpserver|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.key = OpenSSL::PKey.read(read_fixture("server.key"))
      ctx.cert = OpenSSL::X509::Certificate.new(read_fixture("server.crt"))
      serv = OpenSSL::SSL::SSLServer.new(tcpserver, ctx)

      _, port, _, _ = serv.addr
      client_thread = Thread.new {
        proxy = Net::HTTP.Proxy("127.0.0.1", port, 'user', 'password', true)
        http = proxy.new("foo.example.org", 8000)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        begin
          http.start
        rescue EOFError
        end
      }
      server_thread = Thread.new {
        sock = serv.accept
        begin
          proxy_request = sock.gets("\r\n\r\n")
          assert_equal(
            "CONNECT foo.example.org:8000 HTTP/1.1\r\n" +
            "Host: foo.example.org:8000\r\n" +
            "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n" +
            "\r\n",
            proxy_request,
            "[ruby-core:96672]")
        ensure
          sock.close
        end
      }
      assert_join_threads([client_thread, server_thread])
    }
  end
end
