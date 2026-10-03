# frozen_string_literal: false
require "test/unit"
require_relative "utils"
begin
  require 'net/https'
rescue LoadError
  # should skip this test
end

class TestNetHTTPAddressAdmission < Test::Unit::TestCase
  include TestNetHTTPUtils

  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
  }

  LOGICAL_HOST = 'example.test'

  def new_http(host = LOGICAL_HOST, port = config('port'))
    Net::HTTP::Proxy(nil, nil).new(host, port)
  end

  def test_dials_admitted_resolved_address
    http = new_http
    http.resolver = ->(host) { ['127.0.0.1'] }
    http.address_admission = ->(addr) { true }
    http.start do |h|
      res = h.get('/')
      assert_equal $test_net_http_data, res.body
      assert_equal '127.0.0.1', h.ipaddr
    end
  end

  def test_logical_host_identity_preserved
    seen_host = nil
    @server.mount_proc('/host') {|req, res|
      seen_host = req.headers['Host']
      res.body = 'ok'
    }
    http = new_http
    http.resolver = ->(host) { ['127.0.0.1'] }
    http.address_admission = ->(addr) { true }
    http.start do |h|
      res = h.get('/host')
      assert_equal 'ok', res.body
    end
    assert_equal "#{LOGICAL_HOST}:#{config('port')}", seen_host
  end

  def test_admission_receives_each_candidate_before_dialing
    seen = []
    http = new_http
    http.resolver = ->(host) { ['127.0.0.2', '127.0.0.1'] }
    http.address_admission = ->(addr) { seen << addr; addr == '127.0.0.1' }
    http.start do |h|
      res = h.get('/')
      assert_equal $test_net_http_data, res.body
      assert_equal '127.0.0.1', h.ipaddr
    end
    assert_equal ['127.0.0.2', '127.0.0.1'], seen
  end

  def test_falls_through_admitted_candidates_in_order
    http = new_http
    http.resolver = ->(host) { ['::1', '127.0.0.1'] }
    http.address_admission = ->(addr) { true }
    http.start do |h|
      res = h.get('/')
      assert_equal $test_net_http_data, res.body
      assert_equal '127.0.0.1', h.ipaddr
    end
  end

  def test_rejected_address_is_never_dialed
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    http = new_http(LOGICAL_HOST, port)
    http.resolver = ->(host) { ['127.0.0.1'] }
    http.address_admission = ->(addr) { false }
    assert_raise(Net::HTTPAddressNotAllowed) { http.start {} }
    sleep 0.1
    assert_raise(IO::WaitReadable) { server.accept_nonblock }
  ensure
    server&.close
  end

  def test_reconnect_reruns_resolution_and_admission
    resolutions = 0
    admissions = []
    allow = true
    http = new_http
    http.resolver = ->(host) { resolutions += 1; ['127.0.0.1'] }
    http.address_admission = ->(addr) { admissions << addr; allow }
    http.start {|h| h.get('/') }
    allow = false
    assert_raise(Net::HTTPAddressNotAllowed) { http.start {} }
    assert_equal 2, resolutions
    assert_equal ['127.0.0.1', '127.0.0.1'], admissions
  end

  def test_start_accepts_resolver_and_admission_opts
    admitted = []
    Net::HTTP.start(LOGICAL_HOST, config('port'), nil, nil,
                    resolver: ->(host) { ['127.0.0.1'] },
                    address_admission: ->(addr) { admitted << addr; true }) do |http|
      res = http.get('/')
      assert_equal $test_net_http_data, res.body
    end
    assert_equal ['127.0.0.1'], admitted
  end

  def test_proxy_connection_is_checked_not_origin
    resolved = []
    admitted = []
    proxy = Net::HTTP::Proxy('proxy.example.test', config('port'))
    http = proxy.new('origin.example.test', 80)
    http.resolver = ->(host) { resolved << host; ['127.0.0.1'] }
    http.address_admission = ->(addr) { admitted << addr; true }
    http.start do |h|
      res = h.get('/')
      assert_equal $test_net_http_data, res.body
    end
    assert_equal ['proxy.example.test'], resolved
    assert_equal ['127.0.0.1'], admitted
  end

  def test_rejected_proxy_address_is_never_dialed
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    proxy = Net::HTTP::Proxy('proxy.example.test', port)
    http = proxy.new('origin.example.test', 80)
    http.resolver = ->(host) { ['127.0.0.1'] }
    http.address_admission = ->(addr) { false }
    assert_raise(Net::HTTPAddressNotAllowed) { http.start {} }
    sleep 0.1
    assert_raise(IO::WaitReadable) { server.accept_nonblock }
  ensure
    server&.close
  end
end

if defined?(OpenSSL::SSL)
class TestNetHTTPAddressAdmissionSSL < Test::Unit::TestCase
  include TestNetHTTPUtils

  def self.read_fixture(key)
    File.read(File.expand_path("../fixtures/#{key}", __dir__))
  end

  CA_CERT = OpenSSL::X509::Certificate.new(read_fixture("cacert.pem"))
  SERVER_KEY = OpenSSL::PKey.read(read_fixture("server.key"))
  SERVER_CERT = OpenSSL::X509::Certificate.new(read_fixture("server.crt"))
  TEST_STORE = OpenSSL::X509::Store.new.tap {|s| s.add_cert(CA_CERT) }

  CONFIG = {
    'host' => '127.0.0.1',
    'proxy_host' => nil,
    'proxy_port' => nil,
    'ssl_enable' => true,
    'ssl_certificate' => SERVER_CERT,
    'ssl_private_key' => SERVER_KEY,
  }

  def new_https(host)
    http = Net::HTTP::Proxy(nil, nil).new(host, config('port'))
    http.use_ssl = true
    http.cert_store = TEST_STORE
    http.resolver = ->(hostname) { ['127.0.0.1'] }
    http.address_admission = ->(addr) { true }
    http
  end

  def test_tls_verification_uses_logical_host
    http = new_https('localhost')
    http.start do |h|
      res = h.get('/')
      assert_equal $test_net_http_data, res.body
      assert_equal '127.0.0.1', h.ipaddr
      assert_equal SERVER_CERT.to_der, h.peer_cert.to_der
    end
  end

  def test_tls_verification_not_weakened_by_ip_dialing
    http = new_https('not-localhost.example.test')
    assert_raise(OpenSSL::SSL::SSLError) { http.start {} }
  end
end
end
