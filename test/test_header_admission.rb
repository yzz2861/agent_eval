# frozen_string_literal: true

require_relative "helper"
require 'puma/client'

class TestHeaderAdmission < PumaTest
  include Puma::Const

  def create_client(request, &hook)
    @rd, @wr = UNIXSocket.pair
    @rd.define_singleton_method(:peeraddr) { ["AF_INET", 80, "127.0.0.1", "127.0.0.1"] }

    @continue_writes = []
    writes = @continue_writes
    @rd.define_singleton_method(:<<) do |data|
      writes << data
      super(data)
      self
    end

    @client = Puma::Client.new(@rd, {})
    @client.supported_http_methods = SUPPORTED_HTTP_METHODS.sort.product([nil]).to_h
    @client.header_admission = hook
    @wr.write(request)
    @client.try_to_finish while !@client.ready
  end

  def teardown
    @wr&.close
    @rd&.close
  end

  def test_hook_receives_frozen_header_information_before_100_continue
    hook_env = nil

    request = "POST / HTTP/1.1\r\nHost: test.com\r\n" \
      "Content-Type: text/plain\r\nContent-Length: 11\r\n" \
      "Expect: 100-continue\r\nX-Upload: yes\r\n\r\nHello World"

    create_client(request) do |env|
      hook_env = env
      assert_predicate hook_env, :frozen?
      assert_predicate hook_env['HTTP_HOST'], :frozen?
      assert_equal '11', hook_env[CONTENT_LENGTH]
      assert_equal 'text/plain', hook_env[CONTENT_TYPE]
      assert_equal 'yes', hook_env['HTTP_X_UPLOAD']
      refute_includes hook_env, RACK_INPUT
      refute_includes hook_env, PUMA_SOCKET
      assert_empty @continue_writes
      :allow
    end

    assert_equal [HTTP_11_100], @continue_writes
    assert_raises(FrozenError) { hook_env['HTTP_X'] = '1' }
    assert_raises(FrozenError) { hook_env['HTTP_HOST'] << '.example' }
  end

  def test_rejection_drops_buffered_body_and_pipelined_request
    request = "POST / HTTP/1.1\r\nHost: test.com\r\nConnection: keep-alive\r\n" \
      "Content-Length: 8\r\nExpect: 100-continue\r\n\r\nRejected" \
      "GET /next HTTP/1.1\r\nHost: test.com\r\n\r\n"

    error = assert_raises(Puma::HeaderAdmissionError) do
      create_client(request) do
        raise Puma::HeaderAdmissionError.new(403, {}, ['Rejected'])
      end
    end

    assert_equal 403, error.status
    assert_equal ['Rejected'], error.body
    assert_equal 'close', @client.env[HTTP_CONNECTION]
    assert_equal Puma::Client::EmptyBody, @client.body
    assert_nil @client.instance_variable_get(:@buffer)
    assert_equal 0, @client.requests_served
    assert_empty @continue_writes
  end
end
