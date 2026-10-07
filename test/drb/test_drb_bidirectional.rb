# frozen_string_literal: false
require 'test/unit'
require_relative '../../lib/drb/drb'
require 'timeout'

module DRbBidirectionalTests
  class CallbackError < RuntimeError; end

  class Callback
    include DRb::DRbUndumped

    def initialize
      @mutex = Thread::Mutex.new
      @condition = Thread::ConditionVariable.new
      @started = 0
    end

    def nested_call(service, depth)
      return 'client:' + depth.to_s if depth.zero?
      service.three_level(self, depth - 1)
    end

    def wait_for_pair
      @mutex.synchronize do
        @started += 1
        @condition.broadcast
        @condition.wait(@mutex) until @started == 2
        @started
      end
    end

    def fail!
      raise CallbackError, 'callback failed'
    end
  end

  class Front
    def ping
      :pong
    end

    def three_level(callback, depth)
      value = callback.nested_call(self, depth)
      'server:' + depth.to_s + ':' + value.to_s
    end

    def concurrent(callback)
      callback.wait_for_pair
    end

    def close_session_then(callback)
      callback.nested_call(self, 0)
      DRb::DRbBidiSession.current.close
      sleep 1
    end

    def callback_failure(callback)
      callback.fail!
    end
  end
end

class DRbBidirectionalTests::TestBidirectional < Test::Unit::TestCase
  def setup
    @server = DRb.start_service('druby://127.0.0.1:0', DRbBidirectionalTests::Front.new, bidirectional: true)
    @uri = @server.uri.sub(/^druby:/, 'drbbidi:')
  end

  def teardown
    DRb::DRbConn.stop_pool
    @server&.stop_service
    @server&.thread&.join(5)
  end

  def test_simple_request
    assert_equal(:pong, DRb::DRbObject.new_with_uri(@uri).ping)
  end

  def test_legacy_uri_still_uses_legacy_messages
    assert_equal(:pong, DRb::DRbObject.new_with_uri(@server.uri).ping)
  end

  def test_three_level_nested_callbacks
    callback = DRbBidirectionalTests::Callback.new
    result = DRb::DRbObject.new_with_uri(@uri).three_level(callback, 2)
    assert_equal('server:0:client:0', result)
  end

  def test_two_concurrent_requests_share_one_socket
    front = DRb::DRbObject.new_with_uri(@uri)
    callback = DRbBidirectionalTests::Callback.new
    results = []
    threads = 2.times.map do
      Thread.new do
        Thread.current.report_on_exception = false
        results << front.concurrent(callback)
      end
    end

    Timeout.timeout(5) { threads.each(&:join) }
    assert_equal([2, 2], results.sort)
    assert_equal(1, @server.instance_variable_get(:@bidi_sessions).size)
  end

  def test_close_wakes_concurrent_waiters
    front = DRb::DRbObject.new_with_uri(@uri)
    callback = DRbBidirectionalTests::Callback.new
    closing = Thread.new do
      Thread.current.report_on_exception = false
      assert_raise(DRb::DRbConnError) { front.close_session_then(callback) }
    end

    waiter = Thread.new do
      Thread.current.report_on_exception = false
      assert_raise(DRb::DRbConnError) { front.ping }
    end

    Timeout.timeout(5) do
      closing.join
      waiter.join
    end
  end

  def test_callback_exception_returns_to_calling_layer
    callback = DRbBidirectionalTests::Callback.new
    error = assert_raise(DRb::DRbRemoteError) do
      DRb::DRbObject.new_with_uri(@uri).callback_failure(callback)
    end
    assert_match(/callback failed/, error.message)
  end

  def test_bidi_client_rejects_legacy_server
    legacy = DRb::DRbServer.new('druby://127.0.0.1:0', DRbBidirectionalTests::Front.new)
    uri = legacy.uri.sub(/^druby:/, 'drbbidi:')
    assert_raise(DRb::DRbConnError) do
      DRb::DRbObject.new_with_uri(uri).ping
    end
  ensure
    legacy.stop_service
    legacy.thread.join(5)
  end
end
