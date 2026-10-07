# frozen_string_literal: false
require 'test/unit'
require 'drb/drb'

class TestDRbEndpointGroupUnit < Test::Unit::TestCase
  class PendingReplyProtocol
    def send_request(ref, message_id, arguments, block)
      7
    end

    def recv_reply
      raise DRb::DRbConnError, 'connection closed while waiting'
    end

    def close
    end

    def alive?
      false
    end
  end

  class PartialWriteStream
    attr_reader :sent

    def initialize(written)
      @written = written
      @sent = 0
    end

    def write(message)
      count = [message.bytesize, @written - @sent].min
      raise IOError, 'forced failure' if count <= 0
      @sent += count
      count
    end
  end

  def test_front_tries_each_endpoint_before_a_request_is_sent
    group = DRb::DRbEndpointGroup.new('druby://127.0.0.1:1',
                                      'druby://127.0.0.1:2')
    attempts = 0
    interceptor = Module.new do
      define_method(:open) do |uri, config|
        attempts += 1
        raise DRb::DRbConnError, "#{uri} unavailable"
      end
    end
    DRb::DRbProtocol.singleton_class.prepend(interceptor)

    error = assert_raise(DRb::DRbConnError) do
      group.front.record('never sent')
    end
    assert_equal(2, attempts)
    assert_not_kind_of(DRb::DRbUnknownStatusError, error)
  end

  def test_endpoint_group_requires_an_endpoint
    assert_raise(ArgumentError) { DRb::DRbEndpointGroup.new }
  end

  def test_failure_while_waiting_for_a_reply_is_not_retried
    connection = DRb::DRbConn.allocate
    connection.instance_variable_set(:@uri, 'druby://127.0.0.1:1')
    connection.instance_variable_set(:@protocol, PendingReplyProtocol.new)
    proxy = DRb::DRbObject.new(nil, 'druby://127.0.0.1:1')

    assert_raise(DRb::DRbUnknownStatusError) do
      connection.send_message(proxy, :record, ['sent'], nil)
    end
  end

  def test_failure_after_a_partial_write_is_unknown
    message = DRb::DRbMessage.new(DRb.config)
    stream = PartialWriteStream.new(1)
    proxy = DRb::DRbObject.new(nil, 'druby://127.0.0.1:1')

    assert_raise(DRb::DRbUnknownStatusError) do
      message.send_request(stream, proxy, :record, ['partial'], nil)
    end
    assert_equal(1, stream.sent)
  end
end
