# frozen_string_literal: false
require 'test/unit'
require 'drb/drb'
require 'timeout'

class TestDRbEndpointGroup < Test::Unit::TestCase
  class Recorder
    include DRb::DRbUndumped

    def initialize(name)
      @name = name
      @calls = []
    end

    attr_reader :calls

    def record(message)
      @calls << message
      @name
    end

    def sleep_then_record(message, seconds)
      sleep(seconds)
      record(message)
    end

    def object
      self
    end
  end

  class WritingStream
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

  def setup
    DRb.start_service('druby://127.0.0.1:0', nil)
    @primary = DRb::DRbServer.new('druby://127.0.0.1:0', Recorder.new('primary'))
    @backup = DRb::DRbServer.new('druby://127.0.0.1:0', Recorder.new('backup'))
    @group = DRb::DRbEndpointGroup.new('druby://127.0.0.1:1', @backup.uri)
  end

  def teardown
    @primary&.stop_service
    @backup&.stop_service
    DRb.stop_service
    DRb::DRbConn.stop_pool
  end

  def test_front_fails_over_before_a_request_is_sent
    assert_equal('backup', @group.front.record('front'))
    assert_equal(['front'], @backup.front.calls)
    assert_equal([], @primary.front.calls)
  end

  def test_returned_object_is_bound_to_actual_endpoint_and_server
    object = @group.front.object

    assert_instance_of(DRb::DRbObject, object)
    refute_instance_of(DRb::DRbFrontObject, object)
    assert_equal(@backup.uri, object.__drburi)
    assert_equal(@backup.server_id, object.__drb_server_id)
    assert_equal('backup', object.record('object'))
    assert_equal(['object'], @backup.front.calls)
  end

  def test_old_object_is_not_routed_to_equivalent_backup
    primary_group = DRb::DRbEndpointGroup.new(@primary.uri, @backup.uri)
    object = primary_group.front.object
    @primary.stop_service

    assert_raise(DRb::DRbConnError) do
      object.record('stale endpoint')
    end
    assert_equal([], @backup.front.calls)
  ensure
    @primary = nil
  end

  def test_object_reference_fails_after_server_restart
    uri = @primary.uri
    object = DRb::DRbObject.new(nil, uri).object
    server_id = @primary.server_id

    @primary.stop_service
    @primary = DRb::DRbServer.new(uri, Recorder.new('restarted'),
                                  server_id: SecureRandom.uuid)

    error = assert_raise(DRb::DRbStaleReferenceError) do
      object.record('old instance')
    end
    assert_include(error.message, server_id)
    assert_equal([], @primary.front.calls)
  end

  def test_failure_after_a_partial_write_is_unknown_and_not_retried
    DRb::DRbEndpointGroup.new(@primary.uri, @backup.uri)
    message = DRb::DRbMessage.new(DRb.config)
    stream = WritingStream.new(1)
    proxy = DRb::DRbObject.new(nil, @primary.uri)

    assert_raise(DRb::DRbUnknownStatusError) do
      message.send_request(stream, proxy, :record, ['partial'], nil)
    end
    assert_equal(1, stream.sent)
    assert_equal([], @primary.front.calls)
    assert_equal([], @backup.front.calls)
  end

  def test_failure_while_waiting_for_a_reply_is_unknown
    group = DRb::DRbEndpointGroup.new(@primary.uri, @backup.uri)
    thread = Thread.start do
      group.front.sleep_then_record('waiting', 0.2)
    end
    sleep(0.05)
    stop_service(@primary)

    assert_raise(DRb::DRbUnknownStatusError) do
      Timeout.timeout(5) { thread.value }
    end
    sleep(0.3)
    assert_equal([], @backup.front.calls)
  ensure
    @primary = nil
  end

  def test_connection_pool_is_isolated_by_endpoint
    DRb::DRbConn.open(@primary.uri) do |connection|
      connection.send_message(DRb::DRbObject.new(nil, @primary.uri),
                              :record, ['pool-primary'], nil)
    end
    DRb::DRbConn.open(@backup.uri) do |connection|
      connection.send_message(DRb::DRbObject.new(nil, @backup.uri),
                              :record, ['pool-backup'], nil)
    end

    assert_equal(['pool-primary'], @primary.front.calls)
    assert_equal(['pool-backup'], @backup.front.calls)
  end

  private

  def stop_service(server)
    server.stop_service
    server.instance_variable_get(:@grp).list.each do |worker|
      worker.kill
      worker.join
    end
  end
end
