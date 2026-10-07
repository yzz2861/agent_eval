# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb'

class TestDRbEndpointGroup < Test::Unit::TestCase
  WORKER_ID = 4242

  class RecordingWorker
    include DRb::DRbUndumped

    def initialize(front)
      @front = front
    end

    def ping(name)
      @front.worker_calls << name
      name
    end
  end

  class RecordingFront
    include DRb::DRbUndumped

    attr_reader :calls, :worker_calls, :worker

    def initialize
      @calls = []
      @worker_calls = []
      @worker = RecordingWorker.new(self)
    end

    def ping(name)
      @calls << name
      name
    end

    def disconnect_without_reply
      @calls << __method__
      client = Thread.current['DRb']['client']
      Thread.start do
        sleep 0.05
        client.close
      end
      sleep 0.3
    end
  end

  class RecordingIdConv < DRb::DRbIdConv
    def initialize(front)
      @worker = front.worker
    end

    def to_id(obj)
      obj.equal?(@worker) ? TestDRbEndpointGroup::WORKER_ID : super
    end

    def to_obj(ref)
      ref == TestDRbEndpointGroup::WORKER_ID ? @worker : super
    end
  end

  def setup
    @client_service = DRb::DRbServer.new(nil)
    @servers = []
    @primary_front = RecordingFront.new
    @primary = start_service(@primary_front)
    @backup_front = RecordingFront.new
    @backup = start_service(@backup_front)
    @group = DRb::DRbEndpointGroup.new(@primary.uri, @backup.uri)
  end

  def teardown
    @servers.each do |server|
      server.stop_service
      server.thread.join
    end
    @client_service.stop_service
    @client_service.thread.join
    DRb::DRbConn.stop_pool
  end

  def test_front_failover_and_bound_object_identity
    assert_equal(:primary, @group.front.ping(:primary))
    primary_worker = @group.front.worker
    assert_equal(:worker, primary_worker.ping(:worker))
    assert_equal(@primary.uri, primary_worker.__drburi)
    assert_equal(WORKER_ID, primary_worker.__drbref)
    assert_equal(@primary.service_id, primary_worker.__drbservice)

    stop_service(@primary)
    DRb::DRbConn.stop_pool

    assert_equal(:backup, @group.front.ping(:backup))
    assert_raise(DRb::DRbConnError) do
      primary_worker.ping(:after_primary_stop)
    end
    assert_equal([:worker], @primary_front.worker_calls)
    assert_equal([], @backup_front.worker_calls)
    assert_equal([:primary], @primary_front.calls)
    assert_equal([:backup], @backup_front.calls)

    restarted_front = RecordingFront.new
    start_service(restarted_front, @primary.uri)
    error = assert_raise(DRb::DRbRemoteError) do
      primary_worker.ping(:stale)
    end
    assert_equal('DRb::DRbStaleReferenceError', error.reason)
    assert_equal([], restarted_front.worker_calls)
    assert_equal([], @backup_front.worker_calls)

    assert_raise(DRb::DRbUnknownStatusError) do
      @group.front.disconnect_without_reply
    end
    sleep 0.1
    assert_equal([:backup], @backup_front.calls)
    assert_equal([:disconnect_without_reply], restarted_front.calls)
  end

  private

  def start_service(front, uri = 'druby://127.0.0.1:0')
    server = DRb::DRbServer.new(uri, front, idconv: RecordingIdConv.new(front))
    @servers << server
    server
  end

  def stop_service(server)
    server.stop_service
    server.thread.join
    @servers.delete(server)
  end
end

class TestDRbEndpointGroupConnection < Test::Unit::TestCase
  def setup
    @primary = DRb::DRbEndpoint.new('druby://primary.example:1')
    @backup = DRb::DRbEndpoint.new('druby://backup.example:1')
  end

  def teardown
    restore_class_method(:acquire_connection)
    restore_class_method(:use_connection)
  end

  def test_service_identity_is_part_of_object_identity
    old_reference = DRb::DRbObject.new_with(@primary.uri, 4242, 'old-service')
    new_reference = DRb::DRbObject.new_with(@primary.uri, 4242, 'new-service')
    loaded = Marshal.load(Marshal.dump(old_reference))

    assert_not_equal(old_reference, new_reference)
    assert_not_equal(old_reference.hash, new_reference.hash)
    assert_equal(4242, loaded.__drbref)
    assert_equal('old-service', loaded.__drbservice)
  end

  def test_group_parses_endpoint_uris
    group = DRb::DRbEndpointGroup.new('druby://primary.example:1?front', 'druby://backup.example:1')

    assert_equal('druby://primary.example:1', group.endpoints[0].uri)
    assert_equal('front', group.endpoints[0].option)
    assert_equal('druby://backup.example:1', group.endpoints[1].uri)
    assert_nil(group.endpoints[1].option)
    assert_kind_of(DRb::DRbFrontObject, group.front)
  end

  def test_failover_only_while_acquiring_connection
    attempted = []
    stub_acquire do |endpoint|
      attempted << endpoint
      raise DRb::DRbConnError, 'closed' if endpoint == @primary
      Object.new
    end
    stub_use

    selected = DRb::DRbConn.open_group([@primary, @backup]) do |connection, endpoint|
      [endpoint, connection]
    end

    assert_equal([@primary, @backup], attempted)
    assert_equal(@backup, selected[0])
  end

  def test_request_started_is_not_retried
    attempted = []
    primary_connection = Object.new
    stub_acquire do |endpoint|
      attempted << endpoint
      primary_connection
    end
    stub_use

    assert_raise(DRb::DRbUnknownStatusError) do
      DRb::DRbConn.open_group([@primary, @backup]) do |connection, endpoint|
        assert_equal(primary_connection, connection)
        assert_equal(@primary, endpoint)
        raise DRb::DRbUnknownStatusError, 'request status unknown'
      end
    end

    assert_equal([@primary], attempted)
  end

  private

  def stub_acquire(&block)
    implementation = block
    EnvUtil.suppress_warning do
      DRb::DRbConn.singleton_class.alias_method(:original_acquire_connection, :acquire_connection)
      DRb::DRbConn.singleton_class.define_method(:acquire_connection) do |endpoint|
        implementation.call(endpoint)
      end
    end
  end

  def stub_use
    EnvUtil.suppress_warning do
      DRb::DRbConn.singleton_class.alias_method(:original_use_connection, :use_connection)
      DRb::DRbConn.singleton_class.define_method(:use_connection) do |_connection, &request_block|
        request_block.call
      end
    end
  end

  def restore_class_method(name)
    original_name = "original_#{name}"
    if DRb::DRbConn.respond_to?(original_name, true)
      EnvUtil.suppress_warning do
        DRb::DRbConn.singleton_class.alias_method(name, original_name)
        DRb::DRbConn.singleton_class.remove_method(original_name)
      end
    end
  end
end
