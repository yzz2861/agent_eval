# frozen_string_literal: false
require 'test/unit'
require 'drb/timeridconv'
require 'drb/drb'
require 'stringio'
require 'weakref'

module DRbTests

class FakeClock
  attr_accessor :now

  def initialize(now)
    @now = now
  end
end

class TimerIdConvTest < Test::Unit::TestCase
  def setup
    @clock = FakeClock.new(100)
    @idconv = DRb::TimerIdConv.new(10, clock: @clock)
  end

  def teardown
    @idconv.close
  end

  def leased_object
    object = Object.new
    weak = WeakRef.new(object)
    lease = @idconv.to_id(object)
    [lease, weak]
  end

  def perform_active_call(clock)
    object = Object.new
    weak = WeakRef.new(object)
    lease = @idconv.to_id(object)
    keepalives = []
    Thread.current['DRb'] = { 'keepalives' => keepalives }
    begin
      fetched = @idconv.to_obj(lease.id)
      raise unless fetched.equal?(object)
      clock.now = 110
      yield(weak, keepalives, lease)
    ensure
      Thread.current['DRb'] = nil
    end
  end

  def test_lease_grants_expiry_and_keeps_object_alive
    lease, weak = leased_object

    assert_kind_of(DRb::TimerIdConv::Lease, lease)
    assert_equal(@clock.now + 10, lease.expires_at)
    assert_equal(@idconv.to_obj(lease.id), @idconv.to_obj(lease.id))
    GC.start
    assert_predicate(weak, :weakref_alive?)
  end

  def test_lease_expiration_uses_injected_server_clock
    lease, _weak = leased_object
    object = @idconv.to_obj(lease.id)

    @clock.now = 108
    assert_same(object, @idconv.to_obj(lease.id))

    @clock.now = 110
    error = assert_raise(DRb::TimerIdConv::ExpiredLeaseError) do
      @idconv.to_obj(lease.id)
    end
    assert_kind_of(DRb::InvalidReferenceError, error)
  end

  def test_renew_extends_with_server_clock
    lease, _weak = leased_object
    object = @idconv.to_obj(lease.id)
    @clock.now = 109

    lease.renew(5)
    @clock.now = 113
    assert_same(object, @idconv.to_obj(lease.id))

    @clock.now = 114
    assert_raise(DRb::TimerIdConv::ExpiredLeaseError) do
      @idconv.to_obj(lease.id)
    end
  end

  def test_expired_lease_cannot_be_renewed
    lease, weak = leased_object
    @clock.now = 110
    @idconv.reap
    GC.start

    assert_not_predicate(weak, :weakref_alive?)
    assert_raise(DRb::TimerIdConv::ExpiredLeaseError) { lease.renew }
  end

  def test_release_allows_garbage_collection
    lease, weak = leased_object

    assert_equal(true, lease.release())
    GC.start

    assert_not_predicate(weak, :weakref_alive?)
    assert_raise(DRb::TimerIdConv::InvalidLeaseError) do
      @idconv.to_obj(lease.id)
    end
    assert_equal(false, lease.release())
  end

  def test_separate_leases_are_counted_and_released_independently
    object = Object.new
    first = @idconv.to_id(object)
    second = @idconv.to_id(object)

    assert_not_equal(first.id, second.id)
    assert_equal(true, first.release)
    assert_raise(DRb::TimerIdConv::InvalidLeaseError) do
      @idconv.to_obj(first.id)
    end
    assert_same(object, @idconv.to_obj(second.id))

    @clock.now = 110
    @idconv.reap
    assert_raise(DRb::TimerIdConv::ExpiredLeaseError) do
      @idconv.to_obj(second.id)
    end
  end

  def test_reclaimed_lease_id_cannot_point_to_a_new_object
    old_lease, = leased_object
    old_id = old_lease.id
    old_lease.release

    new_lease, _new_weak = leased_object
    new_object = @idconv.to_obj(new_lease.id)

    assert_not_equal(old_id, new_lease.id)
    assert_raise(DRb::TimerIdConv::InvalidLeaseError) do
      @idconv.to_obj(old_id)
    end
    assert_same(new_object, @idconv.to_obj(new_lease.id))
  end

  def test_new_lease_avoids_unevicted_tombstone_id
    holder = @idconv.instance_variable_get(:@holder)
    lease = @idconv.to_id(Object.new)
    holder.reap
    @clock.now = 200
    holder.define_singleton_method(:generate_id) do
      @random_ids ||= [lease.id, 'new-lease-id'].each
      @random_ids.next
    end
    assert_equal('new-lease-id', holder.send(:unique_id))
  end

  def test_expired_renewals_are_decided_consistently
    holder = @idconv.instance_variable_get(:@holder)
    lease = @idconv.to_id(Object.new)
    queue = Queue.new
    attempts = 20.times.map do
      Thread.new do
        queue.pop
        begin
          holder.renew(lease.id, 5)
          :renewed
        rescue DRb::TimerIdConv::ExpiredLeaseError
          :expired
        end
      end
    end
    @clock.now = 110
    20.times { queue.push(:go) }

    results = attempts.map(&:value).sort.uniq
    assert_equal([:expired], results)
  end

  def test_active_call_keeps_object_until_request_finishes
    lease_id = nil
    collected = perform_active_call(@clock) do |weak_reference, keepalives, active_lease|
      lease_id = active_lease.id
      assert_equal(1, keepalives.size)
      assert_predicate(weak_reference, :weakref_alive?)
      keepalives.first.finish
      weak_reference
    end
    GC.start
    assert_not_predicate(collected, :weakref_alive?)
    assert_raise(DRb::TimerIdConv::ExpiredLeaseError) do
      @idconv.to_obj(lease_id)
    end
  end

  def test_release_during_active_call_allows_completion_then_reclamation
    id = nil
    collected = perform_active_call(@clock) do |weak_reference, keepalives, lease|
      id = lease.id
      assert_equal(true, lease.release)
      keepalives.first.finish
      weak_reference
    end
    GC.start

    assert_not_predicate(collected, :weakref_alive?)
    assert_raise(DRb::TimerIdConv::InvalidLeaseError) do
      @idconv.to_obj(id)
    end
  end
end

class TimerLeaseMessageTest < Test::Unit::TestCase
  class FakeServer
    attr_reader :config
    attr_reader :uri

    def initialize(idconv)
      @config = {:idconv => idconv, :load_limit => 26214400, :argc_limit => 256}
      @uri = 'druby://example:1'
    end

    def to_obj(ref)
      @config[:idconv].to_obj(ref)
    end

    def to_id(obj)
      @config[:idconv].to_id(obj)
    end
  end

  def setup
    @clock = FakeClock.new(100)
    @idconv = DRb::TimerIdConv.new(10, clock: @clock)
    @server = FakeServer.new(@idconv)
    @message = DRb::DRbMessage.new(@server.config)
  end

  def teardown
    @idconv.close
  end

  def reply(succ, result)
    stream = StringIO.new
    @message.send_reply(stream, succ, result)
    stream.rewind
    @message.recv_reply(stream)
  end

  def send_receive(ref, name, *args)
    stream = StringIO.new
    proxy = DRb::DRbObject.new_with('druby://example:1', ref)
    @message.send_request(stream, proxy, name, args, nil)
    stream.rewind
    Thread.current['DRb'] = { 'server' => @server, 'keepalives' => [] }
    @message.recv_request(stream)
  ensure
    Thread.current['DRb'] = nil
  end

  def test_lease_round_trip_and_remote_renew
    object = Object.new
    Thread.current['DRb'] = { 'server' => @server }
    server_lease = @idconv.to_id(object)
    Thread.current['DRb'] = nil
    assert_kind_of(DRb::DRbObject, server_lease.instance_variable_get(:@lease_manager))
    lease_stream = StringIO.new(Marshal.dump(server_lease))
    client_lease = Marshal.load(lease_stream.read)

    assert_equal(server_lease.id, client_lease.id)
    assert_equal(server_lease.expires_at, client_lease.expires_at)

    @clock.now = 109
    manager = client_lease.instance_variable_get(:@lease_manager)
    assert_kind_of(DRb::DRbObject, manager)
    request = [manager.__drbref, :renew, client_lease.id, 5]
    manager_ref, name, args, _block = send_receive(*request)
    assert_kind_of(DRb::TimerIdConv::TimerHolder2::LeaseManager, manager_ref)
    assert_equal('renew', name)
    assert_equal([client_lease.id, 5], args)
    succ, expires_at = reply(true, manager_ref.public_send(name.to_sym, *args))
    assert(succ)
    assert_equal(114, expires_at)
  end

  def test_target_call_temporarily_survives_expiry_through_reply
    object = Object.new
    def object.ping
      :pong
    end
    server_lease = @idconv.to_id(object)
    client_lease = Marshal.load(StringIO.new(Marshal.dump(server_lease)).read)
    stream = StringIO.new
    proxy = DRb::DRbObject.new_with('druby://example:1', client_lease)
    @message.send_request(stream, proxy, :ping, [], nil)
    stream.rewind
    keepalives = []
    Thread.current['DRb'] = { 'server' => @server, 'keepalives' => keepalives }
    target, name, _args, _block = @message.recv_request(stream)
    @clock.now = 110
    result = target.public_send(name)
    succ, reply_result = reply(true, result)
    keepalives.each(&:finish)
    Thread.current['DRb'] = nil

    assert_equal(1, keepalives.size)
    assert(succ)
    assert_equal(:pong, reply_result)
    assert_raise(DRb::TimerIdConv::ExpiredLeaseError) do
      @idconv.to_obj(client_lease.id)
    end
  end

  def test_expired_reference_raises_named_invalid_reference_error
    lease = @idconv.to_id(Object.new)
    @clock.now = 110
    @idconv.reap

    error = assert_raise(DRb::TimerIdConv::ExpiredLeaseError) do
      @idconv.to_obj(lease.id)
    end
    assert_equal(DRb::TimerIdConv::ExpiredLeaseError.to_s, error.class.to_s)
    assert_kind_of(DRb::InvalidReferenceError, error)
  end
end

end
