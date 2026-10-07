# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb/timeridconv'
require 'weakref'

class TestTimerIdConv < Test::Unit::TestCase
  class ManualClock
    attr_accessor :now

    def initialize(now = 0)
      @now = now
    end
  end

  class LeasedObject
    include DRb::DRbUndumped

    def ping
      :pong
    end
  end

  class Factory
    include DRb::DRbUndumped

    def make
      LeasedObject.new
    end
  end

  class ReturningObject
    include DRb::DRbUndumped

    def initialize(callback)
      @callback = callback
    end

    def call
      @callback.call
      self
    end
  end

  class InvokeClient
    attr_reader :raw_ref

    def initialize(raw_ref, message, arguments = [], block = nil)
      @raw_ref = raw_ref
      @message = message
      @arguments = arguments
      @block = block
    end

    def recv_request_raw_ref
      @raw_ref
    end

    def recv_request_message
      @message
    end

    def recv_request_arguments
      @arguments
    end

    def recv_request_block
      @block
    end
  end

  def setup
    @clock = ManualClock.new
    @idconv = DRb::TimerIdConv.new(10, @clock)
  end

  def test_lease_keeps_object_alive_until_expiry
    exported = export_object
    weak = exported[:weak]
    token = exported[:token]
    GC.start
    assert_predicate(weak, :weakref_alive?)

    @clock.now = 9
    cleanup
    GC.start
    assert_predicate(weak, :weakref_alive?)

    @clock.now = 10
    cleanup
    GC.start
    refute_predicate(weak, :weakref_alive?)
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(token) }
  end

  def test_separate_leases_are_counted_and_released_independently
    object = Object.new
    first = @idconv.to_id(object)
    second = @idconv.to_id(object)

    assert_equal(object, @idconv.to_obj(first))
    assert_equal(object, @idconv.to_obj(second))

    assert_equal(true, @idconv.to_obj(DRb::DRbLease::SERVICE_REF).release_lease(first))
    assert_equal(object, @idconv.to_obj(second))

    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(first) }
    @idconv.to_obj(second)

    @idconv.to_obj(DRb::DRbLease::SERVICE_REF).release_lease(second)
    cleanup
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(second) }
  end

  def test_release_does_not_affect_expired_other_lease
    object = Object.new
    first = @idconv.to_id(object)
    second = @idconv.to_id(object)

    @clock.now = 10
    assert_equal(false, @idconv.to_obj(DRb::DRbLease::SERVICE_REF).release_lease(second))
    cleanup
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(first) }
  end

  def test_renew_uses_server_clock
    object = Object.new
    token = @idconv.to_id(object)

    @clock.now = 9
    deadline = @idconv.to_obj(DRb::DRbLease::SERVICE_REF).renew_lease(token)
    assert_equal(19, deadline)

    @clock.now = 18
    assert_equal(object, @idconv.to_obj(token))

    @clock.now = 19
    assert_raise(DRb::DRbInvalidReferenceError) do
      @idconv.to_obj(DRb::DRbLease::SERVICE_REF).renew_lease(token)
    end
  end

  def test_invalid_and_expired_proxies_raise_recognizable_error
    object = Object.new
    token = @idconv.to_id(object)

    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(object.__id__) }

    @clock.now = 10
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(token) }
  end

  def test_object_id_reuse_cannot_revive_old_lease
    recycled = Object.new
    token = @idconv.to_id(recycled)
    recycled_id = recycled.__id__
    holder = @idconv.instance_variable_get(:@holder)
    registrations = holder.instance_variable_get(:@registrations)
    old_registration = registrations[recycled_id]
    recycled = nil
    GC.start

    replacement = Object.new
    old_registration.define_singleton_method(:alive?) { false }
    registration_class = holder.class::Registration
    clock = holder.instance_variable_get(:@now)
    registrations[recycled_id] = registration_class.new(replacement, recycled_id, clock)
    registrations[recycled_id].add_lease('new-lease', 20, replacement)

    @clock.now = 10
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(token) }
  ensure
    GC.start
  end

  def test_stale_lease_does_not_revive_after_registration_is_collected
    token = expired_token
    @clock.now = 10
    GC.start

    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(token) }
  end

  def test_active_call_keeps_object_alive_until_response_phase_finishes
    exported = export_object
    weak = exported[:weak]
    token = exported[:token]

    guard = @idconv.begin_call(token)
    @clock.now = 10
    GC.start
    assert_predicate(weak, :weakref_alive?)

    @idconv.end_call(guard)
    guard = nil
    cleanup
    GC.start
    refute_predicate(weak, :weakref_alive?)
  end

  def test_active_call_survives_lease_expiry_until_call_finishes
    object = Object.new
    token = @idconv.to_id(object)
    guard = @idconv.begin_call(token)

    @clock.now = 10
    GC.start
    assert_same(object, guard.last)

    @idconv.end_call(guard)
    cleanup
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(token) }
  end

  def test_keepalive_covers_result_phase
    result_weak = nil
    target = nil
    token = nil
    server = DRb::DRbServer.allocate
    server.instance_variable_set(:@idconv, @idconv)
    previous_drb = Thread.current['DRb']
    Thread.current['DRb'] = (previous_drb || {}).merge('server' => server)
    client = InvokeClient.new(nil, :call)
    target = ReturningObject.new(proc { @clock.now = 10; GC.start })
    token = @idconv.to_id(target)
    result_weak = WeakRef.new(target)
    client.instance_variable_set(:@raw_ref, token)

    invoke = DRb::DRbServer::InvokeMethod.new(server, client)
    succ, result = invoke.perform
    assert_equal(true, succ)
    assert_same(target, result)
    assert_predicate(result_weak, :weakref_alive?)
    keepalives = Thread.current['DRb']['invoke_keepalives']
    target = result = invoke = nil
    keepalives.each { |guard| server.end_invoke(guard) }
    keepalives.clear
    cleanup
    assert_recycled(result_weak)
  ensure
    Thread.current['DRb'] = previous_drb if defined?(previous_drb)
  end

  def test_renew_at_expiry_is_rejected_by_server_clock
    object = Object.new
    token = @idconv.to_id(object)
    service = @idconv.to_obj(DRb::DRbLease::SERVICE_REF)

    @clock.now = 10
    assert_raise(DRb::DRbInvalidReferenceError) { service.renew_lease(token) }
  end

  def test_lease_handle_renew_and_release
    object = LeasedObject.new
    service = @idconv.to_obj(DRb::DRbLease::SERVICE_REF)
    proxy = DRb::DRbObject.new_with('druby://example.invalid:1', @idconv.to_id(object))
    lease = proxy.__drb_lease
    lease.instance_variable_set(:@service, service)

    assert_kind_of(DRb::DRbLease, lease)
    assert_equal(10, lease.expires_at)

    @clock.now = 9
    lease.renew!
    assert_equal(19, lease.expires_at)

    @clock.now = 18
    assert_equal(object, @idconv.to_obj(proxy.__drbref))

    assert_equal(true, lease.release)
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(proxy.__drbref) }
  end

  private

  def assert_recycled(weak)
    GC.start
    refute_predicate(weak, :weakref_alive?)
  end

  def cleanup
    @idconv.instance_variable_get(:@holder).cleanup
  end

  def export_object
    object = LeasedObject.new
    token = @idconv.to_id(object)
    weak = WeakRef.new(object)
    object = nil
    {weak: weak, token: token}
  end

  def expired_token
    object = Object.new
    token = @idconv.to_id(object)
    object = nil
    @clock.now = 10
    token
  end
end
