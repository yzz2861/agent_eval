# frozen_string_literal: false
require 'test/unit'
require 'drb/timeridconv'
require 'weakref'

module DRbTests

class TimerIdConvTest < Test::Unit::TestCase
  class Clock
    attr_accessor :now

    def initialize
      @now = 0
    end
  end

  def setup
    @clock = Clock.new
    @idconv = DRb::TimerIdConv.new(10, @clock)
  end

  def test_lease_is_explicit_and_expires_on_server_clock
    object = Object.new
    token = @idconv.to_id(object)

    assert_equal(DRb::DRbLease::TOKEN_MARKER, token.first)
    assert_equal(object.__id__, token[1])
    assert_equal(10, token[3])
    assert_equal(object, @idconv.to_obj(token))

    @clock.now = 10
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(token) }
  end

  def test_expired_lease_does_not_keep_object
    object = Object.new
    token = @idconv.to_id(object)
    weak = WeakRef.new(object)
    object = nil

    GC.start
    assert_predicate(weak, :weakref_alive?)

    @clock.now = 10
    @idconv.instance_variable_get(:@holder).cleanup
    GC.start
    refute_predicate(weak, :weakref_alive?)
    assert_raise(DRb::DRbInvalidReferenceError) { @idconv.to_obj(token) }
  end
end

end
