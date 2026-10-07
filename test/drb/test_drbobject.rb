require_relative '../lib/helper'
require 'envutil'
require 'drb'
require 'drb/timeridconv'
require 'drb/weakidconv'

module DRbObjectTest
  class Foo
    def initialize
      @foo = 'foo'
    end
  end

  def teardown
    DRb.stop_service
    DRb::DRbConn.stop_pool
  end

  def drb_eq(obj)
    proxy = DRbObject.new(obj)
    assert_equal(obj, DRb.to_obj(proxy.__drbref))
  end

  def test_DRbObject_id_dereference
    drb_eq(Foo.new)
    drb_eq(Foo)
    drb_eq(File)
    drb_eq(Enumerable)
    drb_eq(nil)
    drb_eq(1)
    drb_eq($stdout)
    drb_eq([])
  end
end

class TestDRbObject < Test::Unit::TestCase
  include DRbObjectTest

  def setup
    DRb.start_service
  end
end

class TestDRbObjectTimerIdConv < Test::Unit::TestCase
  include DRbObjectTest

  def setup
    @idconv = DRb::TimerIdConv.new
    DRb.start_service(nil, nil, {:idconv => @idconv})
  end

  def teardown
    super
    GC.start
  end
end

class TestDRbObjectWeakIdConv < Test::Unit::TestCase
  include DRbObjectTest

  def setup
    idconv = EnvUtil.suppress_warning {DRb::WeakIdConv.new}
    DRb.start_service(nil, nil, {:idconv => idconv})
  end
end
