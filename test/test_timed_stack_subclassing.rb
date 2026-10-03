# frozen_string_literal: true

require_relative "helper"

class TestTimedStackSubclassing < Minitest::Test
  def setup
    @klass = Class.new(ConnectionPool::TimedStack)
  end

  def test_try_fetch_connection
    obj = Object.new
    stack = @klass.new(size: 1) { obj }
    assert_equal false, stack.send(:try_fetch_connection)
    assert_equal obj, stack.pop
    stack.push obj
    assert_equal obj, stack.send(:try_fetch_connection)
  end

  def test_override_try_fetch_connection
    obj = Object.new

    stack = @klass.new(size: 1) { obj }
    stack.push stack.pop

    connection_stored_called = "cs_called"
    stack.define_singleton_method(:connection_stored?) { |*| raise connection_stored_called }
    e = assert_raises { stack.send(:try_fetch_connection) }
    assert_equal connection_stored_called, e.message

    stack.define_singleton_method(:try_fetch_connection) { fetch_connection }
    assert_equal obj, stack.send(:try_fetch_connection)
  end

  def test_override_try_create_keeps_legacy_construction
    # Subclasses overriding +try_create+ rely on it being the single creation
    # hook and being able to veto construction by returning nil.
    klass = Class.new(ConnectionPool::TimedStack) do
      attr_reader :create_calls

      def initialize(**opts, &block)
        @create_calls = 0
        super
      end

      private

      def try_create(**)
        return if @created == @max

        @create_calls += 1
        object = @create_block.call
        @created += 1
        object
      end
    end

    stack = klass.new(size: 1) { Object.new }
    conn = stack.pop
    refute_nil conn
    assert_equal 1, stack.create_calls
    assert_empty stack

    stack.push conn
    assert_same conn, stack.pop
    assert_equal 1, stack.create_calls

    assert_raises(ConnectionPool::TimeoutError) { stack.pop(timeout: 0) }
  end
end
