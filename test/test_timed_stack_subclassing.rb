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

  def test_override_try_create_keeps_historical_mutex_behavior
    klass = Class.new(ConnectionPool::TimedStack) do
      attr_reader :created_with_mutex

      def try_create(**options)
        @created_with_mutex = @mutex.owned?
        @created += 1
        options
      end
    end

    stack = klass.new(size: 1) { raise "legacy constructor should not be called" }

    assert_equal({tag: :connection}, stack.pop(tag: :connection))
    assert stack.created_with_mutex
  end

  def test_override_create_connection_runs_without_mutex
    klass = Class.new(ConnectionPool::TimedStack) do
      attr_reader :created_with_mutex

      def create_connection(**options)
        @created_with_mutex = @mutex.owned?
        options
      end
    end

    stack = klass.new(size: 1) { nil }

    assert_equal({tag: :connection}, stack.pop(tag: :connection))
    refute stack.created_with_mutex
  end
end
