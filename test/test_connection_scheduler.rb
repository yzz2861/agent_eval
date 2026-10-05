# frozen_string_literal: true

require_relative "helper"
require "puma/connection_scheduler"

class TestConnectionScheduler < PumaTest
  class Pool
    attr_reader :pushed

    def initialize(capacity)
      @capacity = capacity
      @active = 0
      @mutex = Mutex.new
      @pushed = []
    end

    def activate
      @mutex.synchronize { @active += 1 }
    end

    def ready_push(work, releasing: false)
      @mutex.synchronize do
        active = releasing ? @active - 1 : @active
        return false unless active < @capacity

        @pushed << work
        true
      end
    end
  end

  class Client
    attr_accessor :fair_scheduling_remaining
  end

  def test_dispatches_immediately_when_a_worker_is_available
    pool = Pool.new(1)
    scheduler = Puma::ConnectionScheduler.new(pool, 2)
    client = Client.new

    assert scheduler.add(client)

    assert_equal [client], pool.pushed
    assert_equal 2, client.fair_scheduling_remaining
    assert_equal 0, scheduler.size
  end

  def test_sets_the_request_quota_for_a_round
    pool = Pool.new(1)
    scheduler = Puma::ConnectionScheduler.new(pool, 3)
    client = Client.new

    scheduler.add(client)

    assert_equal 3, client.fair_scheduling_remaining
    client.fair_scheduling_remaining -= 1
    assert_equal 2, client.fair_scheduling_remaining
  end

  def test_releases_waiting_connections_in_fifo_order
    pool = Pool.new(1)
    scheduler = Puma::ConnectionScheduler.new(pool, 1)
    first = Client.new
    second = Client.new
    pool.activate

    assert scheduler.add(first)
    assert scheduler.add(second)
    assert_equal 0, pool.pushed.size
    assert_equal 2, scheduler.size

    scheduler.release(first)

    assert_equal [first], pool.pushed
    assert_equal 1, scheduler.size
  end

  def test_re_ready_connection_does_not_move_ahead_of_waiting_connections
    pool = Pool.new(1)
    scheduler = Puma::ConnectionScheduler.new(pool, 1)
    busy = Client.new
    sparse = Client.new
    pool.activate

    scheduler.add(sparse)
    scheduler.add(busy)
    scheduler.release(busy)

    assert_equal [sparse], pool.pushed
    assert_equal [busy], scheduler.instance_variable_get(:@waiting)
  end

  def test_draining_does_not_dispatch_waiting_connections
    pool = Pool.new(1)
    scheduler = Puma::ConnectionScheduler.new(pool, 1)
    client = Client.new
    pool.activate

    scheduler.add(client)
    scheduler.drain
    scheduler.release

    assert_empty pool.pushed
    assert_equal 0, scheduler.size
  end
end
