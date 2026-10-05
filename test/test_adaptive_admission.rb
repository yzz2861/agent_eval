# frozen_string_literal: true

require_relative "helper"
require "puma/adaptive_admission"
require "puma/thread_pool"

class TestAdaptiveAdmission < PumaTest
  parallelize_me!

  class Clock
    attr_reader :now

    def initialize(now = 0.0)
      @now = now.to_f
    end

    def advance(seconds)
      @now += seconds.to_f
    end

    def call
      @now
    end
  end

  Work = Struct.new(:id, :puma_queued_at)

  def admission(**options)
    @fake_clock = Clock.new(0)
    @clock = @fake_clock
    defaults = {
      min_samples: 4,
      cooldown: 0,
      target_queue_ratio: 0.1,
      hysteresis: 0.15,
      window: 60,
      on_change: ->(change) { (@changes ||= []) << change },
    }
    @admission = Puma::AdaptiveAdmission.new(
      defaults.merge(options),
      max_threads: options.fetch(:max_threads, 4),
      clock: @fake_clock
    )
  end

  def finish(request, failed: false, duration: 1)
    @clock.advance(duration)
    request.fail! if failed
    request.finish
  end

  def test_decreases_from_queue_wait_and_keeps_hysteresis
    controller = admission
    initial = Array.new(4) { controller.start }
    queued = Array.new(6) { |index| Work.new(index) }
    queued.each { |work| controller.stamp_enqueue(work, 0) }

    initial[3].finish
    started = [controller.start(queued[0])]
    @clock.advance(1)

    initial[2].finish
    started << controller.start(queued[1])
    @clock.advance(1)

    initial[1].finish
    started << controller.start(queued[2])
    @clock.advance(1)

    initial[0].finish
    started << controller.start(queued[3])

    finish(started.shift)
    started << controller.start(queued[4])
    finish(started.shift)
    started << controller.start(queued[5])
    finish(started.shift)

    assert_equal 3, controller.limit
    assert_equal [[4, 3]], @changes.map { |change| change.values_at(:from, :to) }
    assert_equal 3, controller.stats[:active]
  end

  def test_increases_when_saturated_without_queue_wait
    controller = admission(max_threads: 5)
    active = Array.new(5) { controller.start }

    5.times do |index|
      @clock.advance(1)
      active[index].finish
    end

    assert_equal 5, controller.limit
  end

  def test_idle_samples_are_recorded_but_do_not_increase_limit
    controller = admission(max_threads: 3, min_samples: 2)

    3.times do
      request = controller.start
      request.finish
      @clock.advance(1)
    end

    stats = controller.stats
    assert_equal 3, controller.limit
    assert_equal 3, stats[:samples]
    assert_equal 3, stats[:idle_samples]
  end

  def test_failures_reduce_limit_without_success_duration_samples
    controller = admission(max_threads: 2, min_samples: 2, failure_threshold: 0.5)
    requests = Array.new(2) { controller.start }

    finish(requests[0], failed: true)
    finish(requests[1], failed: true)

    assert_equal 1, controller.limit
    assert_equal 0.0, controller.stats[:queue_ratio]
  end

  def test_clamps_minimum_and_maximum
    controller = Puma::AdaptiveAdmission.new(
      { min_concurrency: 2, max_concurrency: 8 },
      max_threads: 3,
      clock: Clock.new
    )

    assert_equal 2, controller.min
    assert_equal 3, controller.max
    assert_equal 3, controller.limit
  end

  def test_pool_queues_new_work_after_limit_decreases
    @fake_clock = Clock.new(0)
    @clock = @fake_clock
    @changes = []
    entered = Queue.new
    gates = {}
    completed = Queue.new
    options = {
      min_threads: 0,
      max_threads: 4,
      adaptive_concurrency: {
        min_concurrency: 1,
        min_samples: 4,
        cooldown: 10,
        target_queue_ratio: 0.1,
        hysteresis: 0.15,
        window: 60,
        on_change: ->(change) { @changes << change },
      },
      admission_clock: @fake_clock,
    }

    @pool = Puma::ThreadPool.new("tst", options) do |_processor, work|
      request = @pool.admission.start(work)
      entered << work.id
      gates[work.id].pop
      @fake_clock.advance(1) if work.id < 10
      request.finish
      completed << work.id
    end

    10.times do |index|
      gates[index] = Queue.new
      @fake_clock.advance(0.05) if index >= 4
      @pool << Work.new(index)
    end
    wait_for { entered.size == 4 }

    [3, 2, 1, 0].each do |index|
      gates[index] << true
      completed.pop
    end
    wait_for { @changes.any? }

    assert_equal [4, 3], @changes.first.values_at(:from, :to)
    assert_equal 3, @pool.admission.stats[:active]

    gates[4] << true
    completed.pop
    wait_for { entered.size == 8 }
    gates[5] << true
    completed.pop
    wait_for { entered.size == 9 }
    gates[6] << true
    completed.pop
    wait_for { entered.size == 10 }

    gates[10] = Queue.new
    @pool << Work.new(10)
    assert_equal 10, entered.size

    gates[7] << true
    completed.pop
    wait_for { entered.size == 11 }
    gates[8] << true
    completed.pop
    gates[9] << true
    completed.pop
    gates[10] << true
    completed.pop
  ensure
    gates&.each_value { |gate| gate << true if gate.empty? }
  end

  private

  def wait_for
    Timeout.timeout(2) do
      loop do
        result = yield
        return result if result
        Thread.pass
      end
    end
  end
end
