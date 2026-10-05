# frozen_string_literal: true

require_relative "helper"

require "puma/adaptive_admission"
require "puma/thread_pool"

class TestAdaptiveAdmission < PumaTest
  parallelize_me!

  # Deterministic monotonic clock: time only moves when the test says so.
  class FakeClock
    def initialize
      @now = 0.0
    end

    def call
      @now
    end

    def advance(seconds)
      @now += seconds
    end
  end

  def setup
    @clock = FakeClock.new
  end

  def new_admission(**opts)
    Puma::AdaptiveAdmission.new(
      **{ min: 1, max: 10, target_latency: 1.0, window: 5.0, clock: @clock }.merge(opts)
    )
  end

  # Records one completion with +service+ seconds of latency.
  def complete(admission, service, ok: true)
    token = admission.acquire
    @clock.advance(service)
    admission.release(token, ok: ok)
  end

  def wait_until(timeout: 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      raise "timed out waiting for condition" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
    end
  end

  def test_limit_decreases_stepwise_when_latency_exceeds_target
    admission = new_admission(initial: 10)

    trajectory = []
    7.times do
      2.times { complete(admission, 2.0) } # observed latency 2x target
      @clock.advance(5.0)                  # move past the window end
      complete(admission, 2.0)             # this completion closes the window
      trajectory << admission.limit
    end

    # raw = limit * 1.0 / 2.0, decrease capped at limit * 0.8 per window
    assert_equal [8, 6, 5, 4, 3, 2, 2], trajectory
  end

  def test_limit_increases_stepwise_and_clamps_to_max
    admission = new_admission(initial: 1, max: 4)

    trajectory = []
    4.times do
      complete(admission, 0.1)
      @clock.advance(5.0)
      complete(admission, 0.1)
      trajectory << admission.limit
    end

    # raw is huge, but growth is additive: +1 per window, clamped to max
    assert_equal [2, 3, 4, 4], trajectory
  end

  def test_hysteresis_holds_limit_on_small_deviation
    admission = new_admission(initial: 10, max: 20)

    complete(admission, 0.95) # raw = 10 / 0.95 = +5.3% < 10% hysteresis
    @clock.advance(5.0)
    complete(admission, 0.95)
    assert_equal 10, admission.limit

    complete(admission, 0.8) # candidate +10% reaches the hysteresis band
    @clock.advance(5.0)
    complete(admission, 0.8)
    assert_equal 11, admission.limit
  end

  def test_limit_never_goes_below_min
    admission = new_admission(initial: 2, min: 2)

    complete(admission, 100.0)
    @clock.advance(5.0)
    complete(admission, 100.0)

    assert_equal 2, admission.limit
  end

  def test_idle_windows_do_not_change_limit
    admission = new_admission(initial: 5)

    @clock.advance(60.0)       # server sits idle for many windows
    complete(admission, 0.0)   # first request after idle closes an empty window

    assert_equal 5, admission.limit
  end

  def test_window_with_too_few_samples_holds_limit
    admission = new_admission(initial: 5, min_samples: 3)

    2.times { complete(admission, 100.0) } # only 2 samples in the window
    @clock.advance(5.0)
    complete(admission, 100.0)             # closes the window

    assert_equal 5, admission.limit
  end

  def test_high_failure_ratio_forces_decrease
    admission = new_admission(initial: 4, min: 1)

    2.times { complete(admission, 0.1) }            # fast and healthy
    3.times { complete(admission, 0.1, ok: false) } # fast failures
    @clock.advance(5.0)
    complete(admission, 0.1)                        # closes the window

    assert_equal 3, admission.limit # floor(4 * 0.8), latency ignored
    assert_in_delta 0.6, admission.stats[:last_failure_ratio]
  end

  def test_failed_requests_are_excluded_from_latency_stats
    admission = new_admission(initial: 4, window: 1000.0, failure_threshold: 0.75)

    complete(admission, 0.5)                  # fast success
    complete(admission, 100.0, ok: false)     # slow failure must not poison the mean
    @clock.advance(1000.0)
    complete(admission, 0.5)                  # closes the window

    # observed = 0.5 (failures excluded) => raw = 8 => +1 step up.
    # Had the 100s failure been included, the limit would have decreased.
    assert_equal 5, admission.limit
    assert_in_delta 0.5, admission.stats[:last_observed_latency]
  end

  def test_measure_records_failures
    admission = new_admission(initial: 4)

    admission.measure { :ok }
    assert_raises(RuntimeError) { admission.measure { raise "boom" } }
    @clock.advance(5.0)
    admission.measure { :ok } # closes the window

    assert_in_delta 0.5, admission.stats[:last_failure_ratio]
    assert_equal 3, admission.limit
  end

  def test_decrease_waits_for_in_flight_to_finish_naturally
    admission = new_admission(initial: 3)

    # one very slow completion forces the limit from 3 down to 2
    complete(admission, 10.0)
    @clock.advance(5.0)
    complete(admission, 10.0)
    assert_equal 2, admission.limit

    gate = Queue.new    # blocking point: holds requests "inside the app"
    entered = Queue.new
    threads = 2.times.map do
      Thread.new do
        token = admission.acquire
        entered << true
        gate.pop
        admission.release(token)
      end
    end
    2.times { entered.pop } # both requests are now in-flight

    third = Thread.new do
      token = admission.acquire
      entered << :third
      admission.release(token)
    end

    # the third request must wait: decreasing the limit did not interrupt
    # the two in-flight requests
    wait_until { admission.stats[:waiting] == 1 }
    assert_equal 2, admission.stats[:in_flight]
    assert_raises(ThreadError) { entered.pop(true) }

    gate << true # let one in-flight request finish naturally
    assert_equal :third, entered.pop

    gate << true
    third.join
    threads.each(&:join)
    assert_equal 0, admission.stats[:in_flight]
  end

  def test_shutdown_fails_open
    admission = new_admission(initial: 1)
    token = admission.acquire
    admission.shutdown

    # gate is open after shutdown, no deadlock while draining
    token2 = admission.acquire
    admission.release(token)
    admission.release(token2)
    assert_equal 0, admission.stats[:in_flight]
  end

  def test_thread_pool_gates_concurrency_without_rebuilding
    admission = new_admission(initial: 2, max: 8)
    gate = Queue.new
    entered = 0
    entered_mutex = Mutex.new

    pool = Puma::ThreadPool.new("tst", { min_threads: 4, max_threads: 4 },
      admission: admission) do |_processor, _work|
      entered_mutex.synchronize { entered += 1 }
      gate.pop # blocking point: simulates work waiting on a slow downstream
    end

    4.times { pool << :req }

    # only 2 of 4 pool threads are admitted; the pool itself is untouched
    wait_until { entered_mutex.synchronize { entered } == 2 }
    assert_equal 2, admission.stats[:in_flight]
    assert_equal 2, admission.stats[:waiting]
    assert_equal 4, pool.spawned

    2.times { gate << true } # first two finish, the queued two are admitted
    wait_until { entered_mutex.synchronize { entered } == 4 }

    2.times { gate << true }
    wait_until { admission.stats[:in_flight] == 0 }
  ensure
    pool.shutdown(1) if pool
  end
end
