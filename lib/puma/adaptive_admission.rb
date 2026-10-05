# frozen_string_literal: true

require 'thread'

module Puma
  # AdaptiveAdmission is an optional, windowed admission controller that sits
  # in front of the application and limits how many requests may execute
  # concurrently. The thread pool keeps its fixed size; pool threads simply
  # wait at the admission gate when the current limit is reached, so the pool
  # is never rebuilt while the limit moves.
  #
  # == Adjustment formula
  #
  # Completed requests are grouped into windows of +window+ seconds (by the
  # monotonic +clock+). When a window closes, the controller computes:
  #
  #   observed  = mean(queue_wait + service_time) of *successful* completions
  #   raw       = limit * target_latency / observed
  #
  # and then rate-limits the move:
  #
  #   increase  = min(raw, limit + step_up)     (additive, slow growth)
  #   decrease  = max(raw, limit * step_down)   (multiplicative, quick cut)
  #
  # The candidate is only applied when the relative change is at least
  # +hysteresis+ (e.g. 0.1 = 10%), which damps oscillation, and the result is
  # always clamped to [min, max].
  #
  # == Explicit edge-case handling
  #
  # * Idle: a window with fewer than +min_samples+ completions (including a
  #   completely empty window) is discarded and never changes the limit.
  # * Failures: failed requests are excluded from the latency mean. If the
  #   failure ratio of a window reaches +failure_threshold+, the limit is cut
  #   to +max(min, floor(limit * step_down))+ regardless of latency, because
  #   errors under load are themselves an overload signal.
  # * Decreasing: the limit is only a counter. In-flight requests always run
  #   to natural completion; new admissions wait until in-flight drops below
  #   the new limit. Nothing is killed and no pool thread is recreated.
  # * Clock: all timing uses an injectable monotonic clock (defaults to
  #   +Process.clock_gettime(Process::CLOCK_MONOTONIC)+), so wall-clock jumps
  #   do not corrupt the statistics and tests can drive time deterministically.
  class AdaptiveAdmission
    DEFAULT_WINDOW = 5.0
    DEFAULT_STEP_UP = 1
    DEFAULT_STEP_DOWN = 0.8
    DEFAULT_HYSTERESIS = 0.1
    DEFAULT_MIN_SAMPLES = 1
    DEFAULT_FAILURE_THRESHOLD = 0.5

    # Opaque handle returned by #acquire and passed back to #release.
    Token = Struct.new(:enqueued_at, :started_at)

    attr_reader :min, :max, :target_latency, :window

    def initialize(min: 1, max:, target_latency:, initial: nil,
                   window: DEFAULT_WINDOW,
                   step_up: DEFAULT_STEP_UP, step_down: DEFAULT_STEP_DOWN,
                   hysteresis: DEFAULT_HYSTERESIS,
                   min_samples: DEFAULT_MIN_SAMPLES,
                   failure_threshold: DEFAULT_FAILURE_THRESHOLD,
                   clock: nil)
      min = Integer(min)
      max = Integer(max)
      target_latency = Float(target_latency)
      window = Float(window)
      raise ArgumentError, "min must be >= 1" if min < 1
      raise ArgumentError, "max must be >= min" if max < min
      raise ArgumentError, "target_latency must be > 0" if target_latency <= 0
      raise ArgumentError, "window must be > 0" if window <= 0
      raise ArgumentError, "step_down must be in (0, 1)" unless step_down > 0 && step_down < 1
      raise ArgumentError, "step_up must be >= 1" if step_up < 1
      raise ArgumentError, "hysteresis must be >= 0" if hysteresis < 0
      raise ArgumentError, "min_samples must be >= 1" if min_samples < 1
      raise ArgumentError, "failure_threshold must be in (0, 1]" unless failure_threshold > 0 && failure_threshold <= 1

      @min = min
      @max = max
      @target_latency = target_latency
      @window = window
      @step_up = Integer(step_up)
      @step_down = Float(step_down)
      @hysteresis = Float(hysteresis)
      @min_samples = Integer(min_samples)
      @failure_threshold = Float(failure_threshold)
      @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

      @limit = (initial ? Integer(initial) : max).clamp(min, max)

      @mutex = Mutex.new
      @available = ConditionVariable.new
      @in_flight = 0
      @waiting = 0
      @shutdown = false

      @window_start = now
      @window_samples = []
      @last_observed_latency = nil
      @last_failure_ratio = nil
    end

    # The current admission limit.
    def limit
      @mutex.synchronize { @limit }
    end

    # Current time on the controller's clock. The thread pool uses this to
    # stamp work items when they are enqueued, so queue wait and service time
    # share one clock source.
    def now
      @clock.call
    end

    # Blocks until a slot is available, then marks one request in-flight and
    # returns a token for #release. +enqueued_at+ is the time (on this
    # controller's clock) the request was queued, used to measure queue wait.
    #
    # After #shutdown the gate fails open: callers are admitted immediately so
    # a draining pool can never deadlock on the gate.
    def acquire(enqueued_at: nil)
      @mutex.synchronize do
        @waiting += 1
        begin
          @available.wait(@mutex) while !@shutdown && @in_flight >= @limit
        ensure
          @waiting -= 1
        end
        @in_flight += 1
        Token.new(enqueued_at, now)
      end
    end

    # Marks a previously acquired token as complete. +ok+ should be false when
    # the request failed; failed requests are excluded from the latency mean
    # but counted toward the window's failure ratio.
    def release(token, ok: true)
      timestamp = now
      @mutex.synchronize do
        @in_flight -= 1 if @in_flight > 0
        maybe_close_window(timestamp)
        started = token.enqueued_at || token.started_at
        @window_samples << [timestamp - started, ok]
        @available.broadcast
      end
      nil
    end

    # Convenience wrapper: acquires, yields, and releases, recording the
    # sample as failed if the block raises. Returns the block's value.
    def measure(enqueued_at: nil)
      token = acquire(enqueued_at: enqueued_at)
      begin
        result = yield
        release(token, ok: true)
        result
      rescue Exception
        release(token, ok: false)
        raise
      end
    end

    # Disables the gate and wakes all waiters. In-flight requests are
    # unaffected and further adjustments stop.
    def shutdown
      @mutex.synchronize do
        @shutdown = true
        @available.broadcast
      end
      nil
    end

    # @return [Hash] stat info for reporting purposes.
    def stats
      @mutex.synchronize do
        {
          limit: @limit,
          min: @min,
          max: @max,
          in_flight: @in_flight,
          waiting: @waiting,
          samples_in_window: @window_samples.size,
          last_observed_latency: @last_observed_latency,
          last_failure_ratio: @last_failure_ratio,
        }
      end
    end

    private

    # Must be called with @mutex held. Closes the current window if +timestamp+
    # is past its end and adjusts the limit from the collected samples. Empty
    # (idle) windows are discarded without adjusting.
    def maybe_close_window(timestamp)
      return if @shutdown
      return if timestamp - @window_start < @window

      samples = @window_samples
      @window_samples = []
      @window_start = timestamp

      adjust_limit(samples)
    end

    # Must be called with @mutex held.
    def adjust_limit(samples)
      total = samples.size
      if total < @min_samples
        # Idle or insufficient signal: hold the limit steady.
        @last_observed_latency = nil
        @last_failure_ratio = nil
        return
      end

      failed = samples.count { |(_, ok)| !ok }
      @last_failure_ratio = failed.to_f / total

      if @last_failure_ratio >= @failure_threshold
        @last_observed_latency = nil
        @limit = [@min, (@limit * @step_down).floor].max
        @available.broadcast
        return
      end

      successful = samples.select { |(_, ok)| ok }
      observed = successful.sum { |(latency, _)| latency } / successful.size
      @last_observed_latency = observed

      raw = @limit * @target_latency / observed
      candidate =
        if raw > @limit
          [@limit + @step_up, raw].min
        else
          [@limit * @step_down, raw].max
        end

      # Hysteresis: ignore moves smaller than the configured relative band.
      return if (candidate - @limit).abs / @limit.to_f < @hysteresis

      @limit = candidate.round.clamp(@min, @max)
      @available.broadcast
    end
  end
end
