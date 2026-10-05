# frozen_string_literal: true

module Puma
  # Adjusts how many requests may enter application code without changing the
  # fixed thread pool size. A sliding window compares mean queue wait with mean
  # completion time. Little's law gives an interpretable target:
  #   target = mean_active * (1 + target_queue_ratio) / (1 + queue_ratio)
  # Sustained queueing above the upper hysteresis bound multiplies the limit by
  # decrease_factor; a saturated window below the lower bound adds increase_step.
  # Existing requests keep their admission slots, so decreases only gate new
  # work. Application exceptions and 500 responses are failures; intentional
  # 503 responses are not counted as downstream failures.
  class AdaptiveAdmission
    DEFAULTS = {
      min_concurrency: 1,
      max_concurrency: nil,
      window: 30.0,
      target_queue_ratio: 0.1,
      hysteresis: 0.15,
      min_samples: 20,
      cooldown: 1.0,
      failure_threshold: 0.25,
      decrease_factor: 0.75,
      increase_step: 1,
    }.freeze

    attr_reader :limit, :min, :max, :waiting

    def self.from_options(options, max_threads, clock: nil)
      config = options[:adaptive_concurrency]
      return nil unless config
      return nil if config.is_a?(Hash) && config[:enabled] == false

      config = {} if config == true
      new(config, max_threads: max_threads, clock: clock)
    end

    def initialize(config = {}, max_threads:, clock: nil)
      @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

      @max_threads = Integer(max_threads)
      @configured_max = config[:max_concurrency] || config[:max]
      configured_max = Integer(@configured_max || @max_threads)
      @max = [configured_max, @max_threads].min
      @min = Integer(config[:min_concurrency] || config[:min] || DEFAULTS[:min_concurrency]).clamp(1, @max)

      @window = Float(config[:window] || DEFAULTS[:window])
      @target_queue_ratio = Float(config[:target_queue_ratio] || DEFAULTS[:target_queue_ratio])
      @hysteresis = Float(config[:hysteresis] || DEFAULTS[:hysteresis])
      @min_samples = Integer(config[:min_samples] || DEFAULTS[:min_samples])
      @cooldown = Float(config[:cooldown] || DEFAULTS[:cooldown])
      @failure_threshold = Float(config[:failure_threshold] || DEFAULTS[:failure_threshold])
      @decrease_factor = Float(config[:decrease_factor] || DEFAULTS[:decrease_factor])
      @increase_step = Integer(config[:increase_step] || DEFAULTS[:increase_step])
      @on_change = config[:on_change]

      raise ArgumentError, "window must be positive" unless @window > 0
      raise ArgumentError, "target_queue_ratio must be positive" unless @target_queue_ratio > 0
      raise ArgumentError, "hysteresis must be between 0 and 1" unless (0...1).cover?(@hysteresis)
      raise ArgumentError, "min_samples must be positive" unless @min_samples > 0
      raise ArgumentError, "cooldown must not be negative" if @cooldown < 0
      raise ArgumentError, "failure_threshold must be between 0 and 1" unless (0..1).cover?(@failure_threshold)
      raise ArgumentError, "decrease_factor must be between 0 and 1" unless @decrease_factor > 0 && @decrease_factor < 1
      raise ArgumentError, "increase_step must be positive" unless @increase_step > 0

      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @samples = []
      @active = 0
      @waiting = 0
      @shutdown = false
      @limit = @max
      @last_adjusted_at = -Float::INFINITY
    end

    def update_max_threads(max_threads)
      @mutex.synchronize do
        @max_threads = Integer(max_threads)
        configured_max = Integer(@configured_max || @max_threads)
        @max = [configured_max, @max_threads].min
        @min = [@min, @max].min
        @limit = [@limit, @max].min
      end
    end

    def start(work = nil, queued: work.respond_to?(:puma_queued_at))
      queued_at = queued ? work&.puma_queued_at : nil

      @mutex.synchronize do
        @waiting += 1
        begin
          while @active >= @limit && !@shutdown
            @condition.wait(@mutex)
          end
          raise ThreadPool::ForceShutdown if @shutdown

          started_at = now
          waited = queued_at && started_at >= queued_at ? started_at - queued_at : 0.0
          @active += 1
          Request.new(self, started_at, waited, @active, @limit)
        ensure
          @waiting -= 1
        end
      end
    end

    def stamp_enqueue(work, timestamp = now)
      work.puma_queued_at = timestamp if work.respond_to?(:puma_queued_at=)
    end

    def stats
      @mutex.synchronize do
        prune!
        summary = window_summary
        {
          limit: @limit,
          min: @min,
          max: @max,
          active: @active,
          waiting: @waiting,
          samples: @samples.size,
          idle_samples: summary[:idle],
          failure_ratio: summary[:failure_ratio],
          queue_ratio: summary[:queue_ratio],
        }
      end
    end

    def shutdown
      @mutex.synchronize do
        @shutdown = true
        @condition.broadcast
      end
    end

    def finish(request, failed:)
      finished_at = now
      change = nil

      @mutex.synchronize do
        @active = [@active - 1, 0].max
        @condition.broadcast
        @samples << {
          at: finished_at,
          waited: request.waited,
          duration: [finished_at - request.started_at, 0.0].max,
          active: request.active,
          failed: failed,
          idle: request.idle?(failed: failed),
        }
        change = adjust!(finished_at)
      end

      @on_change&.call(change) if change
      change
    end

    def ignore(request)
      @mutex.synchronize do
        @active = [@active - 1, 0].max
        @condition.broadcast
      end
    end

    private

    def now
      @clock.call.to_f
    end

    def prune!(timestamp = now)
      cutoff = timestamp - @window
      @samples.shift while @samples.first && @samples.first[:at] < cutoff
    end

    def window_summary
      considered = @samples.reject { |sample| sample[:idle] }
      failures = considered.count { |sample| sample[:failed] }
      successes = considered.reject { |sample| sample[:failed] }
      total_wait = successes.sum { |sample| sample[:waited] }
      total_duration = successes.sum { |sample| sample[:duration] }

      {
        considered: considered,
        successes: successes,
        idle: @samples.count { |sample| sample[:idle] },
        failures: failures,
        failure_ratio: considered.empty? ? 0.0 : failures.to_f / considered.size,
        queue_ratio: total_duration.zero? ? 0.0 : total_wait / total_duration,
      }
    end

    def adjust!(timestamp)
      return nil if timestamp - @last_adjusted_at < @cooldown

      prune!(timestamp)
      summary = window_summary
      return nil if summary[:considered].size < @min_samples

      old_limit = @limit
      new_limit = old_limit

      if summary[:failure_ratio] >= @failure_threshold
        new_limit = (old_limit * @decrease_factor).floor
      elsif summary[:successes].size >= @min_samples
        ratio = summary[:queue_ratio]
        average_active = summary[:successes].sum { |sample| sample[:active] }.to_f / summary[:successes].size
        target = (average_active * (1.0 + @target_queue_ratio) / (1.0 + ratio)).floor

        if ratio >= @target_queue_ratio * (1.0 + @hysteresis) &&
           target <= old_limit * (1.0 - @hysteresis)
          new_limit = [target, (old_limit * @decrease_factor).floor].max
        elsif ratio <= @target_queue_ratio * (1.0 - @hysteresis) &&
              average_active >= old_limit
          new_limit = old_limit + @increase_step
        end
      end

      new_limit = new_limit.clamp(@min, @max)
      return nil if new_limit == old_limit

      @limit = new_limit
      @last_adjusted_at = timestamp
      @condition.broadcast
      { from: old_limit, to: new_limit, at: timestamp }
    end

    class Request
      attr_reader :started_at, :waited, :active

      def initialize(admission, started_at, waited, active, limit)
        @admission = admission
        @started_at = started_at
        @waited = waited
        @active = active
        @limit = limit
        @failed = false
        @ignored = false
        @finished = false
      end

      def fail!
        @failed = true
      end

      def ignore!
        @ignored = true
      end

      def idle?(failed:)
        !failed && !@ignored && @waited.zero? && @active < @limit
      end

      def finish
        return if @finished

        @finished = true
        @admission.finish(self, failed: @failed)
      end

      def ignore
        return if @finished

        @finished = true
        @admission.ignore(self)
      end
    end
  end
end
