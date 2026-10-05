require 'time'
require 'zlib'

module Flipper
  # Public: A declarative rollout schedule. The schedule is pure data: it is
  # configured once and never written to by a background job. At query time
  # #enabled? computes the effective percentage of actors from an injected
  # clock and buckets actors deterministically against it.
  #
  # Examples
  #
  #   schedule = Flipper::RolloutSchedule.build(
  #     windows: [{
  #       starts_at: '2026-10-05T10:00:00+08:00',
  #       ends_at:   '2026-10-05T18:00:00+08:00',
  #       from_percentage: 10,
  #       to_percentage: 50,
  #       mode: :linear
  #     }],
  #     after_end: :hold
  #   )
  #   schedule.enabled?(actor, feature_name: :search, now: clock.now)
  class RolloutSchedule
    # Internal: supports up to 3 decimal places in percentages, matching the
    # percentage_of_actors gate.
    SCALING_FACTOR = 1_000
    private_constant :SCALING_FACTOR

    # Internal: percentage is compared against crc32(id) mod this many slots.
    BUCKET_COUNT = 100 * SCALING_FACTOR
    private_constant :BUCKET_COUNT

    MODES = [:linear, :step].freeze

    # Public: What the schedule does after its final window ends.
    # :hold keeps the final window's to_percentage (default).
    # :off disables the feature when no window applies.
    AFTER_END_BEHAVIORS = [:hold, :off].freeze

    # Public: Build a schedule from a plain Hash (e.g. JSON config).
    #
    # config - The Hash of options, see #initialize.
    #
    # Returns a RolloutSchedule.
    # Raises ArgumentError if the config is invalid.
    def self.build(config = nil, &block)
      builder = Builder.new
      builder.instance_eval(&block) if block_given?
      config = normalize_config(builder.to_h.merge(config || {}))
      new(**config)
    end

    # Internal: Accept friendly keys (from/to) and string keys from JSON.
    def self.normalize_config(config)
      config = symbolize(config)
      windows = Array(config[:windows]).map { |window| normalize_window(window) }
      result = { windows: windows }
      result[:after_end] = config[:after_end] if config.key?(:after_end)
      result
    end

    def self.normalize_window(window)
      window = symbolize(window)
      window[:from_percentage] = window.delete(:from) if window.key?(:from)
      window[:to_percentage] = window.delete(:to) if window.key?(:to)
      window
    end

    def self.symbolize(value)
      case value
      when Hash
        value.each_with_object({}) { |(key, val), out| out[key.to_sym] = symbolize(val) }
      when Array
        value.map { |item| symbolize(item) }
      else
        value
      end
    end

    # Public: Define a schedule with a small DSL.
    #
    #   Flipper::RolloutSchedule.define do |s|
    #     s.window '2026-10-05T10:00:00+08:00',
    #              '2026-10-05T18:00:00+08:00',
    #              from: 10, to: 50, mode: :linear
    #     s.after_end :hold
    #   end
    def self.define(&block)
      build(&block)
    end

    # Public: Initialize a schedule.
    #
    # windows - Array of window Hashes:
    #           :starts_at - Time or String time with an explicit offset.
    #           :ends_at   - Time or String time with an explicit offset.
    #           :from_percentage - Numeric 0..100 in effect at/after starts_at.
    #           :to_percentage   - Numeric 0..100 in effect at/after ends_at.
    #           :mode - :linear (default) or :step.
    #           :step_percentage - Required for :step; positive Numeric.
    # after_end - :hold (default) or :off, behavior past the final window.
    def initialize(windows:, after_end: :hold)
      normalized = self.class.normalize_config(windows: windows, after_end: after_end)
      @windows = normalized[:windows].map { |window| Window.new(**window) }.sort_by(&:starts_at)
      @after_end = validate_after_end(after_end)
      validate_windows!
      @windows.freeze
    end

    # Public: Returns the frozen Array of normalized windows.
    attr_reader :windows

    # Public: Returns the :hold/:off behavior past the last window.
    attr_reader :after_end

    # Public: Effective rollout percentage at a given time.
    #
    # now - The Time to evaluate at (the injected clock). Defaults to Time.now.
    #
    # Returns an Integer 0..100.
    def percentage(now = Time.now)
      window = window_for(now)

      if window
        window.percentage(now)
      elsif !@windows.empty? && now >= @windows.first.starts_at
        # Between windows the most recent window's ending percentage holds;
        # after the final window after_end decides.
        ended_window = @windows.reverse.detect { |candidate| now >= candidate.ends_at }
        return 0 unless ended_window

        if ended_window.equal?(@windows.last) && @after_end == :off
          0
        else
          ended_window.to_percentage
        end
      else
        0
      end
    end

    # Public: Whether the schedule has started at the given time.
    def started?(now = Time.now)
      !@windows.empty? && now >= @windows.first.starts_at
    end

    # Public: Whether the final window has ended at the given time.
    def ended?(now = Time.now)
      !@windows.empty? && now >= @windows.last.ends_at
    end

    # Public: Check whether the feature is enabled for an actor at a time.
    #
    # actor        - Object responding to flipper_id, or a String flipper_id.
    # feature_name - The String/Symbol feature name (salts the bucket hash).
    # now          - The Time to evaluate at (injected clock).
    #
    # Returns true or false.
    def enabled?(actor, feature_name:, now: Time.now)
      percentage = percentage(now)
      return false if percentage <= 0
      return true if percentage >= 100

      bucket_for(actor, feature_name) < percentage * SCALING_FACTOR
    end

    # Public: Stable 0..99_999 bucket for an actor/feature pair.
    def bucket_for(actor, feature_name)
      id = "#{feature_name}#{actor_id(actor)}"
      Zlib.crc32(id) % BUCKET_COUNT
    end

    # Internal: Find the window containing a time (boundaries inclusive).
    def window_for(now)
      @windows.detect { |window| window.covers?(now) }
    end

    # Public: Serialize to a JSON-friendly Hash.
    def to_h
      {
        'windows' => @windows.map(&:to_h),
        'after_end' => @after_end.to_s,
      }
    end

    def eql?(other)
      other.is_a?(self.class) && to_h == other.to_h
    end
    alias_method :==, :eql?

    def inspect
      "#<#{self.class.name} windows=#{@windows.inspect} after_end=#{@after_end.inspect}>"
    end

    private

    def actor_id(actor)
      if actor.respond_to?(:flipper_id)
        actor.flipper_id
      elsif actor.respond_to?(:value)
        actor.value
      else
        actor.to_s
      end
    end

    def validate_after_end(value)
      value = value.to_sym
      unless AFTER_END_BEHAVIORS.include?(value)
        raise ArgumentError,
              "after_end must be one of #{AFTER_END_BEHAVIORS.inspect}, but was #{value.inspect}"
      end
      value
    end

    def validate_windows!
      if @windows.empty?
        raise ArgumentError, 'rollout schedule requires at least one window'
      end

      @windows.each_cons(2) do |previous, window|
        if window.starts_at < previous.ends_at
          raise ArgumentError,
                "rollout windows overlap: #{previous.range} overlaps #{window.range}"
        end
      end
    end

    # Internal: Small DSL used by RolloutSchedule.define/build.
    class Builder
      def initialize
        @windows = []
        @after_end = nil
      end

      def window(starts_at, ends_at, **options)
        @windows << options.merge(starts_at: starts_at, ends_at: ends_at)
      end

      def after_end(value)
        @after_end = value
      end

      def to_h
        { windows: @windows, after_end: @after_end || :hold }
      end
    end

    # Internal: A single configured rollout window.
    class Window
      attr_reader :starts_at, :ends_at, :from_percentage, :to_percentage,
                  :mode, :step_percentage

      def initialize(starts_at:, ends_at:, from_percentage:, to_percentage:,
                     mode: :linear, step_percentage: nil)
        @starts_at = parse_time(starts_at, :starts_at)
        @ends_at = parse_time(ends_at, :ends_at)
        @from_percentage = validate_percentage(from_percentage, :from_percentage)
        @to_percentage = validate_percentage(to_percentage, :to_percentage)
        @mode = validate_mode(mode)
        @step_percentage = validate_step_percentage(step_percentage)
        validate_range!
      end

      # Internal: Effective Integer percentage at the given time.
      def percentage(now)
        return from_percentage if now <= starts_at
        return to_percentage if now >= ends_at

        case mode
        when :step
          elapsed_steps = ((now - starts_at) / duration *
                           total_steps).floor
          [from_percentage + elapsed_steps * step_percentage, to_percentage].min
        when :linear
          progress = (now - starts_at) / duration.to_f
          scaled = (from_percentage +
                    (to_percentage - from_percentage) * progress) * SCALING_FACTOR
          scaled.floor / SCALING_FACTOR
        end
      end

      def covers?(now)
        now >= starts_at && now <= ends_at
      end

      def range
        "[#{starts_at.iso8601}, #{ends_at.iso8601}]"
      end

      def to_h
        hash = {
          'starts_at' => starts_at.iso8601,
          'ends_at' => ends_at.iso8601,
          'from_percentage' => from_percentage,
          'to_percentage' => to_percentage,
          'mode' => mode.to_s,
        }
        hash['step_percentage'] = step_percentage if step_percentage
        hash
      end

      def inspect
        "#<Window #{range} #{from_percentage}->#{to_percentage} #{mode}>"
      end

      private

      def duration
        ends_at - starts_at
      end

      def total_steps
        (to_percentage - from_percentage).to_r / step_percentage
      end

      def parse_time(value, label)
        case value
        when Time
          value
        when String
          begin
            time = Time.iso8601(value)
          rescue ArgumentError
            raise ArgumentError, "#{label} is not a valid ISO 8601 time: #{value.inspect}"
          end

          unless offset_given?(value)
            raise ArgumentError, "#{label} must include an explicit offset, but was #{value.inspect}"
          end
          time
        else
          raise ArgumentError,
                "#{label} must be a Time or ISO 8601 String, but was #{value.class}"
        end
      end

      # Internal: ISO 8601 accepts '2026-10-05T10:00:00' without an offset,
      # which silently adopts the system zone. Require Z or ±HH:MM.
      def offset_given?(string)
        string =~ /(?:z|Z|[+-]\d{2}:?\d{2})\z/
      end

      def validate_percentage(value, label)
        percentage = begin
          Integer(value)
        rescue ArgumentError, TypeError
          raise ArgumentError, "#{label} must be an Integer between 0 and 100, but was #{value.inspect}"
        end

        unless percentage >= 0 && percentage <= 100
          raise ArgumentError,
                "#{label} must be between 0 and 100, but was #{value.inspect}"
        end
        percentage
      end

      def validate_mode(value)
        mode = value.to_sym
        unless MODES.include?(mode)
          raise ArgumentError, "mode must be one of #{MODES.inspect}, but was #{value.inspect}"
        end
        mode
      end

      def validate_step_percentage(value)
        return nil unless mode == :step

        if value.nil?
          raise ArgumentError, 'step mode requires step_percentage'
        end

        unless Numeric === value && value > 0
          raise ArgumentError,
                "step_percentage must be a positive number, but was #{value.inspect}"
        end
        value
      end

      def validate_range!
        if ends_at <= starts_at
          raise ArgumentError,
                "ends_at (#{ends_at.iso8601}) must be after starts_at (#{starts_at.iso8601})"
        end

        if mode == :step &&
           !((to_percentage - from_percentage).to_r % step_percentage.to_r).zero?
          raise ArgumentError,
                "step window #{range} is not divisible into #{step_percentage}% steps"
        end
      end
    end
  end
end
