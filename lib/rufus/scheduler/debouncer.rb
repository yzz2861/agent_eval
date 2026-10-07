
class Rufus::Scheduler::Debouncer

  Event = Struct.new(:at, :payload)
  Batch = Struct.new(:key, :first_event, :last_event, :payload)

  Round = Struct.new(
    :key,
    :first_event,
    :last_event,
    :payload,
    :job,
    :thread
  )

  class TimerJob < Rufus::Scheduler::InJob

    attr_reader :debouncer, :debouncer_key
    attr_accessor :round

    def initialize(scheduler, debouncer, key, delay)

      @debouncer = debouncer
      @debouncer_key = key

      handler =
        proc do |job|

          job.debouncer.execute(job.round)
        end

      super(scheduler, delay, { :_t => delay }, handler)

      @next_time = @debouncer.now + delay
    end

    def trigger(time)

      return if unscheduled_at

      @round =
        @debouncer.claim_timer(@debouncer_key, self, time)

      if @round
        super
      elsif @round == false
        # A newer event moved this same job back into the future.
      else
        unschedule unless unscheduled_at
      end
    end
  end

  class Clock

    def now

      Rufus::Scheduler::EoTime.now
    end
  end

  attr_reader :quiet, :max_wait

  def initialize(scheduler, opts={}, &block)

    @scheduler = scheduler

    @quiet =
      Rufus::Scheduler.parse_in(opts[:quiet] || opts[:quiet_period])
    @max_wait =
      Rufus::Scheduler.parse_in(opts.fetch(:max_wait))

    @merge = opts[:merge]
    @handler = opts[:handler] || block
    @clock = opts[:clock] || Clock.new

    fail ArgumentError.new('missing merge callable') \
      unless @merge.respond_to?(:call)
    fail ArgumentError.new('missing handler block or callable') \
      unless @handler.respond_to?(:call)
    fail ArgumentError.new('quiet must be > 0') \
      unless @quiet.is_a?(Numeric) && @quiet > 0
    fail ArgumentError.new('max_wait must be > 0') \
      unless @max_wait.is_a?(Numeric) && @max_wait > 0
    fail ArgumentError.new('max_wait must be >= quiet') \
      unless @max_wait >= @quiet

    @mutex = Mutex.new
    @condition = ConditionVariable.new
    @pending = {}
    @running = Hash.new { |h, k| h[k] = [] }
  end

  def submit(key, payload)

    @mutex.synchronize do

      fail Rufus::Scheduler::NotRunningError.new(
        'cannot submit to a debouncer whose scheduler is down'
      ) unless @scheduler.up?

      current_time = now
      event = Event.new(current_time, payload)
      current = @pending[key]

      if current

        merged = @merge.call(current.payload, payload)

        current.last_event = event
        current.payload = merged
        current.job.next_time =
          [
            current_time + @quiet,
            current.first_event.at + @max_wait
          ].min
      else

        @pending[key] =
          Round.new(
            key,
            event,
            event,
            payload,
            schedule(key, @quiet)
          )
      end

      event
    end
  end

  def flush(key=nil)

    return flush_all if key.nil?

    round = nil
    target = nil

    @mutex.synchronize do

      round = @pending.delete(key)

      if round

        round.job.unschedule
        @running[key] << round
      else

        target = @running[key].last
        return nil unless target
        return batch(target) if target.thread == Thread.current
      end
    end

    execute(round) if round
    wait_for(target) if target

    batch(round || target)
  end

  def cancel(key=nil)

    return cancel_all if key.nil?

    @mutex.synchronize do

      round = @pending.delete(key)
      round.job.unschedule if round

      round ? batch(round) : nil
    end
  end

  def pending?(key=nil)

    @mutex.synchronize do

      if key.nil? then ! @pending.empty?
      else !! @pending[key]
      end
    end
  end

  def keys

    @mutex.synchronize { @pending.keys }
  end

  def close

    cancel_all
  end

  def claim_timer(key, job, trigger_time)

    @mutex.synchronize do

      round = @pending[key]

      return nil unless
        round && round.job.equal?(job)

      return false if round.job.next_time > trigger_time

      @pending.delete(key)
      @running[key] << round

      round
    end
  end

  def execute(round)

    round.thread = Thread.current

    call_handler(batch(round))

  ensure

    @mutex.synchronize do

      @running[round.key].delete(round)
      @condition.broadcast
    end
  end

  def wait_for(round)

    @mutex.synchronize do

      while @running[round.key].include?(round)
        @condition.wait(@mutex)
      end
    end
  end

  def flush_all

    rounds = nil
    targets = []

    @mutex.synchronize do

      rounds = @pending.values
      @pending.clear

      rounds.each do |round|

        round.job.unschedule
        @running[round.key] << round
      end

      @running.each_value do |rounds_for_key|

        rounds_for_key.each do |round|

          targets << round unless round.thread == Thread.current
        end
      end
    end

    rounds.each { |round| execute(round) }

    targets.each do |round|

      next if round.thread == Thread.current
      wait_for(round)
    end

    targets.collect { |round| batch(round) }
  end

  def cancel_all

    @mutex.synchronize do

      @pending.each_with_object({}) do |(key, round), result|

        round.job.unschedule
        result[key] = batch(round)
      end.tap { @pending.clear }
    end
  end

  def batch(round)

    Batch.new(
      round.key,
      round.first_event,
      round.last_event,
      round.payload
    )
  end

  def now

    @clock.now
  end

  private

  def schedule(key, delay)

    if @scheduler.respond_to?(:schedule_debouncer_timer, true)

      @scheduler.send(:schedule_debouncer_timer, self, key, delay)
    elsif @scheduler.respond_to?(:in)

      @scheduler.in(delay) { claim_and_fire(key) }
    else

      fail ArgumentError.new(
        'scheduler must respond to #schedule_debouncer_timer or #in'
      )
    end
  end

  def claim_and_fire(key)

    round = nil

    @mutex.synchronize do

      candidate = @pending[key]

      if candidate

        round = candidate
        @pending.delete(key)
        @running[key] << round
      end
    end

    execute(round) if round
  end

  def call_handler(batch)

    callable =
      @handler.respond_to?(:arity) ?
        @handler :
        @handler.method(:call)

    args =
      case callable.arity
      when 0 then []
      when 1 then [ batch ]
      when 2 then [ batch.key, batch.payload ]
      else [ batch.key, batch.payload, batch ]
      end

    callable.call(*args)
  end
end
