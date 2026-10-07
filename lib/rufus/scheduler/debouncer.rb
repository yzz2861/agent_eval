
class Rufus::Scheduler

  # Accepts external events grouped by key and triggers a callback after
  # a per-key quiet period, without exceeding a maximum wait.
  #
  class Debouncer

    Event = Struct.new(:key, :payload, :time)
    Batch = Struct.new(:key, :payload, :first_event, :last_event)

    class Round

      attr_accessor :key, :payload, :first_event, :last_event, :job, :deadline
      attr_accessor :job_token

      def initialize(key, payload, first_event, last_event, deadline)

        @key = key
        @payload = payload
        @first_event = first_event
        @last_event = last_event
        @deadline = deadline
        @job = nil
      end
    end

    attr_reader :quiet, :max_wait

    def initialize(scheduler, options={}, &block)

      @scheduler = scheduler
      @callback = options[:callback] || block
      @merge = options[:merge]

      fail ArgumentError.new('missing callback') unless @callback
      fail ArgumentError.new('missing merge callable') unless @merge

      @quiet =
        Rufus::Scheduler.parse_in(options.fetch(:quiet, options[:quiet_period]))
      @max_wait = Rufus::Scheduler.parse_in(options.fetch(:max_wait))

      fail ArgumentError.new('quiet must be > 0') unless @quiet > 0
      fail ArgumentError.new('max_wait must be > 0') unless @max_wait > 0

      @clock = options[:clock] || MonotonicClock.new
      @schedule = options[:schedule]

      @mutex = Mutex.new
      @rounds = {}
      @token = 0
    end

    def submit(key, payload=nil, time=current_time)

      event = Event.new(key, payload, time)

      @mutex.synchronize do

        round = @rounds[key]

        if round

          merged = @merge.call(round.payload, payload)
          round.payload = merged
          round.last_event = event

          schedule(round)
        else

          round =
            Round.new(key, payload, event, event, time + @max_wait)

          @rounds[key] = round

          schedule(round)
        end

        event
      end
    end

    # Atomically claims pending events for key (or every key) and runs them.
    # Events that already belong to a running callback form the next round.
    #
    def flush(key=nil)

      rounds = @mutex.synchronize { claim(key) }
      batches = rounds.collect { |round| dispatch(round) }

      key.nil? ? batches : batches.first
    end

    # Atomically removes pending events for key (or every key). A callback
    # that already claimed its round keeps running and is not cancelled.
    #
    def cancel(key=nil)

      rounds = @mutex.synchronize { claim(key) }
      batches = rounds.collect { |round| make_batch(round) }

      key.nil? ? batches : batches.first
    end

    def pending?(key)

      @mutex.synchronize { @rounds.has_key?(key) }
    end

    def pending_keys

      @mutex.synchronize { @rounds.keys }
    end

    private

    def current_time

      @clock.now
    end

    def schedule(round)

      unschedule(round.job) if round.job

      time = current_time
      quiet_at = time + @quiet
      due_at = [ round.deadline, quiet_at ].min
      delay = [ due_at - time, 0 ].max

      token = (@token += 1)

      round.job_token = token
      round.job = schedule_job(delay) { fire(round.key, token) }
    end

    def schedule_job(delay, &block)

      if @schedule
        @schedule.call(delay, block)
      else
        @scheduler.in(delay, block, :job => true)
      end
    end

    def unschedule(job)

      if job.respond_to?(:unschedule)
        job.unschedule
      elsif job.respond_to?(:call)
        job.call
      end
    end

    def fire(key, token)

      round =
        @mutex.synchronize do

          current = @rounds[key]

          if current && current.job_token == token
            claim(key).first
          end
        end

      dispatch(round) if round
    end

    def claim(key=nil)

      keys = key.nil? ? @rounds.keys : [ key ]

      keys.collect { |k|

        round = @rounds.delete(k)
        next unless round

        unschedule(round.job)
        round.job = nil

        round
      }.compact
    end

    def dispatch(round)

      batch = make_batch(round)
      callback = @callback

      args =
        case callback.arity
        when 0 then []
        when 1 then [ batch ]
        when 2 then [ batch.key, batch.payload ]
        else [ batch.key, batch.payload, batch ]
        end

      callback.call(*args)

      batch
    end

    def make_batch(round)

      Batch.new(
        round.key, round.payload, round.first_event, round.last_event)
    end

    class MonotonicClock

      def now

        Rufus::Scheduler.monow
      end
    end
  end
end
