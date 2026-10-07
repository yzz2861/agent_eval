
class Rufus::Scheduler::Job

  EoTime = ::EtOrbi::EoTime

  #
  # Used by Job#kill
  #
  class KillSignal < StandardError; end

  #
  # Used by jobs with :overlap => :latest, describes the trigger
  # currently sitting in the "pending" slot.
  #
  # The slot keeps the original scheduled time of the latest merged
  # trigger and the count of triggers merged into the slot so far
  # (>= 1, the trigger that opened the slot included).
  #
  LatestPending = Struct.new(:time, :merged)

  attr_reader :id
  attr_reader :opts
  attr_reader :original
  attr_reader :scheduled_at
  attr_reader :last_time
  attr_reader :unscheduled_at
  attr_reader :tags
  attr_reader :locals
  attr_reader :count
  attr_reader :last_work_time
  attr_reader :mean_work_time

  attr_accessor :name

  # next trigger time
  #
  attr_accessor :next_time

  # previous "next trigger time"
  #
  attr_accessor :previous_time

  # anything with a #call(job[, timet]) method,
  # what gets actually triggered
  #
  attr_reader :callable

  # a reference to the instance whose call method is the @callable
  #
  attr_reader :handler

  # Default, core, implementation has no effect. Repeat jobs do override it.
  #
  def resume_discard_past=(v); end

  def initialize(scheduler, original, opts, block)

    @scheduler = scheduler
    @original = original
    @opts = opts

    @handler = block

    @callable =
      if block.respond_to?(:arity)
        block
      elsif block.respond_to?(:call)
        block.method(:call)
      elsif block.is_a?(Class)
        @handler = block.new
        @handler.method(:call) rescue nil
      else
        nil
      end

    @scheduled_at = EoTime.now
    @unscheduled_at = nil
    @last_time = nil

    @discard_past = opts[:discard_past]

    @locals = opts[:locals] || opts[:l] || {}
    @local_mutex = Mutex.new

    @latest_mutex = Mutex.new
    @latest_active = false
    @latest_pending = nil

    @id = determine_id
    @name = opts[:name] || opts[:n]

    fail(
      ArgumentError, 'missing block or callable to schedule', caller[2..-1]
    ) unless @callable

    @tags = Array(opts[:tag] || opts[:tags]).collect { |t| t.to_s }

    @count = 0
    @last_work_time = 0.0
    @mean_work_time = 0.0

    # tidy up options

    if @opts[:allow_overlap] == false || @opts[:allow_overlapping] == false
      @opts[:overlap] = false
    end
    if m = @opts[:mutex]
      @opts[:mutex] = Array(m)
    end
  end

  alias job_id id

  def source_location

    @callable.source_location
  end
  alias location source_location

  # Returns true if the job is scheduled in the past.
  # Used for OneTimeJob when discard_past == true
  #
  def past?

    false # by default
  end

  # Will fail with an ArgumentError if the job frequency is higher than
  # the scheduler frequency.
  #
  def check_frequency

    # this parent implementation never fails
  end

  def trigger(time)

    @previous_time = @next_time
    set_next_time(time)

    do_trigger(time)
  end

  # Trigger the job right now, off of its schedule.
  #
  # Done in collaboration with Piavka in
  # https://github.com/jmettraux/rufus-scheduler/issues/214
  #
  def trigger_off_schedule(time=EoTime.now)

    do_trigger(time)
  end

  # Only meaningful for jobs with :overlap => :latest.
  #
  # Returns a LatestPending (time, merged) describing the trigger
  # currently sitting in the pending slot, or nil when the slot
  # is empty.
  #
  def latest_pending

    @latest_mutex.synchronize {
      @latest_pending ? @latest_pending.dup : nil }
  end

  def unschedule

    @unscheduled_at = EoTime.now

    @latest_mutex.synchronize { @latest_pending = nil }
  end

  def threads

    Thread.list.select { |t| t[:rufus_scheduler_job] == self }
  end

  # Kills all the threads this Job currently has going on.
  #
  def kill

    threads.each { |t| t.raise(KillSignal) }
  end

  def running?

    threads.any?
  end

  def scheduled?

    @scheduler.scheduled?(self)
  end

  def []=(key, value)

    @local_mutex.synchronize { @locals[key] = value }
  end

  def [](key)

    @local_mutex.synchronize { @locals[key] }
  end

  def has_key?(key)

    @local_mutex.synchronize { @locals.has_key?(key) }
  end
  alias key? has_key?

  def keys; @local_mutex.synchronize { @locals.keys }; end
  def values; @local_mutex.synchronize { @locals.values }; end
  def entries; @local_mutex.synchronize { @locals.entries }; end

  #def hash
  #  self.object_id
  #end
  #def eql?(o)
  #  o.class == self.class && o.hash == self.hash
  #end
    #
    # might be necessary at some point

  def next_times(count)

    next_time ? [ next_time ] : []
  end

  # Calls the callable (usually a block) wrapped in this Job instance.
  #
  # Warning: error rescueing is the responsibity of the caller.
  #
  def call(do_rescue=false)

    do_call(EoTime.now, do_rescue)
  end

  protected

  def callback(meth, time)

    return true unless @scheduler.respond_to?(meth)

    arity = @scheduler.method(meth).arity
    args = [ self, time ][0, (arity < 0 ? 2 : arity)]

    @scheduler.send(meth, *args)
  end

  def compute_timeout

    if to = @opts[:timeout]
      Rufus::Scheduler.parse(to)
    else
      nil
    end
  end

  def mutex(m)

    m.is_a?(Mutex) ? m : (@scheduler.mutexes[m.to_s] ||= Mutex.new)
  end

  def do_call(time, do_rescue)

    args = [ self, time ][0, @callable.arity]

    @scheduler.around_trigger(self) do
      @callable.call(*args)
    end

  rescue StandardError => se

    fail se unless do_rescue

    return if se.is_a?(KillSignal) # discard

    @scheduler.on_error(self, se)

  # exceptions above StandardError do pass through
  end

  def do_trigger(time)

    return if (
      opts[:overlap] == false &&
      running?
    )
    return if (
      callback(:confirm_lock, time) &&
      callback(:on_pre_trigger, time)
    ) == false

    return if (
      opts[:overlap] == :latest &&
      ! claim_latest_slot(time)
    )

    @count += 1

    if opts[:blocking]
      trigger_now(time)
    else
      trigger_queue(time)
    end
  end

  def trigger_now(time)

    ct = Thread.current

    t = EoTime.now
      # if there are mutexes, t might be really bigger than time

    ct[:rufus_scheduler_job] = self
    ct[:rufus_scheduler_time] = t
    ct[:rufus_scheduler_timeout] = compute_timeout

    @last_time = t

    do_call(time, true)

  ensure

    @last_work_time =
      EoTime.now - ct[:rufus_scheduler_time]
    @mean_work_time =
      ((@count - 1) * @mean_work_time + @last_work_time) / @count

    post_trigger(time)

    release_latest_slot

    ct[:rufus_scheduler_job] = nil
    ct[:rufus_scheduler_time] = nil
    ct[:rufus_scheduler_timeout] = nil
  end

  # For jobs with :overlap => :latest.
  #
  # Returns true when the trigger may proceed (it claimed the
  # "active" slot), false when the trigger got merged into the
  # pending slot (a newer trigger replaces the slot content).
  #
  def claim_latest_slot(time)

    @latest_mutex.synchronize do

      if @latest_active
        if @latest_pending
          @latest_pending.time = time
          @latest_pending.merged += 1
        else
          @latest_pending = LatestPending.new(time, 1)
        end
        false
      else
        @latest_active = true
        true
      end
    end
  end

  # For jobs with :overlap => :latest. Called when a run of the job
  # is done (end of #trigger_now).
  #
  # Hands the "active" slot over to the pending trigger if there is
  # one, else simply releases the slot.
  #
  def release_latest_slot

    return unless opts[:overlap] == :latest

    pending = nil

    @latest_mutex.synchronize do
      pending = @latest_pending
      @latest_pending = nil
      @latest_active = false unless pending
    end

    trigger_pending_latest(pending) if pending
  end

  # Dispatches the pending trigger of an :overlap => :latest job.
  #
  # Goes through the work queue (never through #trigger_now) so that
  # the follow-up run does not happen recursively on the stack of
  # the thread that just finished (not even for :blocking => true
  # jobs).
  #
  def trigger_pending_latest(pending)

    time = pending.time

    if (
      callback(:confirm_lock, time) &&
      callback(:on_pre_trigger, time)
    ) == false
      @latest_mutex.synchronize { @latest_active = false }
      return
    end

    @count += 1

    trigger_queue(time)
  end

  def post_trigger(time)

    set_next_time(time, true)
      # except IntervalJob instances, jobs will ignore this call

    callback(:on_post_trigger, time)
  end

  def start_work_thread

    thread =
      Thread.new do

        ct = Thread.current

        ct[:rufus_scheduler_job] = true
          # indicates that the thread is going to be assigned immediately

        ct[@scheduler.thread_key] = true
        ct[:rufus_scheduler_work_thread] = true

        loop do

          break if @scheduler.started_at == nil

          job, time = @scheduler.work_queue.pop

          break if job == :shutdown
          break if @scheduler.started_at == nil

          next if job.unscheduled_at

          begin

            (job.opts[:mutex] || []).reduce(
              lambda { job.trigger_now(time) }
            ) do |b, m|
              lambda { mutex(m).synchronize { b.call } }
            end.call

          rescue KillSignal

            # simply go on looping
          end
        end
      end

    thread[@scheduler.thread_key] = true
    thread[:rufus_scheduler_work_thread] = true
      #
      # same as above (in the thead block),
      # but since it has to be done as quickly as possible.
      # So, whoever is running first (scheduler thread vs job thread)
      # sets this information

    thread
  end

  def trigger_queue(time)

    threads = @scheduler.work_threads

    vac = threads.select { |t| t[:rufus_scheduler_job] == nil }.size
    que = @scheduler.work_queue.size

    cur = threads.size
    max = @scheduler.max_work_threads

    start_work_thread if vac - que < 1 && cur < max

    @scheduler.work_queue << [ self, time ]
  end

  # Scheduler level < Job level < this resume()'s level
  #
  def discard_past?

    dp = @scheduler.discard_past
    dp = @discard_past if @discard_past != nil
    dp = @resume_discard_past if @resume_discard_past != nil

    dp
  end
end

