
require 'date' if RUBY_VERSION < '1.9.0'
require 'thread'

require 'fugit'


module Rufus; end

class Rufus::Scheduler

  VERSION = '3.9.2'

  EoTime = ::EtOrbi::EoTime

  require 'rufus/scheduler/util'
  require 'rufus/scheduler/jobs_core'
  require 'rufus/scheduler/jobs_one_time'
  require 'rufus/scheduler/jobs_repeat'
  require 'rufus/scheduler/job_array'
  require 'rufus/scheduler/locks'

  #
  # A common error class for rufus-scheduler
  #
  class Error < StandardError; end

  #
  # This error is thrown when the :timeout attribute triggers
  #
  class TimeoutError < Error; end

  #
  # For when the scheduler is not running
  # (it got shut down or didn't start because of a lock)
  #
  class NotRunningError < Error; end

  # For when a scheduler created in another process is used after a fork
  #
  class ForkedSchedulerError < Error; end

  #MIN_WORK_THREADS = 3
  MAX_WORK_THREADS = 28

  attr_accessor :frequency
  attr_accessor :discard_past

  attr_reader :started_at
  attr_reader :paused_at
  attr_reader :thread
  attr_reader :thread_key
  attr_reader :mutexes
  attr_reader :pid
  attr_reader :parent_pid

  #attr_accessor :min_work_threads
  attr_accessor :max_work_threads

  attr_accessor :stderr

  attr_reader :work_queue

  def initialize(opts={})

    @opts = opts

    @pid = $$
    @parent_pid = nil

    @started_at = nil
    @paused_at = nil

    @jobs = JobArray.new

    @frequency = Rufus::Scheduler.parse(opts[:frequency] || 0.300)
    @discard_past = opts.has_key?(:discard_past) ? opts[:discard_past] : true

    @mutexes = {}

    @work_queue = Queue.new
    @join_queue = Queue.new

    #@min_work_threads =
    #  opts[:min_work_threads] || opts[:min_worker_threads] ||
    #  MIN_WORK_THREADS
    @max_work_threads =
      opts[:max_work_threads] || opts[:max_worker_threads] ||
      MAX_WORK_THREADS

    @stderr = $stderr

    @thread_key = "rufus_scheduler_#{self.object_id}"

    @scheduler_lock = build_scheduler_lock(opts)
    @trigger_lock = build_trigger_lock(opts)

    # If we can't grab the @scheduler_lock, don't run.
    lock || return

    start
  end

  # Returns a singleton Rufus::Scheduler instance
  #
  def self.singleton(opts={})

    @singleton ||= Rufus::Scheduler.new(opts)
  end

  # Alias for Rufus::Scheduler.singleton
  #
  def self.s(opts={}); singleton(opts); end

  # Takes over the singleton scheduler in a forked child process.
  #
  def self.after_fork(opts={})

    singleton.after_fork(opts)
  end

  # Releasing the gem would probably require redirecting .start_new to
  # .new and emit a simple deprecation message.
  #
  # For now, let's assume the people pointing at rufus-scheduler/master
  # on GitHub know what they do...
  #
  def self.start_new

    fail 'this is rufus-scheduler 3.x, use .new instead of .start_new'
  end

  def uptime

    @started_at ? EoTime.now - @started_at : nil
  end

  # Returns true if this scheduler object was inherited through a fork.
  #
  def forked?

    @pid != $$
  end

  # Raises if this scheduler object belongs to the parent process.
  #
  def ensure_current_process!

    return unless forked?

    fail ForkedSchedulerError.new(
      "scheduler was started in PID #{@pid}, current PID is #{$$}; " +
      "call #after_fork before using it in this process"
    )
  end

  # Rebuilds a forked scheduler inside the child process. By default the child
  # starts with an empty schedule. Set :copy_jobs (or :copy_schedule) to true
  # to re-register the parent's currently scheduled job definitions.
  #
  def after_fork(copy_jobs=false, opts={})

    if copy_jobs.is_a?(Hash)
      opts = copy_jobs
      copy_jobs = opts[:copy_jobs] || opts[:copy_schedule]
    else
      copy_jobs = opts[:copy_jobs] || opts[:copy_schedule] || copy_jobs
    end

    fail Error.new(
      "#after_fork was called in PID #{$$}, the scheduler's original PID"
    ) unless forked?

    definitions = copy_jobs ? fork_job_definitions : []

    reset_for_fork

    return self unless lock

    start

    definitions.each { |d| register_fork_job_definition(d) }

    self
  end

  def around_trigger(job)

    yield
  end

  def uptime_s

    uptime ? self.class.to_duration(uptime) : ''
  end

  def join(time_limit=nil)

    ensure_current_process!
    fail NotRunningError.new('cannot join scheduler that is not running') \
      unless @thread
    fail ThreadError.new('scheduler thread cannot join itself') \
      if @thread == Thread.current

    if time_limit
      time_limit_join(time_limit)
    else
      no_time_limit_join
    end
  end

  def down?

    @started_at.nil? || forked?
  end

  def up?

    !! @started_at && ! forked?
  end

  def paused?

    !! @paused_at
  end

  def pause

    ensure_current_process!
    @paused_at = EoTime.now
  end

  def resume(opts={})

    ensure_current_process!
    dp = opts[:discard_past]
    jobs.each { |job| job.resume_discard_past = dp }

    @paused_at = nil
  end

  #--
  # scheduling methods
  #++

  def at(time, callable=nil, opts={}, &block)

    do_schedule(:once, time, callable, opts, opts[:job], block)
  end

  def schedule_at(time, callable=nil, opts={}, &block)

    do_schedule(:once, time, callable, opts, true, block)
  end

  def in(duration, callable=nil, opts={}, &block)

    do_schedule(:once, duration, callable, opts, opts[:job], block)
  end

  def schedule_in(duration, callable=nil, opts={}, &block)

    do_schedule(:once, duration, callable, opts, true, block)
  end

  def every(duration, callable=nil, opts={}, &block)

    do_schedule(:every, duration, callable, opts, opts[:job], block)
  end

  def schedule_every(duration, callable=nil, opts={}, &block)

    do_schedule(:every, duration, callable, opts, true, block)
  end

  def interval(duration, callable=nil, opts={}, &block)

    do_schedule(:interval, duration, callable, opts, opts[:job], block)
  end

  def schedule_interval(duration, callable=nil, opts={}, &block)

    do_schedule(:interval, duration, callable, opts, true, block)
  end

  def cron(cronline, callable=nil, opts={}, &block)

    do_schedule(:cron, cronline, callable, opts, opts[:job], block)
  end

  def schedule_cron(cronline, callable=nil, opts={}, &block)

    do_schedule(:cron, cronline, callable, opts, true, block)
  end

  def schedule(arg, callable=nil, opts={}, &block)

    callable, opts = nil, callable if callable.is_a?(Hash)
    opts = opts.dup

    opts[:_t] = Rufus::Scheduler.parse(arg, opts)

    case opts[:_t]
    when ::Fugit::Cron then schedule_cron(arg, callable, opts, &block)
    when ::EtOrbi::EoTime, Time then schedule_at(arg, callable, opts, &block)
    else schedule_in(arg, callable, opts, &block)
    end
  end

  def repeat(arg, callable=nil, opts={}, &block)

    callable, opts = nil, callable if callable.is_a?(Hash)
    opts = opts.dup

    opts[:_t] = Rufus::Scheduler.parse(arg, opts)

    case opts[:_t]
    when ::Fugit::Cron then schedule_cron(arg, callable, opts, &block)
    else schedule_every(arg, callable, opts, &block)
    end
  end

  def unschedule(job_or_job_id)

    ensure_current_process!
    job, job_id = fetch(job_or_job_id)

    fail ArgumentError.new("no job found with id '#{job_id}'") unless job

    job.unschedule if job
  end

  #--
  # jobs methods
  #++

  # Returns all the scheduled jobs
  # (even those right before re-schedule).
  #
  def jobs(opts={})

    opts = { opts => true } if opts.is_a?(Symbol)

    jobs = @jobs.to_a

    if opts[:running]
      jobs = jobs.select { |j| j.running? }
    elsif ! opts[:all]
      jobs = jobs.reject { |j| j.next_time.nil? || j.unscheduled_at }
    end

    tags = Array(opts[:tag] || opts[:tags]).collect(&:to_s)
    jobs = jobs.reject { |j| tags.find { |t| ! j.tags.include?(t) } }

    jobs
  end

  def at_jobs(opts={})

    jobs(opts).select { |j| j.is_a?(Rufus::Scheduler::AtJob) }
  end

  def in_jobs(opts={})

    jobs(opts).select { |j| j.is_a?(Rufus::Scheduler::InJob) }
  end

  def every_jobs(opts={})

    jobs(opts).select { |j| j.is_a?(Rufus::Scheduler::EveryJob) }
  end

  def interval_jobs(opts={})

    jobs(opts).select { |j| j.is_a?(Rufus::Scheduler::IntervalJob) }
  end

  def cron_jobs(opts={})

    jobs(opts).select { |j| j.is_a?(Rufus::Scheduler::CronJob) }
  end

  def job(job_id)

    @jobs[job_id]
  end

  # Returns true if the scheduler has acquired the [exclusive] lock and
  # thus may run.
  #
  # Most of the time, a scheduler is run alone and this method should
  # return true. It is useful in cases where among a group of applications
  # only one of them should run the scheduler. For schedulers that should
  # not run, the method should return false.
  #
  # Out of the box, rufus-scheduler proposes the
  # :lockfile => 'path/to/lock/file' scheduler start option. It makes
  # it easy for schedulers on the same machine to determine which should
  # run (the first to write the lockfile and lock it). It uses "man 2 flock"
  # so it probably won't work reliably on distributed file systems.
  #
  # If one needs to use a special/different locking mechanism, the scheduler
  # accepts :scheduler_lock => lock_object. lock_object only needs to respond
  # to #lock
  # and #unlock, and both of these methods should be idempotent.
  #
  # Look at rufus/scheduler/locks.rb for an example.
  #
  def lock

    ensure_current_process!

    @scheduler_lock.lock
  end

  # Sister method to #lock, is called when the scheduler shuts down.
  #
  def unlock

    ensure_current_process!
    @trigger_lock.unlock
    @scheduler_lock.unlock
  end

  # Callback called when a job is triggered. If the lock cannot be acquired,
  # the job won't run (though it'll still be scheduled to run again if
  # necessary).
  #
  def confirm_lock

    @trigger_lock.lock
  end

  # Returns true if this job is currently scheduled.
  #
  # Takes extra care to answer true if the job is a repeat job
  # currently firing.
  #
  def scheduled?(job_or_job_id)

    job, _ = fetch(job_or_job_id)

    !! (job && job.unscheduled_at.nil? && job.next_time != nil)
  end

  # Lists all the threads associated with this scheduler.
  #
  def threads

    Thread.list.select { |t| t[thread_key] }
  end

  # Lists all the work threads (the ones actually running the scheduled
  # block code)
  #
  # Accepts a query option, which can be set to:
  # * :all (default), returns all the threads that are work threads
  #   or are currently running a job
  # * :active, returns all threads that are currently running a job
  # * :vacant, returns the threads that are not running a job
  #
  # If, thanks to :blocking => true, a job is scheduled to monopolize the
  # main scheduler thread, that thread will get returned when :active or
  # :all.
  #
  def work_threads(query=:all)

    ts = threads.select { |t| t[:rufus_scheduler_work_thread] }

    case query
    when :active then ts.select { |t| t[:rufus_scheduler_job] }
    when :vacant then ts.reject { |t| t[:rufus_scheduler_job] }
    else ts
    end
  end

  def running_jobs(opts={})

    jobs(opts.merge(:running => true))
  end

  def occurrences(time0, time1, format=:per_job)

    ensure_current_process!

    h = {}

    jobs.each do |j|
      os = j.occurrences(time0, time1)
      h[j] = os if os.any?
    end

    if format == :timeline
      a = []
      h.each { |j, ts| ts.each { |t| a << [ t, j ] } }
      a.sort_by { |(t, _)| t }
    else
      h
    end
  end

  def timeline(time0, time1)

    occurrences(time0, time1, :timeline)
  end

  def on_error(job, err)

    pre = err.object_id.to_s

    ms = {}; mutexes.each { |k, v| ms[k] = v.locked? }

    stderr.puts("{ #{pre} rufus-scheduler intercepted an error:")
    if job
      stderr.puts("  #{pre}   job:")
      stderr.puts("  #{pre}     #{job.class} #{job.original.inspect} #{job.opts.inspect}")
      stderr.puts("  #{pre}     #{job.source_location.inspect}")
      # TODO: eventually use a Job#detail or something like that
    else
      stderr.puts("  #{pre}   job: (error did not occur in a job)")
    end
    stderr.puts("  #{pre}   error:")
    stderr.puts("  #{pre}     #{err.object_id}")
    stderr.puts("  #{pre}     #{err.class}")
    stderr.puts("  #{pre}     #{err}")
    err.backtrace.each do |l|
      stderr.puts("  #{pre}       #{l}")
    end
    stderr.puts("  #{pre}   tz:")
    stderr.puts("  #{pre}     ENV['TZ']: #{ENV['TZ']}")
    stderr.puts("  #{pre}     Time.now: #{Time.now}")
    stderr.puts("  #{pre}     local_tzone: #{EoTime.local_tzone.inspect}")
    stderr.puts("  #{pre}   et-orbi:")
    stderr.puts("  #{pre}     #{EoTime.platform_info}")
    stderr.puts("  #{pre}   scheduler:")
    stderr.puts("  #{pre}     object_id: #{object_id}")
    stderr.puts("  #{pre}     opts:")
    stderr.puts("  #{pre}       #{@opts.inspect}")
    stderr.puts("  #{pre}       frequency: #{self.frequency}")
    stderr.puts("  #{pre}       scheduler_lock: #{@scheduler_lock.inspect}")
    stderr.puts("  #{pre}       trigger_lock: #{@trigger_lock.inspect}")
    stderr.puts("  #{pre}     uptime: #{uptime} (#{uptime_s})")
    stderr.puts("  #{pre}     down?: #{down?}")
    stderr.puts("  #{pre}     frequency: #{frequency.inspect}")
    stderr.puts("  #{pre}     discard_past: #{discard_past.inspect}")
    stderr.puts("  #{pre}     started_at: #{started_at.inspect}")
    stderr.puts("  #{pre}     paused_at: #{paused_at.inspect}")
    stderr.puts("  #{pre}     threads: #{self.threads.size}")
    stderr.puts("  #{pre}       thread: #{self.thread}")
    stderr.puts("  #{pre}       thread_key: #{self.thread_key}")
    stderr.puts("  #{pre}       work_threads: #{work_threads.size}")
    stderr.puts("  #{pre}         active: #{work_threads(:active).size}")
    stderr.puts("  #{pre}         vacant: #{work_threads(:vacant).size}")
    stderr.puts("  #{pre}         max_work_threads: #{max_work_threads}")
    stderr.puts("  #{pre}       mutexes: #{ms.inspect}")
    stderr.puts("  #{pre}     jobs: #{jobs.size}")
    stderr.puts("  #{pre}       at_jobs: #{at_jobs.size}")
    stderr.puts("  #{pre}       in_jobs: #{in_jobs.size}")
    stderr.puts("  #{pre}       every_jobs: #{every_jobs.size}")
    stderr.puts("  #{pre}       interval_jobs: #{interval_jobs.size}")
    stderr.puts("  #{pre}       cron_jobs: #{cron_jobs.size}")
    stderr.puts("  #{pre}     running_jobs: #{running_jobs.size}")
    stderr.puts("  #{pre}     work_queue:")
    stderr.puts("  #{pre}       size: #{@work_queue.size}")
    stderr.puts("  #{pre}       num_waiting: #{@work_queue.num_waiting}")
    stderr.puts("  #{pre}     join_queue:")
    stderr.puts("  #{pre}       size: #{@join_queue.size}")
    stderr.puts("  #{pre}       num_waiting: #{@join_queue.num_waiting}")
    stderr.puts("} #{pre} .")

  rescue => e

    stderr.puts("failure in #on_error itself:")
    stderr.puts(e.inspect)
    stderr.puts(e.backtrace)

  ensure

    stderr.flush
  end

  def shutdown(opt=nil)

    ensure_current_process!

    opts =
      case opt
      when Symbol then { opt => true }
      when Hash then opt
      else {}
      end

    @jobs.unschedule_all

    if opts[:wait] || opts[:join]
      join_shutdown(opts)
    elsif opts[:kill]
      kill_shutdown(opts)
    else
      regular_shutdown(opts)
    end

    @work_queue.clear

    unlock

    @thread.join unless @thread == Thread.current
  end
  alias stop shutdown

  protected

  def build_scheduler_lock(opts)

    if lockfile = opts[:lockfile]
      Rufus::Scheduler::FileLock.new(lockfile)
    else
      opts[:scheduler_lock] || Rufus::Scheduler::NullLock.new
    end
  end

  def build_trigger_lock(opts)

    opts[:trigger_lock] || Rufus::Scheduler::NullLock.new
  end

  def refresh_fork_lock(lock)

    lock.respond_to?(:after_fork) ? lock.after_fork : lock
  end

  def reset_for_fork

    @jobs = JobArray.new
    @mutexes = {}
    @work_queue = Queue.new
    @join_queue = Queue.new

    @started_at = nil
    @paused_at = nil
    @thread = nil
    @parent_pid = @pid
    @pid = $$
    @thread_key = "rufus_scheduler_#{object_id}_p#{$$}"

    @scheduler_lock =
      refresh_fork_lock(build_scheduler_lock(@opts))
    @trigger_lock =
      refresh_fork_lock(build_trigger_lock(@opts))
  end

  FORK_FIRST_KEYS = %i[ first first_time first_at first_in ].freeze
  FORK_LAST_KEYS = %i[ last last_at last_in ].freeze

  def fork_job_definitions

    now = EoTime.now

    jobs.each_with_object([]) do |job, a|

      opts = job.opts.dup

      opts.delete(:_t)
      opts.delete(:locals)
      opts.delete(:l)

      if job.is_a?(OneTimeJob)

        job_discard_past =
          job.opts[:discard_past].nil? ?
          discard_past :
          job.opts[:discard_past]

        next if job_discard_past && job.past?
      end

      opts[:mutex] =
        Array(opts[:mutex]).collect do |m|
          m.is_a?(Mutex) ? "__forked_mutex_#{m.object_id}" : m
        end if opts[:mutex]

      if job.is_a?(RepeatJob)

        FORK_FIRST_KEYS.each { |k| opts.delete(k) }
        FORK_LAST_KEYS.each { |k| opts.delete(k) }

        next if job.last_at && job.last_at < now

        opts[:first_at] = job.first_at if job.first_at && job.first_at > now
        opts[:last_at] = job.last_at if job.last_at
      end

      opts[:forked_from_job_id] = job.id

      a << { :job => job, :callable => job.handler, :opts => opts }
    end
  end

  def register_fork_job_definition(definition)

    job = definition[:job]
    callable = definition[:callable]
    opts = definition[:opts]

    case job
    when InJob then public_send(:in, job.original, callable, opts)
    when AtJob then at(job.original, callable, opts)
    when EveryJob then every(job.original, callable, opts)
    when IntervalJob then interval(job.original, callable, opts)
    when CronJob then cron(job.original, callable, opts)
    end
  end

  def join_shutdown(opts)

    limit = opts[:wait] || opts[:join]
    limit = limit.is_a?(Numeric) ? limit : nil

    #@started_at = nil
      #
      # when @started_at is nil, the scheduler thread exits, here
      # we want it to exit when all the work threads have been joined
      # hence it's set to nil later on
      #
    @paused_at = EoTime.now

    (work_threads.size * 2 + 1).times { @work_queue << :shutdown }

    work_threads
      .collect { |wt|
        wt == Thread.current ? nil : Thread.new { wt.join(limit); wt.kill } }
      .each { |st|
        st.join if st }

    @started_at = nil
  end

  def kill_shutdown(opts)

    @started_at = nil
    work_threads.each(&:kill)
  end

  def regular_shutdown(opts)

    @started_at = nil
  end

  def time_limit_join(limit)

    fail ArgumentError.new("limit #{limit.inspect} should be > 0") \
      unless limit.is_a?(Numeric) && limit > 0

    t0 = monow
    f = [ limit.to_f / 20, 0.100 ].min

    while monow - t0 < limit
      r =
        begin
          @join_queue.pop(true)
        rescue ThreadError
          # #<ThreadError: queue empty>
          false
        end
      return r if r
      sleep(f)
    end

    nil
  end

  def no_time_limit_join

    @join_queue.pop
  end

  # Returns [ job, job_id ]
  #
  def fetch(job_or_job_id)

    if job_or_job_id.respond_to?(:job_id)
      [ job_or_job_id, job_or_job_id.job_id ]
    else
      [ job(job_or_job_id), job_or_job_id ]
    end
  end

  def terminate_all_jobs

    jobs.each { |j| j.unschedule }

    sleep 0.01 while running_jobs.size > 0
  end

  #def free_all_work_threads
  #
  #  work_threads.each { |t| t.raise(KillSignal) }
  #end

  def start

    @started_at = EoTime.now

    @thread =
      Thread.new do

        while @started_at do
          begin

            unschedule_jobs
            trigger_jobs unless @paused_at
            timeout_jobs

            sleep(@frequency)

          rescue => err
            #
            # for `blocking: true` jobs mostly
            #
            on_error(nil, err)
          end
        end

        rejoin
      end

    @thread[@thread_key] = true
    @thread[:rufus_scheduler] = self
    @thread[:name] = @opts[:thread_name] || "#{@thread_key}_scheduler"
  end

  def unschedule_jobs

    @jobs.delete_unscheduled
  end

  def start_work_thread

    thread =
      Thread.new do

        ct = Thread.current

        ct[:rufus_scheduler_job] = true
        ct[thread_key] = true
        ct[:rufus_scheduler_work_thread] = true

        loop do

          break if started_at == nil

          job, time = work_queue.pop

          break if job == :shutdown
          break if started_at == nil

          next if job.unscheduled_at

          begin

            (job.opts[:mutex] || []).reduce(
              lambda { job.send(:trigger_now, time) }
            ) do |b, m|
              lambda { job.send(:mutex, m).synchronize { b.call } }
            end.call

          rescue Job::KillSignal

            # simply go on looping
          end
        end
      end

    thread[thread_key] = true
    thread[:rufus_scheduler_work_thread] = true

    thread
  end

  def trigger_jobs

    now = EoTime.now

    @jobs.each(now) do |job|

      job.trigger(now)
    end
  end

  def timeout_jobs

    work_threads(:active).each do |t|

      job = t[:rufus_scheduler_job]
      to = t[:rufus_scheduler_timeout]
      ts = t[:rufus_scheduler_time]

      next unless job && to && ts
        # thread might just have become inactive (job -> nil)

      to = ts + to unless to.is_a?(EoTime)

      next if to > EoTime.now

      t.raise(Rufus::Scheduler::TimeoutError)
    end
  end

  def rejoin

    (@join_queue.num_waiting * 2 + 1).times { @join_queue << @thread }
  end

  def do_schedule(job_type, t, callable, opts, return_job_instance, block)

    ensure_current_process!

    fail NotRunningError.new(
      'cannot schedule, scheduler is down or shutting down'
    ) if @started_at.nil?

    callable, opts = nil, callable if callable.is_a?(Hash)
    opts = opts.dup unless opts.has_key?(:_t)

    return_job_instance ||= opts[:job]

    job_class =
      case job_type
      when :once
        opts[:_t] ||= Rufus::Scheduler.parse(t, opts)
        opts[:_t].is_a?(Numeric) ? InJob : AtJob
      when :every
        EveryJob
      when :interval
        IntervalJob
      when :cron
        CronJob
      end

    job = job_class.new(self, t, opts, block || callable)

    if job.past? && (d = job.send(:discard_past?))
      fail ArgumentError.new(
        "scheduling in the past and discard_past set to :fail"
          ) if d == :fail
      return
    end

    job.check_frequency

    @jobs.push(job)

    return_job_instance ? job : job.job_id
  end

  def monow; self.class.monow; end
  def ltstamp; self.class.ltstamp; end
end
