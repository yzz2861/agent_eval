#
# Offline concurrency (capacity) analysis.
#
# Given estimated work durations for the jobs of a scheduler and an
# observation window, computes how many jobs may run concurrently,
# without triggering anything and without modifying the jobs (their
# next_time, times, ... are left untouched).
#
class Rufus::Scheduler::ConcurrencyAnalysis

  DEFAULT_MAX_EXPANSIONS = 10_000

  # A half-open [starts_at, ends_at) span during which the concurrency
  # peak holds, along with the jobs contributing to it.
  #
  class Window

    attr_reader :starts_at, :ends_at, :jobs

    def initialize(starts_at, ends_at, jobs)

      @starts_at = starts_at
      @ends_at = ends_at
      @jobs = jobs
    end

    # Merges a contiguous span (starting where this window ends)
    # into this window.
    #
    def extend_to(ends_at, jobs)

      @ends_at = ends_at
      @jobs |= jobs
    end

    def ==(other)

      other.is_a?(Window) &&
        other.starts_at == starts_at &&
        other.ends_at == ends_at &&
        other.jobs == jobs
    end

    def to_s

      "#{starts_at} ... #{ends_at} (#{jobs.collect(&:id).join(', ')})"
    end
  end

  attr_reader :scheduler
  attr_reader :time0, :time1
  attr_reader :max_expansions
  attr_reader :expansions

  # The maximum number of jobs simultaneously "running" over the
  # covered window.
  #
  attr_reader :peak

  # Array of Window instances, the spans where #peak holds.
  #
  attr_reader :peak_windows

  # End of the window over which the analysis is valid. Equal to
  # #time1 when the analysis is complete, smaller when the expansion
  # limit was hit and occurrences are missing past that point.
  #
  attr_reader :covered_until

  def initialize(scheduler, time0, time1, durations={}, opts={})

    @scheduler = scheduler

    @time0 = EoTime.make(time0)
    @time1 = EoTime.make(time1)

    fail ArgumentError.new(
      "window end #{time1.inspect} must be after window start #{time0.inspect}"
    ) if @time1 <= @time0

    @durations = durations || {}
    @max_expansions = opts[:max_expansions] || DEFAULT_MAX_EXPANSIONS

    @expansions = 0
    @truncated_at = nil

    compute
  end

  # Returns false when the expansion limit was reached and the result
  # only covers [ time0, covered_until ), not the full requested window.
  #
  def complete?

    @truncated_at.nil?
  end

  # The jobs contributing to the peak windows.
  #
  def contributors

    @peak_windows.collect(&:jobs).flatten.uniq
  end

  protected

  EoTime = ::EtOrbi::EoTime

  def compute

    events = []

    @scheduler.jobs.each do |job|

      next if job.respond_to?(:paused?) && job.paused?

      duration = duration_for(job)
        #
        # zero duration jobs occupy an empty [t, t) interval,
        # they can never contribute to the concurrency

      next if duration <= 0.0

      expand(job, duration).each do |s, e|
        events << [ s.to_f, s, 1, job ]
        events << [ e.to_f, e, -1, job ]
      end
    end

    sweep(events)
  end

  # Expands the occurrences of a job, following the real cron / every /
  # interval semantics, without touching the job state.
  #
  # Returns an array of [ start, start + duration ) pairs.
  #
  def expand(job, duration)

    intervals = []

    nt = job.next_time
    times = job.is_a?(Rufus::Scheduler::RepeatJob) ? job.times : 1
    last_at = job.respond_to?(:last_at) ? job.last_at : nil

    while nt && nt < @time1

      break if times && times <= 0
      break if last_at && nt >= last_at

      if @expansions >= @max_expansions
        @truncated_at = nt if @truncated_at.nil? || nt < @truncated_at
        break
      end

      @expansions += 1
      intervals << [ nt, nt + duration ]

      times -= 1 if times
      break if times && times <= 0

      nt = next_start_from(job, nt, duration)
    end

    intervals
  end

  # The start time following the given one, mirroring each job class:
  #
  # * cron: next cron point (time zone aware, via Fugit)
  # * every: one frequency after the previous trigger
  # * interval: interval counted from the (estimated) end of the work
  #
  def next_start_from(job, time, duration)

    if job.is_a?(Rufus::Scheduler::IntervalJob)
      time + duration + job.interval
    else
      job.next_time_from(time)
    end
  end

  def duration_for(job)

    d = @durations

    v =
      if d.respond_to?(:call)
        d.call(job)
      else
        d[job] ||
        d[job.id] ||
        (job.name && (d[job.name] || d[job.name.to_s] || d[job.name.to_sym])) ||
        job.tags
          .collect { |t| d[t] || d[t.to_sym] }
          .compact.first ||
        d[:default] || d['default']
      end

    v = 0.0 if v.nil?
    v = Rufus::Scheduler.parse_duration(v).to_f

    fail ArgumentError.new(
      "negative duration #{v} for job #{job.id}"
    ) if v < 0.0

    v
  end

  # Half-open interval sweep: at any given point, intervals ending there
  # are removed before intervals starting there get added, so an interval
  # ending exactly when another starts does not inflate the count.
  #
  def sweep(events)

    by_time = {}
    events.each { |ev| (by_time[ev[0]] ||= []) << ev }

    @covered_until =
      complete? ? @time1 : [ @time1, @truncated_at ].min

    t0f = @time0.to_f
    t1f = @covered_until.to_f

    count = 0
    active = {} # job => number of active occurrences (insertion ordered)

    apply = lambda do |t|
      by_time[t].each { |(_, _, delta, job)|
        next if delta > 0
        c = active[job] - 1
        c > 0 ? active[job] = c : active.delete(job)
        count -= 1
      }
      by_time[t].each { |(_, _, delta, job)|
        next if delta < 0
        active[job] = (active[job] || 0) + 1
        count += 1
      }
    end

    times = by_time.keys.sort

    times.each { |t| apply.call(t) if t <= t0f }
      # state at the beginning of the window

    @peak = 0
    @peak_windows = []

    current = @time0
    current_f = t0f

    record = lambda do |up_to, up_to_f|
      return if up_to_f <= current_f
      return if count < 1
      if count > @peak
        @peak = count
        @peak_windows = [ Window.new(current, up_to, active.keys.dup) ]
      elsif count == @peak
        last = @peak_windows.last
        if last && last.ends_at == current
          last.extend_to(up_to, active.keys)
        else
          @peak_windows << Window.new(current, up_to, active.keys.dup)
        end
      end
    end

    times.each do |t|

      next if t <= t0f
      break if t >= t1f

      up_to = by_time[t].first[1]
      record.call(up_to, t)
      apply.call(t)

      current = up_to
      current_f = t
    end

    record.call(@covered_until, t1f)
  end
end
