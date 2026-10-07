class Rufus::Scheduler::ConcurrencyAnalyzer

  DEFAULT_MAX_EXPANSIONS = 10_000

  def initialize(jobs, time0, time1, durations, options={})

    @jobs = jobs
    @from = to_time(time0)
    @to = to_time(time1)
    @durations = durations
    @max_expansions = options[:max_expansions] || DEFAULT_MAX_EXPANSIONS

    fail ArgumentError.new('time0 must be before time1') if @from >= @to
    fail ArgumentError.new(
      ':max_expansions must be a positive Integer'
    ) unless @max_expansions.is_a?(Integer) && @max_expansions > 0

    @intervals = []
    @truncated_jobs = []
  end

  def call

    states = compatible_jobs.collect { |job| new_state(job) }

    expansions = 0

    while expansions < @max_expansions

      states = states.select { |state| candidate?(state) }
      break if states.empty?

      state = states.min_by { |item| [ item[:start].to_f, item[:job].id ] }

      expand_one(state)
      expansions += 1
    end

    if expansions >= @max_expansions
      @truncated_jobs =
        states
          .select { |state| candidate?(state) }
          .collect { |state| state[:job] }
    end

    result = scan

    result[:peak_concurrency] ||= 0
    result[:peak_windows] ||= []
    result[:complete] =
      expansions < @max_expansions && @truncated_jobs.empty?
    result[:truncated_jobs] = @truncated_jobs.dup

    result
  end

  private

  def compatible_jobs

    @jobs.select { |job| supported?(job) }
  end

  def new_state(job)

    {
      job: job,
      start: job.next_time,
      remaining: job.times,
      active_end: nil
    }
  end

  def expand_one(state)

    job = state[:job]
    start = state[:start]
    duration = duration_for(job)
    finish = start + duration

    if duration > 0 &&
       finish > @from &&
       can_start?(job, start, state[:active_end])

      @intervals << [ start, finish, job ]
      state[:active_end] = finish if job.opts[:overlap] == false
    end

    state[:remaining] -= 1 if state[:remaining]
    state[:start] = next_start(job, start, duration)
  end

  def supported?(job)

    job.is_a?(Rufus::Scheduler::RepeatJob) &&
    ! job.unscheduled_at &&
    ! job.paused?
  end

  def candidate?(state)

    job = state[:job]
    start = state[:start]

    return false if start.nil? || start == false
    return false if start >= @to
    return false if state[:remaining] && state[:remaining] <= 0
    return false if job.last_at && start >= job.last_at

    true
  end

  def can_start?(job, start, active_end)

    return true unless job.opts[:overlap] == false
    return true if active_end.nil?

    start >= active_end
  end

  def next_start(job, start, duration)

    case job
    when Rufus::Scheduler::IntervalJob
      start + duration + job.interval
    when Rufus::Scheduler::EveryJob
      start + job.frequency
    when Rufus::Scheduler::CronJob
      job.cron_line.next_time(start)
    end
  end

  def duration_for(job)

    duration = raw_duration_for(job)

    duration =
      duration.is_a?(Numeric) ? duration.to_f :
      Rufus::Scheduler.parse_in(duration)

    fail ArgumentError.new('duration cannot be negative') if duration < 0

    duration
  end

  def raw_duration_for(job)

    return @durations.call(job) if @durations.respond_to?(:call)
    return hash_duration_for(job) if @durations.is_a?(Hash)

    @durations
  end

  def hash_duration_for(job)

    keys = [
      job,
      job.id,
      job.name,
      job_type(job),
      job_type(job).to_s,
      job.class,
      job.class.name
    ].compact

    key = keys.find { |key| @durations.key?(key) }

    fail ArgumentError.new('no duration given') if key.nil?

    @durations[key]
  end

  def job_type(job)

    case job
    when Rufus::Scheduler::IntervalJob then :interval
    when Rufus::Scheduler::EveryJob then :every
    when Rufus::Scheduler::CronJob then :cron
    end
  end

  def scan

    events = []

    @intervals.each do |start, finish, job|

      next if finish <= @from || start >= @to

      start_event = start > @from ? start : @from
      end_event = finish < @to ? finish : @to

      events << [ start_event, 1, job ]
      events << [ end_event, -1, job ]
    end

    return {} if events.empty?

    events.sort_by! { |time, delta, _| [ time.to_f, delta ] }

    active = Hash.new(0)
    windows = []
    peak = 0
    current_time = @from
    grouped_events(events).each do |time, group|

      if time > current_time
        peak = record_window(windows, peak, current_time, time, active)
      end

      group.each { |_, delta, job| active[job] += delta }
      current_time = time
    end

    if current_time < @to
      peak = record_window(windows, peak, current_time, @to, active)
    end

    peak_windows = windows.select { |window| window[:concurrency] == peak }
    peak_windows = merge_adjacent_windows(peak_windows)

    {
      peak_concurrency: peak,
      peak_windows: peak_windows
    }
  end

  def grouped_events(events)

    events.chunk { |time, _, _| time.to_f }.collect do |_, group|
      [ group.first.first, group ]
    end
  end

  def record_window(windows, peak, start_time, end_time, active)

    concurrency = active.values.reduce(0, :+)

    if concurrency > 0

      window = {
        start_time: start_time,
        end_time: end_time,
        duration: end_time.to_f - start_time.to_f,
        concurrency: concurrency,
        jobs: active_jobs(active)
      }

      windows << window
      peak = concurrency if concurrency > peak
    end

    peak
  end

  def active_jobs(active)

    active
      .select { |_, count| count > 0 }
      .keys
      .sort_by { |job| job.id }
  end

  def merge_adjacent_windows(windows)

    windows.each_with_object([]) do |window, merged|

      previous = merged.last

      if previous &&
         previous[:end_time].to_f == window[:start_time].to_f &&
         previous[:jobs] == window[:jobs]
        previous[:end_time] = window[:end_time]
        previous[:duration] += window[:duration]
      else
        merged << window
      end
    end
  end

  def to_time(value)

    return value if value.is_a?(Rufus::Scheduler::EoTime)

    Rufus::Scheduler.parse_at(value)
  end
end
