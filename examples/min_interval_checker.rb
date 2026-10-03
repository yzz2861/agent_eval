#!/usr/bin/env ruby

# This is a configuration-time checker. It never starts a scheduler.

require 'fugit'
require 'time'

def same_time_next_year(time)

  Time.utc(
    time.year + 1,
    time.month,
    [ time.day, Time.utc(time.year + 1, time.month).day ].min,
    time.hour,
    time.min,
    time.sec)
end

def check_cron_config(entry)

  cron = Fugit.do_parse_cron(entry.fetch('cron'))
  min_interval = entry.fetch('min_interval_seconds', 30)
  budget = entry.fetch('occurrence_budget', 1_100_000)

  window_start =
    if entry.key?('window_start')
      Time.parse(entry['window_start'])
    else
      Time.now.utc
    end

  window_end =
    if entry.key?('window_end')
      Time.parse(entry['window_end'])
    else
      same_time_next_year(window_start)
    end

  result = cron.verify_min_interval(
    min_interval,
    window_start,
    window_end,
    budget: budget)

  case result.status
  when :passed
    puts "PASS #{entry['cron']} (checked #{result.checked} occurrence(s))"
  when :counterexample
    warn(
      "REJECT #{entry['cron']}: " \
      "#{result.previous_time.utc.iso8601} -> " \
      "#{result.current_time.utc.iso8601} is " \
      "#{result.interval}s, less than #{result.min_interval}s")
  when :budget_exhausted
    warn(
      "REJECT #{entry['cron']}: budget exhausted after " \
      "#{result.checked} occurrence(s); verification is inconclusive")
  end

  result.passed?
end

entries = [
  {
    'cron' => '0 0 * * * UTC',
    'window_start' => '2026-10-03T00:00:00Z',
    'window_end' => '2027-10-03T00:00:00Z' },
  {
    'cron' => '0,29 * * * * * UTC',
    'window_start' => '2026-10-03T00:00:00Z',
    'window_end' => '2027-10-03T00:00:00Z' }
]

exit(entries.all? { |entry| check_cron_config(entry) } ? 0 : 1)
