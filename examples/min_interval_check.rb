#!/usr/bin/env ruby
#
# examples/min_interval_check.rb
#
# A minimal "config center" gate: verifies that each cron entry in a
# YAML config file cannot fire twice within MIN_INTERVAL seconds over
# the next WINDOW seconds (default: one year), without starting any
# scheduler.
#
# Usage:
#   ruby -Ilib examples/min_interval_check.rb [config.yml]
#
# Config format (YAML), see examples/crons.yml:
#
#   - name: cache-warmer
#     cron: "*/30 * * * * *"
#   - name: nightly-report
#     cron: "0 3 * * * America/New_York"
#
# Window inclusion rule: [now, now + WINDOW), left-closed, right-open.
#
# Exit status: 0 when every entry passes, 1 otherwise. A budget
# exhaustion or an unparsable/never-firing cron counts as a failure
# (fail closed), never as a pass.

require 'yaml'
require 'fugit'

MIN_INTERVAL = 30            # seconds
WINDOW = 365 * 24 * 3600     # one year, in seconds
BUDGET = 2_000_000           # trigger examinations per entry

path = ARGV[0] || File.join(__dir__, 'crons.yml')
entries = YAML.load_file(path)

from = Time.now
to = from + WINDOW
failures = 0

entries.each do |entry|

  name = entry['name'] || entry['cron'].to_s

  cron =
    begin
      Fugit::Cron.do_parse(entry['cron'].to_s)
    rescue => e
      puts format('ERROR  %-24s unparsable cron %p (%s)', name, entry['cron'], e.message)
      failures += 1
      next
    end

  verdict =
    begin
      cron.verify_min_interval(from, to, MIN_INTERVAL, budget: BUDGET)
    rescue => e
      # e.g. a cron that can never fire ("0 0 30 2 *", Feb 30th)
      puts format('ERROR  %-24s %s: %s', name, e.class, e.message)
      failures += 1
      next
    end

  case
  when verdict.ok?
    puts format(
      'PASS   %-24s no gap below %ds in [%s, %s) (%d triggers checked)',
      name, MIN_INTERVAL, from, to, verdict.checked)
  when verdict.violation?
    a, b = verdict.pair
    puts format(
      'FAIL   %-24s gap of %ds between %s and %s',
      name, verdict.delta,
      a.strftime('%F %T %z'), b.strftime('%F %T %z'))
    failures += 1
  else
    puts format(
      'BUDGET %-24s window not fully checked (%d triggers, budget %d); NOT a pass',
      name, verdict.checked, verdict.budget)
    failures += 1
  end
end

exit(failures.zero? ? 0 : 1)
