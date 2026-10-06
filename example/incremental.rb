# Demonstrates incremental parsing: a stateful session reparses a
# document after each edit, reusing memoized results that the edit could
# not influence. For every step, the incremental result is checked
# against a full reparse, and cache statistics show how much work was
# avoided -- no timing involved.
#
# Run with: ruby example/incremental.rb

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'parslet'

class RulesFileParser < Parslet::Parser
  rule(:space)  { match('\\s').repeat(1) }
  rule(:space?) { space.maybe }
  rule(:ident)  { match('[a-z_]').repeat(1) }
  rule(:number) { match('[0-9]').repeat(1) }
  rule(:string) { str('"') >> (str('"').absent? >> any).repeat >> str('"') }
  rule(:value)  { string | number | ident }
  rule(:rule_line) do
    ident.as(:name) >> space? >> str('=') >> space? >>
      value.as(:value) >> str(';')
  end
  rule(:line) { rule_line.as(:rule) }
  rule(:file) { (space? >> line).repeat >> space? }
  root(:file)
end

def replace_first(session, anchor, by)
  index = session.text.index(anchor) or raise "anchor #{anchor.inspect} missing"
  session.edit(index, index + anchor.size, by)
end

TEXT = <<-'TEXT'
alpha = 1;
beta = "two";
gamma = ninety;
delta = 4;
epsilon = "five";
TEXT

# A fixed script of insertions, deletions and replacements.
SCRIPT = [
  ['replace a number (substitution)', ->(s) { replace_first(s, 'alpha = 1;', 'alpha = 42;') }],
  ['insert a line in the middle',     ->(s) { replace_first(s, 'beta', "mid = 3;\nbeta") }],
  ['delete that line again',          ->(s) { replace_first(s, "mid = 3;\n", '') }],
  ['append a line at end of input',   ->(s) { s.edit(s.text.size, s.text.size, "zeta = 6;\n") }],
  ['insert a line at start of input', ->(s) { s.edit(0, 0, "zero = 0;\n") }],
  ['replace a value by a longer one', ->(s) { replace_first(s, 'delta = 4;', 'delta = "four";') }],
  ['introduce multibyte characters',  ->(s) { replace_first(s, '"five"', '"fünf"') }],
  ['break the syntax (parse fails)',  ->(s) { replace_first(s, 'gamma =', 'gamma ') }],
  ['repair the syntax',               ->(s) { replace_first(s, 'gamma  ', 'gamma = ') }],
  ['delete the final newline',        ->(s) { s.edit(s.text.size - 1, s.text.size, '') }],
  ['restore the final newline',       ->(s) { s.edit(s.text.size, s.text.size, "\n") }],
]

parser = RulesFileParser.new
session = Parslet::Incremental::Session.new(parser, TEXT)

def checked_parse(session, parser)
  incremental =
    begin
      session.parse
    rescue Parslet::ParseFailed => error
      error
    end
  full =
    begin
      parser.parse(session.text)
    rescue Parslet::ParseFailed => error
      error
    end

  same =
    if full.is_a?(Parslet::ParseFailed)
      incremental.is_a?(Parslet::ParseFailed) &&
        incremental.message == full.message
    else
      !incremental.is_a?(Parslet::ParseFailed) &&
        incremental.inspect == full.inspect
    end
  raise "incremental result diverges from full parse!" unless same

  incremental
end

checked_parse(session, parser)

puts format('%-34s %6s %7s %7s %7s %11s %8s  %s',
  'edit', 'hits', 'misses', 'full', 'saved', 'invalidated', 'shifted', 'result')
puts '-' * 100

SCRIPT.each do |description, edit|
  session.reset_stats!
  edit.call(session)
  result = checked_parse(session, parser)
  stats = session.stats

  fresh = Parslet::Incremental::Session.new(parser, session.text)
  begin
    fresh.parse
  rescue Parslet::ParseFailed
    # baseline misses still recorded
  end
  full_misses = fresh.stats[:misses]

  saved = (full_misses - stats[:misses]) * 100.0 / full_misses
  outcome = result.is_a?(Parslet::ParseFailed) ? 'ParseFailed (same position)' : 'ok'

  puts format('%-34s %6d %7d %7d %6.1f%% %11d %8d  %s',
    description, stats[:hits], stats[:misses], full_misses, saved,
    stats[:invalidated], stats[:shifted], outcome)
end

puts '-' * 100
puts 'Every incremental result (including failure positions) was verified'
puts 'to be identical to a full reparse of the edited text.'
