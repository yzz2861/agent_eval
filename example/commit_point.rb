$:.unshift File.dirname(__FILE__) + "/../lib"

require 'parslet'

# A tiny configuration language with an `include <file>` directive. The
# directive can be defined with or without a commit point (cut) right
# after the `include ` keyword: once the keyword has been seen, the
# parser commits to the directive and a missing file name is reported
# as such, instead of backtracking into the other statement kinds and
# producing an unrelated error.
#
class ConfigParser < Parslet::Parser
  def initialize(commit)
    @commit = commit
    super()
  end

  rule(:space)     { match[' \t'].repeat(1) }
  rule(:key)       { match['a-z_'].repeat(1) }
  rule(:value)     { match['0-9'].repeat(1) }
  rule(:filename)  { match['\w'].repeat(1) >> (str('.') >> match['\w'].repeat(1)).repeat }

  rule(:assignment) { key.as(:key) >> str('=') >> value.as(:value) }
  rule(:directive)  {
    head = str('include') >> space
    head = head >> cut if @commit
    head >> filename.as(:file)
  }
  rule(:statement)  { (directive | assignment) >> match['\n'].maybe }
  root(:statement)
end

def error_tree(parser, input)
  parser.parse(input)
  '<no error>'
rescue Parslet::ParseFailed => failure
  failure.parse_failure_cause.ascii_tree
end

truncated = "include \n"

puts %{Truncated input: #{truncated.inspect}}
puts
puts '--- commit point OFF: the parser backtracks into `assignment` and'
puts '    complains about a missing "=" - an unrelated error.'
puts error_tree(ConfigParser.new(false), truncated)
puts '--- commit point ON: the choice is committed once `include ` has'
puts '    been seen; the error points at the missing file name.'
puts error_tree(ConfigParser.new(true), truncated)

parser = ConfigParser.new(true)
first  = error_tree(parser, truncated)
valid  = parser.parse("include boot.cfg\n")   # same parser, valid input
second = error_tree(parser, truncated)

puts '--- Same parser instance, truncated input parsed twice with a'
puts '    valid parse in between.'
puts %{valid parse in between still works: #{valid.inspect}}
puts %{no residual commit state (identical error trees): #{first == second}}
