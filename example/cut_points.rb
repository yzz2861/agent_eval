$:.unshift File.dirname(__FILE__) + "/../lib"

require 'parslet'

# A commit point (cut, written as #cut or the \u2191 atom) says: "once we got
# here, we know which kind of statement this is - do not try the other
# alternatives of *this* choice anymore."
#
# Run me with:
#   ruby example/cut_points.rb

class ConfigParser < Parslet::Parser
  root :statement

  rule(:statement) { include_directive | identifier }

  # `include "foo.rb"` - the moment the keyword has been seen, the input
  # cannot be an identifier anymore. The cut is placed right after the
  # keyword, in the branch of the top-level choice it commits.
  rule(:include_directive) do
    str('include') >>
    str(' ').cut >>
    str('"') >>
    filename.as(:file) >>
    str('"')
  end

  rule(:filename)   { match('[^"\r\n]').repeat(1) }
  rule(:identifier) { match['[:alnum:]'].repeat(1).as(:name) }
end

# Same grammar, but without the cut. It exists only to show the difference
# in the error tree for one and the same broken input.
class ConfigParserWithoutCut < ConfigParser
  rule(:include_directive) do
    str('include') >>
    str(' ') >>
    str('"') >>
    filename.as(:file) >>
    str('"')
  end
end

broken = 'include '   # keyword seen, file name missing

def error_tree(parser, input)
  parser.parse(input)
rescue Parslet::ParseFailed => error
  error.parse_failure_cause.ascii_tree
end

def show(title, parser, input)
  puts "=" * 72
  puts title
  puts "=" * 72
  parser.parse(input)
rescue Parslet::ParseFailed => error
  puts error.parse_failure_cause.ascii_tree
end

show 'WITHOUT a cut: every alternative is still tried',
     ConfigParserWithoutCut.new, broken

show 'WITH a cut: the include directive was committed',
     ConfigParser.new, broken

# ---- parser reuse: the cut state lives in the parse run, not the parser --
puts "=" * 72
puts 'REUSING THE SAME PARSER INSTANCE TWICE'
puts "=" * 72

parser = ConfigParser.new
first  = error_tree(parser, broken)
middle = parser.parse('ordinary').inspect
second = error_tree(parser, broken)

puts "parse of the other branch after a committed failure: #{middle}"
puts "error trees of two runs identical? #{first == second}"
