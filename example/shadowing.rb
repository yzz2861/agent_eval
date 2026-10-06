# Demonstrates Parslet::Shadowing on the classic keyword vs. identifier
# conflict, and shows how the witnesses change when the branches are
# swapped.
#
# Run with: ruby example/shadowing.rb

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'parslet'

class KeywordFirstParser < Parslet::Parser
  rule(:keyword)    { str('if') }
  rule(:identifier) { match('[a-z]').repeat(1) }
  rule(:token)      { keyword.as(:keyword) | identifier.as(:identifier) }
  rule(:statement)  { token >> str(';') }
  root(:statement)
end

class IdentifierFirstParser < Parslet::Parser
  rule(:keyword)    { str('if') }
  rule(:identifier) { match('[a-z]').repeat(1) }
  rule(:token)      { identifier.as(:identifier) | keyword.as(:keyword) }
  rule(:statement)  { token >> str(';') }
  root(:statement)
end

ALPHABET = %w(i f x)

puts '=' * 72
puts 'Order 1: keyword | identifier'
puts '=' * 72
report = Parslet::Shadowing.check(
  KeywordFirstParser.new.token,
  alphabet: ALPHABET, max_length: 3)
puts report
report.verify!
puts
puts 'All witnesses reproduce against the real atoms.'

# The same witness in the real, full parser: inside the sequence
# token >> ';', the keyword branch wins the prefix 'if' of 'ifx;' and the
# sequence then fails on 'x;' - the identifier branch is never retried.
begin
  KeywordFirstParser.new.parse('ifx;')
rescue Parslet::ParseFailed => failure
  puts
  puts 'Real parser on "ifx;" (keyword first):'
  puts "  Parslet::ParseFailed: #{failure.message.lines.first}"
end
puts "Real parser on 'if;' (keyword first): " +
  KeywordFirstParser.new.parse('if;').inspect

puts
puts '=' * 72
puts 'Order 2: identifier | keyword (swapped)'
puts '=' * 72
report = Parslet::Shadowing.check(
  IdentifierFirstParser.new.token,
  alphabet: ALPHABET, max_length: 3)
puts report
report.verify!
puts
puts 'All witnesses reproduce against the real atoms.'

# With the swapped order, 'ifx;' parses fine, but 'if;' is now silently an
# identifier - the keyword branch has become dead.
puts
puts "Real parser on 'ifx;' (identifier first): " +
  IdentifierFirstParser.new.parse('ifx;').inspect
puts "Real parser on 'if;' (identifier first): " +
  IdentifierFirstParser.new.parse('if;').inspect +
  ' (keyword branch never reached)'
