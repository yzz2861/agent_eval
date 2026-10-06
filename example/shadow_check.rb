# Demonstrates Parslet::ShadowCheck on the classic keyword vs identifier
# conflict: an identifier rule placed in front of a keyword makes the
# keyword unreachable. Swapping the branches moves the shadow instead of
# removing it; only a keyword with a proper boundary guard leaves just
# the intended overlaps.

$:.unshift File.dirname(__FILE__) + '/../lib'

require 'parslet'

include Parslet

identifier = match('[a-z]') >> match('[a-z0-9_]').repeat
keyword    = str('if')
guarded    = str('if') >> match('[a-z0-9_]').absent?

def show(title, choice)
  puts title
  report = Parslet::ShadowCheck.check(choice, alphabet: %w[i f x], max_length: 2)
  puts report.to_s.gsub(/^/, '  ')
  if report.found?
    puts '  recheck: ' + report.recheck(report.witnesses.first).to_s
  end
  puts
end

show '1) identifier | keyword (wide branch first):',
  identifier | keyword

show '2) keyword | identifier (branches swapped):',
  keyword | identifier

show "3) (keyword + boundary guard) | identifier:",
  guarded | identifier

