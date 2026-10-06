# A commit point (cut). Matches always, consuming no input. Its effect is
# on failure handling: once the parse has advanced past a commit point, a
# later failure will not backtrack into the remaining alternatives of the
# innermost enclosing choice anymore. The commit only governs that one
# layer of choice; once the choice has been left, the failure turns back
# into an ordinary one.
#
# Boundaries:
# * Sequences, rules (entities), maybe and repetition are transparent:
#   they propagate a committed failure to the enclosing choice instead
#   of absorbing it.
# * Lookahead (present?/absent?) confines commits: speculation inside a
#   lookahead never leaks into the enclosing parse.
# * A commit point without an enclosing choice has no effect.
#
# Example:
#
#   (str('include') >> cut >> filename) | assignment
#
# Once 'include' has been matched, a failure to parse the filename will
# not make the parser try to match 'assignment' anymore.
#
class Parslet::Atoms::Cut < Parslet::Atoms::Base
  def try(source, context, consume_all)
    context.cut!
    succ(nil)
  end

  def has_cut?
    true
  end

  precedence BASE
  def to_s_inner(prec)
    'cut'
  end
end
