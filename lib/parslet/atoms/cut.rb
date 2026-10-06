# A commit point (a 'cut'). 
#
# A cut always matches the empty input. Once it has been reached while
# evaluating one alternative of an {Atoms::Alternative}, that alternative is
# committed: if it fails later on, the remaining alternatives are not tried
# and the failure of the committed alternative is reported directly. 
#
# A cut commits only the choice it belongs to (the innermost enclosing
# alternative). Cuts reached while speculatively matching inside a repetition
# (including +.maybe+), a positive/negative lookahead or a failed repetition
# iteration cannot leak past those boundaries. 
#
# Example: 
#
#   (str('include') >> str(' ') >> cut >> filename) | identifier
#
# Once 'include ' has been seen, a failure in +filename+ will be reported at
# that point instead of falling back to +identifier+. 
#
# Cuts are never cached (see {Base#cached?}); the side effect of committing a
# choice belongs to the parse in which it happens. 
#
class Parslet::Atoms::Cut < Parslet::Atoms::Base
  def try(source, context, consume_all)
    context.cut!
    succ(nil)
  end

  # Cuts change parser state (the committed choice), so they must run on every
  # application and cannot be memoized. 
  def cached?
    false
  end
  
  precedence LOOKAHEAD
  def to_s_inner(prec)
    "\u2191"       # up arrow: the cut operator
  end
end
