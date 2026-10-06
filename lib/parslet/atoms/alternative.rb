
# Alternative during matching. Contains a list of parslets that is tried each
# one in turn. Only fails if all alternatives fail. 
#
# Example: 
# 
#   str('a') | str('b')   # matches either 'a' or 'b'
#
class Parslet::Atoms::Alternative < Parslet::Atoms::Base
  attr_reader :alternatives
  
  # Constructs an Alternative instance using all given parslets in the order
  # given. This is what happens if you call '|' on existing parslets, like 
  # this: 
  #
  #   str('a') | str('b')
  #
  def initialize(*alternatives)
    super()
    
    @alternatives = alternatives
  end

  #---
  # Don't construct a hanging tree of Alternative parslets, instead store them
  # all here. This reduces the number of objects created.
  #+++
  def |(parslet)
    self.class.new(*@alternatives + [parslet])
  end

  def has_cut?
    return @has_cut if defined?(@has_cut)
    @has_cut = alternatives.any? { |a| a.has_cut? }
  end

  def error_msg
    @error_msg ||= "Expected one of #{alternatives.inspect}"
  end

  def try(source, context, consume_all)
    errors = []

    context.push_cut_frame
    alternatives.each do |a|
      success, value = result = a.apply(source, context, consume_all)
      return result if success

      # A commit point was crossed while trying this alternative. The
      # failure is final for this choice: don't try the remaining
      # alternatives and propagate the failure as is.
      return result if context.cut_committed?

      # Aggregate all errors
      errors << value
    end

    # If we reach this point, all alternatives have failed. 
    context.err(self, source, error_msg, errors)
  ensure
    context.pop_cut_frame
  end

  precedence ALTERNATE
  def to_s_inner(prec)
    alternatives.map { |a| a.to_s(prec) }.join(' / ')
  end
end
