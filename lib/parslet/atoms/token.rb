# Matches one lexical token by token type and an optional value predicate.
#
# Example:
#
#   token(:number) { |value| value > 0 }
#
class Parslet::Atoms::Token < Parslet::Atoms::Base
  attr_reader :type
  attr_reader :condition

  def initialize(type=nil, &condition)
    super()

    @type = type
    @condition = condition
  end

  def error_msgs
    @error_msgs ||= {
      premature: 'Premature end of token input',
      failed: "Expected #{description}, but got "
    }
  end

  def try(source, context, consume_all)
    unless source.respond_to?(:current_token)
      return context.err(self, source, "Token atoms require token input")
    end

    return context.err(self, source, error_msgs[:premature]) \
      if source.chars_left < 1

    token = source.current_token

    if matches?(token)
      return succ(source.consume(1))
    end

    error_pos = source.pos
    context.err_at(
      self,
      source,
      "#{error_msgs[:failed]}#{token.inspect}",
      error_pos)
  end

  def to_s_inner(prec)
    "token(#{description})"
  end

private

  def matches?(token)
    matches_type?(token.type) && matches_value?(token.value, token)
  end

  def matches_type?(token_type)
    return token_type == type if type.is_a?(Array)
    type.nil? || type === token_type
  end

  def matches_value?(value, token)
    return true if condition.nil?

    if condition.arity == 1
      condition.call(value)
    else
      condition.call(value, token)
    end
  end

  def description
    type_description = type.nil? ? "any token" : type.inspect
    condition ? "#{type_description} matching a value condition" : type_description
  end
end
