class Parslet::Atoms::Token < Parslet::Atoms::Base
  UNSET = Object.new.freeze

  attr_reader :type

  def initialize(type, expected_value=UNSET, &condition)
    super()

    @type = type
    @conditions = []
    @conditions << proc { |token| token.value == expected_value } unless expected_value.equal?(UNSET)
    @conditions << condition if condition
  end

  def try(source, context, consume_all)
    unless source.kind_of?(Parslet::TokenSource)
      return context.err(self, source, "Token atom can only be applied to a Parslet::TokenSource.")
    end

    token = source.current_token

    return context.err(self, source, "Premature end of input") unless token
    return succ(source.consume_token) if token.type == type && matches_value?(token)

    unless token.type == type
      return context.err_at(
        self,
        source,
        "Expected token #{type.inspect}, but got #{token.type.inspect} (#{token.lexeme.inspect})",
        source.pos)
    end

    context.err_at(
      self,
      source,
      "Expected token #{type.inspect} matching its value condition, but got #{token.value.inspect} (#{token.lexeme.inspect})",
      source.pos)
  end

  def to_s_inner(prec)
    "token(#{type.inspect})"
  end

  private

  def matches_value?(token)
    @conditions.all? { |condition| condition.call(token) }
  end
end
