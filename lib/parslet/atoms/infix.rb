# Parses expressions built from a single kind of element and a table of
# operators. Next to binary infix operators (the common case), the table
# can also declare prefix ('-x'), postfix ('x!') and ternary ('x ? y : z')
# operators. All of them live in the same table and combine freely; each
# entry declares its precedence and, where meaningful, its associativity.
#
class Parslet::Atoms::Infix < Parslet::Atoms::Base
  # A normalized entry of the operator table.
  #
  # kind:       :binary, :prefix, :postfix or :ternary
  # atom:       parslet matching the operator token (the opening token for
  #             ternary operators)
  # separator:  parslet matching the token between the middle and the right
  #             subexpression (ternary operators only)
  # precedence: number, higher binds tighter
  # assoc:      :left or :right (binary and ternary operators only)
  #
  Operation = Struct.new(:kind, :atom, :separator, :precedence, :assoc)

  attr_reader :element, :operations, :reducer

  # The default tree producer. Binary and unary operations become
  #   {l: left, o: operator, r: right}
  # where the missing side of a unary operator is nil. Ternary operations
  # become
  #   {l: condition, o: operator, m: middle, s: separator, r: right}
  #
  DEFAULT_REDUCER = lambda { |*args|
    left, op, a, b, c = args

    if args.size == 5
      {l: left, o: op, m: a, s: b, r: c}
    else
      {l: left, o: op, r: a}
    end
  }

  def initialize(element, operations, &reducer)
    super()

    @element = element
    @operations = operations.map { |operation| normalize_operation(operation) }
    @reducer = reducer || DEFAULT_REDUCER
  end

  def try(source, context, consume_all)
    return catch(:error) {
      return succ(
        precedence_climb(source, context, consume_all))
    }
  end

  # A precedence climbing algorithm married to parslet, as described here
  #   http://eli.thegreenplace.net/2012/08/02/parsing-expressions-by-precedence-climbing/
  #
  # The tree is reduced eagerly: as soon as an operator and its operands
  # are complete, the reducer is called. Binary operations reduce as
  # reducer.call(left, op, right); prefix and postfix operations pass nil
  # for the missing side; ternary operations reduce as
  # reducer.call(condition, op, middle, separator, right).
  #
  # @note Error handling in this routine is done by throwing :error and
  #       as a value the error to return to parslet. This avoids cluttering
  #       the recursion logic here with parslet error handling.
  #
  def precedence_climb(source, context, consume_all, current_prec=1)
    left = parse_operand(source, context, consume_all)

    # Loop until we fail on operator matching or until input runs out.
    loop do
      op_pos = source.bytepos
      match = match_operation(source, context, consume_all, current_prec)

      # If no operator could be matched here, one of several cases
      # applies:
      #
      # - end of file
      # - end of expression
      # - syntax error
      #
      # We abort matching the expression here.
      break unless match

      operation, op_match, middle, separator_match = match

      case operation.kind
      when :postfix
        left = reducer.call(left, op_match, nil)
      when :ternary
        right = precedence_climb(
          source, context, consume_all, next_prec(operation))
        left = reducer.call(left, op_match, middle, separator_match, right)
      else # :binary
        right = precedence_climb(
          source, context, consume_all, next_prec(operation))
        left = reducer.call(left, op_match, right)
      end
    end

    return left
  end

  # Parses the operand that starts a (sub)expression: either a prefix
  # operator followed by its operand, or a bare element. A prefix operator
  # parses its operand at its own precedence, so whether '-x ** y' reads
  # as '-(x ** y)' or as '(-x) ** y' depends on the declared precedences
  # alone.
  #
  def parse_operand(source, context, consume_all)
    prefix_operation, op_match = match_prefix(source, context)

    if prefix_operation
      operand = precedence_climb(
        source, context, consume_all, prefix_operation.precedence)
      return reducer.call(nil, op_match, operand)
    end

    # To even begin parsing an expression, there needs to be at least one
    # @element.
    success, value = @element.apply(source, context, false)

    unless success
      throw :error, context.err(self, source, "#{@element.inspect} was expected", [value])
    end

    return flatten(value, true)
  end

  # Matches a prefix operator at the current position. Prefix operators
  # are always allowed where an operand is expected, no matter the current
  # precedence level.
  #
  def match_prefix(source, context)
    @operations.each do |operation|
      next unless operation.kind == :prefix

      success, value = operation.atom.apply(source, context, false)
      return operation, flatten(value, true) if success
    end

    return nil
  end

  # Matches the next continuing operator (binary, postfix or ternary) at
  # the current position. Operators are tried in declaration order, so
  # operators that share a common prefix should be declared longest first.
  # Operators with a precedence below current_prec cannot bind here and
  # are skipped entirely.
  #
  def match_operation(source, context, consume_all, current_prec)
    @operations.each do |operation|
      next if operation.kind == :prefix
      next if operation.precedence < current_prec

      case operation.kind
      when :ternary
        match = match_ternary(source, context, consume_all, operation)
        return match if match
      else
        success, value = operation.atom.apply(source, context, false)
        return operation, flatten(value, true) if success
      end
    end

    return nil
  end

  # Matches a ternary operator: opening token, middle expression and
  # separator token. The middle expression is a full expression of its
  # own, parsed at the lowest precedence level.
  #
  # The match is atomic: if any of the three parts fails, the input is
  # rewound to before the opening token. Operators that share a prefix
  # with the opening token (a postfix '?' versus a ternary '?:', say)
  # thus still get their chance, and no characters are swallowed
  # prematurely.
  #
  def match_ternary(source, context, consume_all, operation)
    op_pos = source.bytepos

    success, op_value = operation.atom.apply(source, context, false)
    return nil unless success

    middle_attempt = catch(:error) {
      [:matched, precedence_climb(source, context, consume_all, 1)]
    }

    sep_success, sep_value =
      if middle_attempt.first == :matched
        operation.separator.apply(source, context, false)
      end

    unless sep_success
      source.bytepos = op_pos
      return nil
    end

    _, middle = middle_attempt
    return operation, flatten(op_value, true), middle, flatten(sep_value, true)
  end

  def next_prec(operation)
    (operation.assoc == :left) ? operation.precedence + 1 : operation.precedence
  end

  # Turns a user supplied operation tuple into an Operation. Recognized
  # forms:
  #
  #   [atom, precedence, :left]                binary infix, left associative
  #   [atom, precedence, :right]               binary infix, right associative
  #   [atom, precedence, :prefix]              prefix unary
  #   [atom, precedence, :postfix]             postfix unary
  #   [[atom, separator], precedence, :left]   ternary, left associative
  #   [[atom, separator], precedence, :right]  ternary, right associative
  #
  def normalize_operation(operation)
    atom, precedence, assoc = operation

    case assoc
    when :left, :right
      if atom.kind_of? Array
        opening, separator = atom
        Operation.new(:ternary, opening, separator, precedence, assoc)
      else
        Operation.new(:binary, atom, nil, precedence, assoc)
      end
    when :prefix, :postfix
      Operation.new(assoc, atom, nil, precedence, nil)
    else
      raise ArgumentError,
        "Unknown operator kind/associativity #{assoc.inspect} in #{operation.inspect}."
    end
  end

  def to_s_inner(prec)
    ops = @operations.map { |operation|
      [operation.atom, operation.separator].
        compact.map(&:inspect).join(' ')
    }.join(', ')
    "infix_expression(#{@element.inspect}, [#{ops}])"
  end
end
