# Parses expressions made of a single kind of @element joined together by
# operators of varying precedence, associativity and fixity. The operators
# all live in one table, so a single declaration can combine binary infix
# operations (+, *, **), prefix operations (-x), postfix operations (x!)
# and ternary operations (condition ? yes : no).
#
class Parslet::Atoms::Infix < Parslet::Atoms::Base
  attr_reader :element, :operations, :reducer

  # The four supported fixities. Ternary operators reuse :left/:right
  # (with :right giving the conventional nesting of the C conditional).
  FIXITIES = [:prefix, :postfix, :left, :right]

  def initialize(element, operations, &reducer)
    super()

    @element = element
    @operations = operations.map { |operation| normalize_operation(operation) }
    @default_reducer = reducer.nil?
    @reducer = reducer || method(:default_reduction).to_proc
  end

  def try(source, context, consume_all)
    return catch(:error) {
      return succ(precedence_climb(source, context, consume_all))
    }
  end

  # Validates and normalizes an operation tuple into
  #   [[atoms], precedence, associativity]
  #
  # Binary, prefix and postfix operations use the three-element tuple
  #   [atom, precedence, associativity]
  # with associativity of :left or :right for binary infix operators and
  # :prefix (think -x) or :postfix (think x!) otherwise. Ternary
  # operations (think condition ? yes : no) carry both their opening and
  # their closing atom:
  #   [question_atom, colon_atom, precedence, :right]
  #
  def normalize_operation(operation)
    atom, second, third, fourth = operation

    if fourth
      atoms = [atom, second]
      precedence, associativity = third, fourth
      unless [:left, :right].include?(associativity)
        raise ArgumentError,
          "ternary associativity must be :left or :right"
      end
    else
      atoms = [atom]
      precedence, associativity = second, third
    end

    unless FIXITIES.include?(associativity)
      raise ArgumentError,
        "associativity must be one of #{FIXITIES.map(&:inspect).join(', ')}"
    end

    [atoms, precedence, associativity]
  end

  # A precedence climbing algorithm married to parslet, as described here
  #   http://eli.thegreenplace.net/2012/08/02/parsing-expressions-by-precedence-climbing/
  #
  # @note Error handling in this routine is done by throwing :error and
  #       as a value the error to return to parslet. This keeps the
  #       recursion logic free of parslet error handling.
  #
  def precedence_climb(source, context, consume_all, current_prec=1)
    left = parse_prefix(source, context, current_prec)

    # Loop until we fail on matching a postfix or infix operator or until
    # input runs out.
    loop do
      op_pos = source.bytepos
      matched = match_operation(source, context, :postfix_or_infix)

      # If no operator could be matched here, one of several cases
      # applies:
      #
      # - end of file
      # - end of expression
      # - syntax error
      #
      # We abort matching the expression here.
      break unless matched

      op_match, precedence, associativity, atoms = matched

      unless precedence >= current_prec
        source.bytepos = op_pos
        break
      end

      if associativity == :postfix
        left = reduce_postfix(left, op_match)
      elsif atoms.length == 2
        # Ternary: the question mark has just matched. The middle
        # expression is a full expression starting at precedence 1, as in
        # C, then the closing atom is required, then the right branch is
        # parsed at this operator's binding precedence, which makes the
        # conditional nest to the right when declared :right.
        middle = precedence_climb(source, context, consume_all, 1)

        close_pos = source.bytepos
        close_success, close_value = atoms.last.apply(source, context, false)
        unless close_success
          source.bytepos = close_pos
          throw :error, context.err(
            self, source,
            "#{atoms.last.inspect} was expected", [close_value])
        end

        right = precedence_climb(source, context, consume_all, precedence)
        left = reduce_ternary(
          left, op_match, middle, flatten(close_value, true), right)
      else
        next_prec = (associativity == :left) ? precedence+1 : precedence
        right = precedence_climb(source, context, consume_all, next_prec)
        left = reduce_binary(left, op_match, right)
      end
    end

    left
  end

  # Parses a run of prefix operators whose precedence is at least
  # current_prec and then the operand they apply to. The operand is parsed
  # with a full precedence climb starting at the prefix operator's own
  # precedence, which makes the relation between a prefix minus and
  # exponentiation explicit in the table: a prefix '-' tighter than '**'
  # makes -2**3 parse as (-2)**3, while a looser one makes it parse as
  # -(2**3). A run of equal prefixes stacks to the right.
  #
  def parse_prefix(source, context, current_prec)
    op_pos = source.bytepos
    matched = match_operation(source, context, :prefix)

    if matched && matched[1] >= current_prec
      op_match, precedence = matched
      operand = precedence_climb(source, context, false, precedence)
      return reduce_prefix(op_match, operand)
    end

    source.bytepos = op_pos
    parse_element(source, context)
  end

  # Parses a single @element.
  #
  def parse_element(source, context)
    success, value = @element.apply(source, context, false)
    unless success
      throw :error, context.err(
        self, source, "#{@element.inspect} was expected", [value])
    end

    flatten(value, true)
  end

  # Probes every operation eligible at this position and rewinds the
  # source after each probe, then commits the best match. Because all
  # candidates are tried at the same starting position, operators sharing
  # a prefix (think '?' and '??', or '-' declared both as prefix and as
  # infix) cannot gobble characters prematurely: the longest match wins.
  # Ties are broken by higher precedence, then by fixity (postfix over
  # infix over prefix), and finally by declaration order.
  #
  # Returns nil when nothing matches, otherwise
  #   [op_match, precedence, associativity, atoms]
  # where op_match is the flattened match value and atoms is the list of
  # declared atoms (length 2 for ternary operations).
  #
  def match_operation(source, context, position)
    candidates = []

    @operations.each_with_index do |(atoms, precedence, associativity), order|
      next unless eligible?(associativity, position)

      start_pos = source.bytepos
      # Ternary operations only present their opening atom here; their
      # closing atom is matched after the middle expression has been
      # parsed. So probing and committing concerns atoms.first only, while
      # the full atoms list (length 2) marks the operation as ternary.
      success, value = atoms.first.apply(source, context, false)
      next unless success

      end_pos = source.bytepos
      source.bytepos = start_pos

      candidates << [
        end_pos - start_pos, precedence, fixity_rank(associativity), -order,
        flatten(value, true), atoms, associativity]
    end

    return nil if candidates.empty?

    _, precedence, _, _, op_value, atoms, associativity = best = candidates.max

    # Commit the winning match by consuming exactly what it probed.
    source.bytepos += best.first

    [op_value, precedence, associativity, atoms]
  end

  def eligible?(associativity, position)
    case position
    when :prefix then associativity == :prefix
    when :postfix_or_infix
      [:postfix, :left, :right].include?(associativity)
    end
  end

  def fixity_rank(associativity)
    {postfix: 2, left: 1, right: 1, prefix: 0}.fetch(associativity)
  end

  # Builds a tree node for an operator application. Without a reducer
  # block the node shapes are the default hashes. A block with three
  # required parameters keeps its historical binary meaning exactly and
  # is only invoked for binary operations; a block taking a fixed number
  # of arguments is invoked for the fixities whose arity matches; a block
  # taking variable arguments (+|*args|+) receives every fixity, with the
  # arguments in declared order (op and operand for prefix, operand and
  # op for postfix, and condition, opening op, middle, closing op and
  # right expression for the ternary).
  #
  def reduce(fixity, *args)
    unless @default_reducer
      arity = reducer.arity
      if arity < 0 || arity == args.length
        return reducer.call(*args)
      end
    end

    default_reduction(fixity, *args)
  end

  def default_reduction(fixity, *args)
    case fixity
    when :prefix
      {o: args[0], r: args[1]}
    when :postfix
      {l: args[0], o: args[1]}
    when :binary
      {l: args[0], o: args[1], r: args[2]}
    when :ternary
      {l: args[0], o: args[1], m: args[2], c: args[3], r: args[4]}
    end
  end

  def reduce_prefix(op, operand)
    reduce(:prefix, op, operand)
  end

  def reduce_postfix(operand, op)
    reduce(:postfix, operand, op)
  end

  def reduce_binary(left, op, right)
    reduce(:binary, left, op, right)
  end

  def reduce_ternary(left, open_op, middle, close_op, right)
    reduce(:ternary, left, open_op, middle, close_op, right)
  end

  def to_s_inner(prec)
    ops = @operations.map { |atoms, _, _| atoms.map(&:inspect).join('/') }.join(', ')
    "infix_expression(#{@element.inspect}, [#{ops}])"
  end
end
