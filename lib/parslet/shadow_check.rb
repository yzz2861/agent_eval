# Searches a bounded input space for inputs on which an ordered choice
# (Parslet::Atoms::Alternative) shadows one of its later branches: an
# earlier branch matches first, so the later branch is never tried, even
# though it would have matched the same input.
#
# Parslet alternatives are an /ordered/ choice: branches are tried left to
# right and the first match wins. Putting a wide branch in front of a
# narrower one (an identifier rule in front of a keyword, say) makes the
# narrow branch unreachable. This tool produces concrete witness inputs
# for such shadowing, restricted to a finite alphabet and a maximum input
# length.
#
# The check is deliberately bounded:
#
# * Only inputs over +alphabet+ with up to +max_length+ characters are
#   tried. Finding no witness means none exists inside that space; it does
#   NOT prove the grammar free of shadowing.
# * Lookahead and recursion are handled by running the real parslet atoms,
#   so they behave exactly as they do during an actual parse. Inputs that
#   hit runaway recursion (left recursion) are reported as unknown.
# * Parslet::Atoms::Dynamic atoms evaluate arbitrary code at parse time
#   and cannot be analysed reliably. Branches containing one are reported
#   as analysis boundaries; inputs whose outcome depends on them are
#   listed as unknown instead of being guessed at.
#
# Example:
#
#   choice = match['a-z'].repeat(1) | str('if')
#   report = Parslet::ShadowCheck.check(choice, alphabet: 'fix', max_length: 2)
#   puts report
#
class Parslet::ShadowCheck
  # Safety cap on the number of inputs enumerated, so that a careless
  # alphabet/length combination doesn't turn into an accidental
  # denial-of-service against your own machine.
  DEFAULT_MAX_INPUTS = 100_000

  # A branch of the choice that matched a given input, together with the
  # number of characters it consumed.
  #
  class BranchMatch
    attr_reader :index, :atom, :consumed

    def initialize(index, atom, consumed)
      @index = index
      @atom = atom
      @consumed = consumed
    end

    def to_s
      "branch #{index} (#{atom.inspect}) consumes #{consumed} char(s)"
    end
  end

  # A concrete input on which an earlier branch of the choice shadows one
  # or more later branches.
  #
  class Witness
    # The input string exhibiting the shadowing.
    attr_reader :input
    # BranchMatch of the earliest branch that matches (the one the real
    # parser will use).
    attr_reader :winner
    # Array of BranchMatch for later branches that would also match, but
    # are never reached.
    attr_reader :shadowed

    def initialize(input, winner, shadowed)
      @input = input
      @winner = winner
      @shadowed = shadowed
    end

    def to_s
      lines = ["input #{input.inspect}:"]
      lines << "  #{winner} -- ordered choice stops here"
      shadowed.each do |match|
        lines << "  #{match} -- would match, but is never reached"
      end
      lines.join("\n")
    end
  end

  # An input that could not be classified, because analysis hit a
  # boundary: a dynamic atom or runaway (left) recursion.
  #
  class Unknown
    attr_reader :input, :reason

    def initialize(input, reason)
      @input = input
      @reason = reason
    end

    def to_s
      "input #{input.inspect}: unknown (#{reason})"
    end
  end

  # The result of a ShadowCheck run.
  #
  class Report
    attr_reader :choice, :alphabet, :max_length, :inputs_examined,
      :witnesses, :unknowns, :boundaries

    def initialize(choice, alphabet, max_length, inputs_examined,
        witnesses, unknowns, boundaries)
      @choice = choice
      @alphabet = alphabet
      @max_length = max_length
      @inputs_examined = inputs_examined
      @witnesses = witnesses
      @unknowns = unknowns
      @boundaries = boundaries
    end

    # True if at least one shadowing witness was found.
    #
    def found?
      !witnesses.empty?
    end

    # Re-runs the real parser on the input of a witness and cross-checks
    # the analysis: the whole choice node must match and consume exactly
    # what the winning branch consumed, and every shadowed branch must
    # still match on its own. Returns a Recheck; see Recheck#consistent?.
    #
    def recheck(witness)
      input = witness.respond_to?(:input) ? witness.input : witness

      source = Parslet::Source.new(input)
      context = Parslet::Atoms::Context.new(nil)
      success, _ = choice.apply(source, context, false)
      choice_consumed = success ? source.pos.charpos : nil

      shadowed_consumed =
        if witness.respond_to?(:shadowed)
          witness.shadowed.map { |match|
            Parslet::ShadowCheck.probe(match.atom, input)
          }
        else
          []
        end

      Recheck.new(
        input,
        choice_consumed,
        witness.respond_to?(:winner) ? witness.winner.consumed : nil,
        shadowed_consumed)
    end

    def to_s
      lines = []
      lines << "Shadow check of #{choice.inspect}"
      lines << "  alphabet: #{alphabet.inspect}, max length: #{max_length}, " \
        "#{inputs_examined} input(s) examined"

      boundaries.each do |boundary|
        lines << "  boundary: #{boundary}"
      end

      if found?
        lines << "  #{witnesses.size} shadowing witness(es) found:"
        witnesses.each do |witness|
          lines << witness.to_s.gsub(/^/, '    ')
        end
      else
        lines << "  no shadowing witness found in this bounded space"
      end

      unless unknowns.empty?
        lines << "  #{unknowns.size} input(s) could not be classified:"
        unknowns.each do |unknown|
          lines << "    #{unknown}"
        end
      end

      lines << "  note: results are bounded to the alphabet and length " \
        "above; finding no witness here does not prove the grammar " \
        "unambiguous."
      lines.join("\n")
    end
  end

  # Outcome of cross-checking a witness against the real parser. See
  # Report#recheck.
  #
  class Recheck
    attr_reader :input, :choice_consumed, :winner_consumed, :shadowed_consumed

    def initialize(input, choice_consumed, winner_consumed, shadowed_consumed)
      @input = input
      @choice_consumed = choice_consumed
      @winner_consumed = winner_consumed
      @shadowed_consumed = shadowed_consumed
    end

    # True if the real parser confirms the analysis for this input.
    #
    def consistent?
      !choice_consumed.nil? &&
        choice_consumed == winner_consumed &&
        shadowed_consumed.all? { |consumed| consumed.is_a?(Integer) }
    end

    def to_s
      "recheck of #{input.inspect}: choice consumes " \
        "#{choice_consumed.inspect} char(s) (analysis said " \
        "#{winner_consumed.inspect}) -- " \
        "#{consistent? ? 'consistent' : 'INCONSISTENT'}"
    end
  end

  # Checks the given ordered choice node for shadowed branches.
  #
  # @param choice [Parslet::Atoms::Alternative] the choice node to check;
  #   a Parslet::Atoms::Entity (a rule) wrapping one is unwrapped first
  # @param alphabet [Array<String>, String] characters that enumerated
  #   inputs are built from
  # @param max_length [Integer] maximum input length
  # @param max_inputs [Integer] safety cap on the number of inputs
  #   enumerated (default DEFAULT_MAX_INPUTS)
  # @return [Report]
  #
  def self.check(choice, alphabet:, max_length:, max_inputs: DEFAULT_MAX_INPUTS)
    new(alphabet, max_length, max_inputs).check(choice)
  end

  def initialize(alphabet, max_length, max_inputs=DEFAULT_MAX_INPUTS)
    @alphabet =
      case alphabet
      when String then alphabet.each_char.to_a
      else alphabet.to_a
      end

    unless @alphabet.all? { |token| token.is_a?(String) && !token.empty? }
      raise ArgumentError,
        "Alphabet entries must be non-empty strings, got #{@alphabet.inspect}."
    end

    @max_length = max_length
    @max_inputs = max_inputs
  end

  def check(choice)
    choice = choice.parslet while choice.is_a?(Parslet::Atoms::Entity)

    unless choice.is_a?(Parslet::Atoms::Alternative)
      raise ArgumentError,
        "ShadowCheck checks ordered choice nodes " \
        "(Parslet::Atoms::Alternative), got #{choice.class}."
    end

    total_inputs = (0..@max_length).inject(0) { |sum, length|
      sum + @alphabet.size**length
    }
    if total_inputs > @max_inputs
      raise ArgumentError,
        "Refusing to enumerate #{total_inputs} inputs (max_inputs: " \
        "#{@max_inputs}). Shrink the alphabet or max_length, or pass a " \
        "larger :max_inputs if you really mean it."
    end

    alternatives = choice.alternatives

    # Branches containing dynamic atoms cannot be analysed reliably; mark
    # them as boundaries up front.
    opaque = alternatives.map { |alternative| opaque_atoms(alternative) }
    boundaries = []
    opaque.each_with_index do |found, index|
      next if found.empty?
      boundaries << "branch #{index} contains #{found.first.inspect}; " \
        "analysis stops at this boundary"
    end

    witnesses = []
    unknowns = []
    inputs_examined = 0

    each_input do |input|
      inputs_examined += 1

      outcomes = alternatives.each_with_index.map { |alternative, index|
        if opaque[index].empty?
          self.class.probe(alternative, input)
        else
          :unknown
        end
      }

      unknown_indexes = outcomes.each_index.select { |i|
        outcomes[i] == :unknown
      }
      unless unknown_indexes.empty?
        reasons = unknown_indexes.map { |i|
          opaque[i].empty? ?
            "branch #{i} hit runaway recursion" :
            "branch #{i} contains a dynamic atom"
        }
        unknowns << Unknown.new(input, reasons.join('; '))
        next
      end

      winner_index = outcomes.index { |outcome| outcome.is_a?(Integer) }
      next unless winner_index

      shadowed = (winner_index + 1...alternatives.size).select { |index|
        outcomes[index].is_a?(Integer)
      }
      next if shadowed.empty?

      witnesses << Witness.new(
        input,
        BranchMatch.new(winner_index, alternatives[winner_index],
          outcomes[winner_index]),
        shadowed.map { |index|
          BranchMatch.new(index, alternatives[index], outcomes[index])
        })
    end

    Report.new(choice, @alphabet, @max_length, inputs_examined,
      witnesses, unknowns, boundaries)
  end

  # Applies a single atom to the input (prefix match) using the real
  # parslet machinery. Returns the number of characters consumed,
  # :no_match or :unknown (runaway recursion).
  #
  def self.probe(atom, input)
    source = Parslet::Source.new(input)
    context = Parslet::Atoms::Context.new(nil)
    success, _ = atom.apply(source, context, false)
    return :no_match unless success

    source.pos.charpos
  rescue SystemStackError
    :unknown
  end

  private

  def each_input
    yield ''
    1.upto(@max_length) do |length|
      @alphabet.repeated_permutation(length) do |permutation|
        yield permutation.join
      end
    end
  end

  # Collects dynamic atoms in the subtree of +atom+, resolving entities
  # (rules) while guarding against recursive cycles.
  #
  def opaque_atoms(atom, seen={})
    return [] if seen[atom.object_id]
    seen[atom.object_id] = true

    found = []
    found << atom if atom.is_a?(Parslet::Atoms::Dynamic)
    children_of(atom).each do |child|
      found.concat(opaque_atoms(child, seen))
    end
    found
  end

  def children_of(atom)
    case atom
    when Parslet::Atoms::Alternative
      atom.alternatives
    when Parslet::Atoms::Sequence
      atom.parslets
    when Parslet::Atoms::Repetition
      [atom.parslet]
    when Parslet::Atoms::Lookahead
      [atom.bound_parslet]
    when Parslet::Atoms::Named, Parslet::Atoms::Ignored, Parslet::Atoms::Capture
      [atom.parslet]
    when Parslet::Atoms::Entity
      [atom.parslet]
    when Parslet::Atoms::Scope
      [atom.block.call]
    when Parslet::Atoms::Infix
      [atom.element] + atom.operations.map(&:first)
    when Parslet::Parser
      [atom.root]
    else
      []
    end
  end
end

