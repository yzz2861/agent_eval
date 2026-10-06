# A checker for *shadowed alternatives* in ordered choices.
#
# In PEG-style grammars (which parslet implements), the alternatives of a
# choice are tried in order and the first one that matches wins. A later
# alternative that would also match - maybe even consume more input - is
# never tried. When this happens unintentionally, the later alternative is
# said to be "shadowed" by the earlier one:
#
#   str('if') | match('[a-z]').repeat(1)
#
# On the input "ifx", the first alternative matches and consumes 2
# characters; the second alternative (which would have consumed all 3) is
# never tried.
#
# This module searches for concrete witness inputs that demonstrate such
# shadowing, within a finite alphabet and a maximum input length:
#
#   report = Parslet::Shadowing.check(
#     parser.token.parslet,
#     alphabet: %w(i f x),
#     max_length: 3)
#   puts report
#
# Lookahead and recursive rules are handled with real choice semantics,
# because every candidate input is matched by applying the actual atoms.
# Dynamic atoms (Parslet::Atoms::Dynamic, Parslet::Atoms::Scope) cannot be
# analysed reliably; branches containing them are skipped and reported as
# analysis boundaries.
#
# IMPORTANT: If no witness is found, that only means none exists within the
# searched alphabet and length bound. It does NOT prove that the grammar is
# free of shadowing.
#
module Parslet::Shadowing
  # The outcome of matching one alternative against one input.
  #
  class Branch
    attr_reader :index, :atom, :consumed

    def initialize(index, atom, consumed)
      @index = index
      @atom = atom
      @consumed = consumed
    end

    def to_s
      "branch #{index + 1} (#{atom.inspect}) consumed #{consumed} character(s)"
    end
  end

  # A concrete input on which an earlier alternative wins the ordered choice
  # while a later alternative would also have matched.
  #
  class Witness
    attr_reader :input, :winner, :shadowed

    def initialize(input, winner, shadowed)
      @input = input
      @winner = winner
      @shadowed = shadowed
    end

    # Re-applies the winning and the shadowed alternatives to the witness
    # input using the real parser machinery, and confirms that the consumed
    # lengths are exactly the ones recorded. Returns true if the witness
    # reproduces, raises otherwise.
    #
    def verify
      actual_winner = Parslet::Shadowing.apply_prefix(winner.atom, input)
      unless actual_winner == winner.consumed
        fail "Witness #{input.inspect} does not reproduce: " \
          "winner now consumes #{actual_winner.inspect} instead of #{winner.consumed}."
      end

      shadowed.each do |branch|
        actual = Parslet::Shadowing.apply_prefix(branch.atom, input)
        unless actual == branch.consumed
          fail "Witness #{input.inspect} does not reproduce: " \
            "branch #{branch.index + 1} now consumes #{actual.inspect} " \
            "instead of #{branch.consumed}."
        end
      end

      true
    end

    def to_s
      lines = ["input #{input.inspect}:"]
      lines << "  #{winner}  <- wins (ordered choice)"
      shadowed.each do |branch|
        relation =
          if branch.consumed > winner.consumed
            'shadowed (would consume MORE input)'
          elsif branch.consumed == winner.consumed
            'shadowed (would consume the same amount)'
          else
            'shadowed (would consume less input)'
          end
        lines << "  #{branch}  <- #{relation}"
      end
      lines.join("\n")
    end
  end

  # The result of a shadowing check. See Parslet::Shadowing.check.
  #
  class Report
    attr_reader :witnesses, :boundaries, :alphabet, :max_length,
      :inputs_tested, :truncated

    def initialize(witnesses:, boundaries:, alphabet:, max_length:,
                   inputs_tested:, truncated:)
      @witnesses = witnesses
      @boundaries = boundaries
      @alphabet = alphabet
      @max_length = max_length
      @inputs_tested = inputs_tested
      @truncated = truncated
    end

    # True if at least one shadowing witness was found.
    #
    def found?
      !witnesses.empty?
    end

    # Re-verifies every witness against the real atoms. Returns true when
    # all witnesses reproduce.
    #
    def verify!
      witnesses.each(&:verify)
      true
    end

    def to_s
      lines = []
      lines << "Searched #{inputs_tested} input(s) " \
        "(alphabet #{alphabet.inspect}, max length #{max_length})."

      boundaries.each do |boundary|
        lines << "Analysis boundary: #{boundary}"
      end

      if found?
        lines << "Found #{witnesses.size} shadowing witness(es)" \
          "#{truncated ? ' (search stopped at limit, more may exist)' : ''}:"
        witnesses.each do |witness|
          lines << ''
          lines << witness.to_s
        end
      else
        lines << 'No shadowing witness found WITHIN THIS SEARCH SPACE. ' \
          'This does not prove the choice is free of shadowing in general; ' \
          'try a larger alphabet or a greater max length.'
      end

      lines.join("\n")
    end
  end

  # Searches for inputs on which an earlier alternative of +atom+ shadows a
  # later one.
  #
  # @param atom [Parslet::Atoms::Base] an Parslet::Atoms::Alternative, or an
  #   entity (rule) that resolves to one
  # @param alphabet [Array<String>] characters to build candidate inputs from
  # @param max_length [Integer] maximum input length (inputs of length 0 up
  #   to and including max_length are tried)
  # @param limit [Integer] maximum number of witnesses to collect
  # @return [Report]
  #
  def self.check(atom, alphabet:, max_length:, limit: 10)
    atom = atom.parslet while atom.is_a?(Parslet::Atoms::Entity)

    unless atom.is_a?(Parslet::Atoms::Alternative)
      raise ArgumentError,
        "Expected an alternative (a | b | ...) to check, got #{atom.inspect}."
    end

    alternatives = atom.alternatives
    boundaries = []
    analyzable = alternatives.each_with_index.map do |alternative, index|
      if dynamic_free?(alternative)
        true
      else
        boundaries << "branch #{index + 1} (#{alternative.inspect}) contains " \
          'a dynamic or unknown atom; skipped (analysis stops at this boundary).'
        false
      end
    end

    witnesses = []
    inputs_tested = 0
    truncated = false

    each_input(alphabet, max_length) do |input|
      inputs_tested += 1

      consumed = alternatives.each_with_index.map do |alternative, index|
        analyzable[index] ? apply_prefix(alternative, input) : nil
      end

      winner_index = consumed.index { |length| !length.nil? }
      next unless winner_index

      shadowed = []
      consumed.each_with_index do |length, index|
        next if index <= winner_index || length.nil?
        shadowed << Branch.new(index, alternatives[index], length)
      end
      next if shadowed.empty?

      witnesses << Witness.new(
        input,
        Branch.new(winner_index, alternatives[winner_index],
          consumed[winner_index]),
        shadowed)

      if witnesses.size >= limit
        truncated = true
        break
      end
    end

    Report.new(
      witnesses: witnesses,
      boundaries: boundaries,
      alphabet: alphabet,
      max_length: max_length,
      inputs_tested: inputs_tested,
      truncated: truncated)
  end

  # Applies +atom+ to +input+ with prefix semantics (consume_all = false)
  # and returns the number of characters consumed, or nil if the atom does
  # not match. Uses the real parsing machinery, so lookahead, repetition
  # and recursive rules behave exactly as they do during a real parse.
  #
  def self.apply_prefix(atom, input)
    source = Parslet::Source.new(input)
    context = Parslet::Atoms::Context.new(nil)
    success, _ = atom.apply(source, context, false)
    success ? source.pos.charpos : nil
  end

  # True if the atom tree contains no atom that cannot be analysed
  # reliably. Dynamic atoms and scopes evaluate arbitrary blocks at parse
  # time; unknown custom atoms are treated conservatively as well. Entity
  # (rule) references are followed, with cycles broken, so recursive
  # grammars terminate here.
  #
  def self.dynamic_free?(atom, visited={})
    return true if visited[atom.object_id]
    visited[atom.object_id] = true

    case atom
    when Parslet::Atoms::Str, Parslet::Atoms::Re
      true
    when Parslet::Atoms::Alternative
      atom.alternatives.all? { |child| dynamic_free?(child, visited) }
    when Parslet::Atoms::Sequence
      atom.parslets.all? { |child| dynamic_free?(child, visited) }
    when Parslet::Atoms::Repetition,
         Parslet::Atoms::Named,
         Parslet::Atoms::Ignored,
         Parslet::Atoms::Capture
      dynamic_free?(atom.parslet, visited)
    when Parslet::Atoms::Lookahead
      dynamic_free?(atom.bound_parslet, visited)
    when Parslet::Atoms::Entity
      begin
        dynamic_free?(atom.parslet, visited)
      rescue StandardError
        false
      end
    else
      # Dynamic, Scope, Infix and any unknown atom: stop at this boundary.
      false
    end
  end

  # Yields every string over +alphabet+ with a length between 0 and
  # +max_length+ (inclusive), shortest first.
  #
  def self.each_input(alphabet, max_length)
    (0..max_length).each do |length|
      alphabet.repeated_permutation(length) do |permutation|
        yield permutation.join
      end
    end
  end
end
