# frozen_string_literal: true

module Mustermann
  # A single thing a pattern expected to find at a given point in the input.
  #
  # Expectations are collected by {Mustermann::Pattern#explain} and describe
  # what would have had to appear at {#position} for the match to proceed.
  # Several expectations may share one position, for instance when multiple
  # alternative branches failed there.
  #
  # @see Mustermann::Failure
  # @see Mustermann::Pattern#explain
  class Expectation
    # @return [Integer] character position in the input at which this was expected
    attr_reader :position

    # @return [Symbol] kind of segment that was expected, e.g. +:literal+, +:capture+,
    #   +:splat+, +:end+
    attr_reader :kind
    # @return [Integer] character position in the pattern string of the expected segment
    attr_reader :pattern_position

    # @return [String, nil] literal character/string expected, for +:literal+ expectations
    attr_reader :literal

    # @return [String, nil] name of the capture or splat, when applicable
    attr_reader :name

    # @return [Object, nil] capture constraint (a Regexp, Class, Symbol, etc.), when applicable
    attr_reader :constraint

    # @!visibility private
    def initialize(position:, kind:, pattern_position:, literal: nil, name: nil, constraint: nil)
      @position         = position
      @kind             = kind
      @pattern_position = pattern_position
      @literal          = literal
      @name             = name
      @constraint       = constraint
      freeze
    end

    # @return [String] human readable description of what was expected
    def to_s
      case kind
      when :literal
        "expected %p at position %d" % [literal, position]
      when :end
        "expected end of string at position %d" % position
      when :capture
        suffix = constraint ? " matching %p" % [constraint] : EMPTY_STRING
        label  = name ? "capture %p" % name : "capture"
        "expected %s at position %d%s" % [label, position, suffix]
      when :splat
        "expected splat %p at position %d" % [name, position]
      when :excluded
        "input was excluded by the pattern at position %d" % position
      else
        "expected %s at position %d" % [kind, position]
      end
    end

    # @return [String]
    # @!visibility private
    def inspect
      parts = ["position=#{position}", "kind=#{kind.inspect}", "pattern_position=#{pattern_position}"]
      parts << "literal=#{literal.inspect}" if literal
      parts << "name=#{name.inspect}" if name
      parts << "constraint=#{constraint.inspect}" if constraint
      "#<#{self.class.name} #{parts.join(" ")}>"
    end

    # Two expectations are considered identical when they point to the same
    # input position and the same pattern segment.
    # @return [Boolean]
    def ==(other)
      other.is_a?(self.class) &&
        position == other.position && kind == other.kind &&
        pattern_position == other.pattern_position && literal == other.literal &&
        name == other.name && constraint == other.constraint
    end

    alias eql? ==

    # @see #==
    def hash
      [position, kind, pattern_position, literal, name, constraint].hash
    end

    # @!visibility private
    def deconstruct_keys(keys)
      keys.to_h { |key| [key, public_send(key)] }
    end
  end

  # Result of {Mustermann::Pattern#explain} when a string does not match.
  #
  # Carries the furthest position in the input reachable while trying the
  # pattern together with all expectations that were waiting at that
  # position across alternative branches.
  #
  # @example
  #   pattern = Mustermann.new("/users/:id", capture: :integer)
  #   failure = pattern.explain("/users/abc")
  #   failure.position   # => 7
  #   failure.expectations.map(&:kind) # => [:capture]
  #   failure.message    # => "expected numeric capture \"id\" at position 7"
  #
  # @see Mustermann::Expectation
  # @see Mustermann::Pattern#explain
  class Failure
    # @return [Mustermann::Pattern] the pattern the string was matched against
    attr_reader :pattern

    # @return [String] the string that failed to match
    attr_reader :string

    # @return [Integer] furthest character position in the input reached
    #   while matching; this is where the diagnosis starts
    attr_reader :position

    # @return [Array<Mustermann::Expectation>] merged expectations at {#position},
    #   ordered by their position in the pattern
    attr_reader :expectations

    # @!visibility private
    def initialize(pattern:, string:, position:, expectations:)
      @pattern      = pattern
      @string       = string
      @position     = position
      @expectations = expectations.uniq.sort_by { |e| [e.pattern_position, e.kind.to_s] }
      freeze
    end

    # @return [String] human readable diagnosis combining all expectations
    def message
      if expectations.one?
        expectations.first.to_s
      else
        "expected one of %s at position %d" % [
          expectations.map { |e| expectation_label(e) }.join(", "), position
        ]
      end
    end

    alias to_s message

    # @return [String] the input with a caret pointing at {#position}, useful in logs
    def detail
      "#{string}\n#{' ' * position}^"
    end

    # @return [String]
    # @!visibility private
    def inspect
      "#<#{self.class.name} position=#{position} expectations=#{expectations.inspect}>"
    end

    private

    def expectation_label(expectation)
      case expectation.kind
      when :literal  then expectation.literal.inspect
      when :end      then "end of string"
      when :capture  then label_capture(expectation)
      when :splat    then "splat #{expectation.name.inspect}"
      when :excluded then "an allowed (not excluded) input"
      else expectation.kind.to_s
      end
    end

    def label_capture(expectation)
      name   = " #{expectation.name.inspect}" if expectation.name
      suffix = expectation.constraint ? " (#{expectation.constraint.inspect})" : EMPTY_STRING
      "capture#{name}#{suffix}"
    end
  end
end
