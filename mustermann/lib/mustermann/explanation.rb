# frozen_string_literal: true

module Mustermann
  # Explains why a pattern does not match a given string.
  #
  # An explanation points at the furthest position in the string that matching
  # was able to reach, along with the list of things that would have been
  # accepted at that position. Each of these expectations also knows where in
  # the pattern it originates from.
  #
  # Explanations are computed on demand by {Mustermann::Pattern#explain} and do
  # not affect the performance of normal matching.
  #
  # @example
  #   pattern = Mustermann.new('/users/:id', capture: :digit)
  #   pattern.explain('/users/new').message
  #   # => 'expected a digit segment (:id) at position 7 in "/users/new"'
  #
  # @see Mustermann::Pattern#explain
  class Explanation
    # A single thing that would have been accepted at the failure position.
    class Expectation
      # @return [Symbol] what kind of segment was expected, one of :literal,
      #   :capture, :splat, :end, :except or :pattern
      attr_reader :kind

      # @return [String, nil] name of the expected capture, if any
      attr_reader :name

      # @return [Object, nil] further constraint details, like the expected
      #   literal string, a capture constraint or an excluded pattern
      attr_reader :detail

      # @return [Range, nil] offsets of the corresponding part of the pattern
      #   string, if known
      attr_reader :pattern_range

      # @!visibility private
      def initialize(kind, name: nil, detail: nil, pattern_range: nil)
        @kind, @name, @detail, @pattern_range = kind, name, detail, pattern_range
      end

      # @!visibility private
      def self.literal(node)
        new(:literal, detail: node.payload, pattern_range: node.start...node.stop)
      end

      # @!visibility private
      def self.capture(node, detail)
        new(:capture, name: node.name, detail: detail, pattern_range: node.start...node.stop)
      end

      # @!visibility private
      def self.splat(node)
        name = node.name unless node.name == 'splat'
        new(:splat, name: name, pattern_range: node.start...node.stop)
      end

      # @!visibility private
      def self.end_of_input
        new(:end)
      end

      # @!visibility private
      def self.except(detail)
        new(:except, detail: detail)
      end

      # @!visibility private
      def self.pattern(detail)
        new(:pattern, detail: detail)
      end

      # @return [String] human readable description of the expectation
      def description
        case kind
        when :literal  then detail.inspect
        when :capture  then capture_description
        when :splat    then name ? "a splat (*#{name})" : "a splat"
        when :end      then "end of input"
        when :except   then "a string not matching #{detail.inspect}"
        else                "a string matching #{detail.inspect}"
        end
      end

      # @!visibility private
      # Expectations are merged by the kind of thing they describe, ignoring
      # where in the pattern they originate from.
      def key
        [kind, name, detail]
      end

      # @!visibility private
      def ==(other)
        other.class == self.class and other.key == key
      end

      # @!visibility private
      alias_method :eql?, :==

      # @!visibility private
      def hash
        key.hash
      end

      # @!visibility private
      def inspect
        "#<#{self.class.name} #{description}>"
      end

      private

      def capture_description
        case detail
        when nil    then "a path segment (:#{name})"
        when Symbol then "#{article(detail)} #{detail} segment (:#{name})"
        when Array  then "a segment matching one of #{detail.inspect} (:#{name})"
        else             "a segment matching #{detail.inspect} (:#{name})"
        end
      end

      def article(word)
        word.to_s =~ /\A[aeiou]/i ? "an" : "a"
      end
    end

    # @return [Mustermann::Pattern] the pattern that did not match
    attr_reader :pattern

    # @return [String] the string that did not match
    attr_reader :string

    # @return [Integer] character offset into the string up to which matching
    #   was able to proceed
    attr_reader :position

    # @return [Array<Expectation>] what would have been accepted at {#position}
    attr_reader :expectations

    # @!visibility private
    def initialize(pattern:, string:, position:, expectations:)
      @pattern, @string, @position = pattern, string, position
      @expectations = expectations.freeze
    end

    # @return [String] human readable summary of the mismatch
    def message
      "expected %s at position %d in %s" % [
        expectations.map(&:description).join(' or '), position, string.inspect
      ]
    end

    alias_method :to_s, :message

    # @return [String] part of the string that did match the pattern
    def matched_prefix
      string[0...position]
    end

    # @return [String] part of the string from the failure position onwards
    def remainder
      string[position..]
    end

    # @!visibility private
    def inspect
      "#<#{self.class.name}: #{message}>"
    end
  end
end
