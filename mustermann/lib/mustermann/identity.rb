# frozen_string_literal: true
require 'mustermann'
require 'mustermann/pattern'
require 'mustermann/ast/node'

module Mustermann
  # Matches strings that are identical to the pattern.
  #
  # @example
  #   Mustermann.new('/:foo', type: :identity) === '/bar' # => false
  #
    # @see Mustermann::Pattern
    # @see file:README.md#identity Syntax description in the README
    class Identity < Pattern
    include Concat::Native
    register :identity

    # @param (see Mustermann::Pattern#===)
    # @return (see Mustermann::Pattern#===)
    # @see (see Mustermann::Pattern#===)
    def ===(string)
      return unescape(string) == @string unless normalize?
      check_encoding(string)
      normalized_peek_size(string) == string.size
    end

    # @param (see Mustermann::Pattern#peek_size)
    # @return (see Mustermann::Pattern#peek_size)
    # @see (see Mustermann::Pattern#peek_size)
    def peek_size(string)
      return normalized_peek_size(string) if normalize?
      return unless unescape(string).start_with? @string
      return @string.size if string.start_with? @string # optimization
      @string.each_char.with_index.inject(0) do |count, (char, index)|
        char_size = 1
        escaped   = @@uri.escape(char, /./)
        char_size = escaped.size if string[index, escaped.size].downcase == escaped.downcase
        count + char_size
      end
    end

    # URI templates support generating templates (the logic is quite complex, though).
    #
    # @example (see Mustermann::Pattern#to_templates)
    # @param (see Mustermann::Pattern#to_templates)
    # @return (see Mustermann::Pattern#to_templates)
    # @see Mustermann::Pattern#to_templates
    def to_templates
      [@@uri.escape(to_s)]
    end

    # Generates an AST so it's compatible with {Mustermann::AST::Pattern}.
    # Not used internally by {Mustermann::Identity}.
    # @!visibility private
    def to_ast
      payload = @string.each_char.with_index.map { |c, i| AST::Node[c == ?/ ? :separator : :char].new(c, start: i, stop: i+1) }
      AST::Node[:root].new(payload, pattern: @string, start: 0, stop: @string.length)
    end

    # Identity patterns support expanding.
    #
    # This implementation does not use {Mustermann::Expander} internally to save memory and
    # compilation time.
    #
    # @example (see Mustermann::Pattern#expand)
    # @param (see Mustermann::Pattern#expand)
    # @return (see Mustermann::Pattern#expand)
    # @raise (see Mustermann::Pattern#expand)
    # @see Mustermann::Pattern#expand
    # @see Mustermann::Expander
    def expand(behavior = nil, values = EMPTY_HASH)
      result = if values.empty? or behavior == :ignore
        to_s
      else
        raise ExpandError,   "cannot expand with keys %p" % values.keys.sort if behavior == :raise
        raise ArgumentError, "unknown behavior %p"        % behavior         if behavior != :append
        normalize = ->(value) { @normalization && value.is_a?(String) ? Mustermann::Unicode.normalize(value, @normalization) : value }
        params    = values.map do |key, value|
          value = normalize.call(value)
          @@uri.escape(key.to_s) + "=" + @@uri.escape(value.to_s, /[^\w]/)
        end
        separator = @string.include?(??) ? ?& : ??
        @string + separator + params.join(?&)
      end
      @normalization ? Mustermann::Unicode.normalize(result, @normalization) : result
    end

    private

    # @return [String] the pattern string in its normalized Unicode form
    def normalized_literal
      @normalized_literal ||= Mustermann::Unicode.normalize(@string, @normalization)
    end

    # Like {#peek_size}, but literal characters may appear in either canonical
    # form and/or percent-encoded in the input string.
    def normalized_peek_size(string)
      return unless check_encoding(string)
      position = 0
      normalized_literal.each_char do |char|
        # Try the longest canonical form first so that a percent-encoded base
        # character is not swallowed by the shorter form.
        candidates = Mustermann::Unicode.forms(char, @normalization).sort_by { |c| -c.size }
        matched = candidates.any? do |candidate|
          scanned = scan_literal(string, position, candidate)
          position = scanned if scanned
          scanned
        end
        return unless matched
      end
      position
    end

    # Tries to match each codepoint of a canonical-form candidate at the given
    # position, either raw or percent-encoded (case-insensitively).
    # @return [Integer, nil] the new position, or nil if nothing matched
    def scan_literal(string, position, candidate)
      offset = position
      candidate.each_char do |char|
        step = scan_step(string, offset, char)
        return unless step
        offset += step
      end
      offset unless offset == position
    end

    # A codepoint may appear raw, percent-encoded as a single codepoint, or
    # (if it is a composed character) percent-encoded as a multi-byte sequence.
    # @return [Integer, nil] number of input characters consumed
    def scan_step(string, offset, char)
      escaped = @@uri.escape(char, /./)
      return escaped.size if @uri_decode && string[offset, escaped.size]&.downcase == escaped.downcase
      return 1 if string[offset] == char
    end
    end
end
