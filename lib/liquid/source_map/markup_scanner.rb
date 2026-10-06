# frozen_string_literal: true

require "strscan"

module Liquid
  class SourceMap
    # Tokenizes the markup of a single tag or output expression and reports
    # every identifier that may be a variable reference, together with its byte
    # span relative to the markup.
    #
    # Identifier tokens that are *syntactically* never variables are filtered
    # out here:
    #
    #   * string and number literals (including identifiers inside strings)
    #   * property names following a dot (`user.name`)
    #   * keyword argument keys (`limit: n`)
    #   * filter names (`x | default: y`)
    #   * reserved language words (`and`, `or`, `not`, `contains`, `true`, ...)
    #
    # Identifiers inside square brackets ARE reported because brackets hold
    # expressions (`products[item]`); quoted bracket keys are strings and are
    # skipped. The lexical binding resolution lives in SourceMap.
    class MarkupScanner
      Token = Struct.new(:type, :value, :start_byte, :end_byte, keyword_init: true)

      IDENTIFIER = /[a-zA-Z_][\w-]*\??/
      NUMBER     = /-?\d+(?:\.\d+)?/
      STRING     = /"(?:[^"]|\\.)*"|'(?:[^']|\\.)*'/

      KEYWORDS = %w[and or not contains in with for as true false nil null].freeze

      def self.scan(markup, base_byte)
        new(markup, base_byte).scan
      end

      def self.tokenize(markup, base_byte = 0)
        new(markup, base_byte).tokenize
      end

      def initialize(markup, base_byte)
        @markup = markup
        @base = base_byte
        @ss = StringScanner.new(markup.b)
      end

      # Returns an Array of Token objects for candidate root variables only.
      def scan
        tokens = tokenize
        select_variable_identifiers(tokens)
      end

      def tokenize
        tokens = []

        until @ss.eos?
          @ss.skip(/\s+/m)
          break if @ss.eos?

          start = @ss.pos
          if (value = @ss.scan(STRING))
            tokens << Token.new(type: :string, value: value, start_byte: @base + start, end_byte: @base + @ss.pos)
          elsif (value = @ss.scan(NUMBER))
            tokens << Token.new(type: :number, value: value, start_byte: @base + start, end_byte: @base + @ss.pos)
          elsif (value = @ss.scan(IDENTIFIER))
            tokens << Token.new(type: :id, value: value, start_byte: @base + start, end_byte: @base + @ss.pos)
          else
            char = @ss.get_byte
            type = case char
            when '.' then :dot
            when '[' then :open_square
            when ']' then :close_square
            when '(' then :open_round
            when ')' then :close_round
            when ':' then :colon
            when '|' then :pipe
            when ',' then :comma
            when '?' then :question
            when '=' then :equals
            when '<', '>', '!' then :comparison
            else :punct
            end
            tokens << Token.new(type: type, value: char, start_byte: @base + start, end_byte: @base + @ss.pos)
          end
        end

        tokens
      end

      private

      # A lexical classification pass. An :id token denotes a root variable
      # unless a preceding token makes it a property, keyword-arg key, filter
      # name or reserved word.
      def select_variable_identifiers(tokens)
        result = []
        tokens.each_with_index do |token, idx|
          next unless token.type == :id
          next if KEYWORDS.include?(token.value)

          prev = previous_significant(tokens, idx)

          # Property access: `user.name`
          next if prev&.type == :dot

          # Keyword argument key: `key: value` (colon follows directly).
          next if next_significant(tokens, idx)&.type == :colon

          # Filter name: token following a pipe is the filter.
          next if prev&.type == :pipe

          result << token
        end

        result
      end

      def previous_significant(tokens, idx)
        tokens[idx - 1]
      end

      def next_significant(tokens, idx)
        tokens[idx + 1..]&.first
      end
    end
  end
end
