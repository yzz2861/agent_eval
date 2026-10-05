# encoding: utf-8
# frozen_string_literal: true
require 'date'

module Mail
  # Parses a single Received header into its structured parts (from, by,
  # with, id, for and the date) so a message's relay path can be inspected
  # when tracking down delivery delays.
  #
  # The parser is deliberately tolerant: it never raises. Comments and
  # quoted strings are honored while scanning, so keywords or semicolons
  # inside them do not confuse the clause splitting, and folded lines are
  # unfolded first. Anything that does not fit the from/by/with/id/for
  # grammar is kept in +extra+, and the untouched (unfolded) field value is
  # always available as +raw+.
  #
  #  hop = Mail::ReceivedHop.new(field_value)
  #  hop.from      #=> "mail.example.com (mail.example.com [10.0.0.1])"
  #  hop.by        #=> "mx.example.org"
  #  hop.with      #=> "ESMTP"
  #  hop.id        #=> "50FD3A96F"
  #  hop.for       #=> "<user@example.org>"
  #  hop.date_time #=> #<DateTime ...> or nil
  #  hop.extra     #=> tokens that were not recognized
  #  hop.raw       #=> the original field value
  class ReceivedHop
    KEYWORDS = %w[from by with id for].freeze #:nodoc:

    attr_reader :raw, :from, :by, :with, :id, :for, :date_time, :extra, :errors

    def initialize(raw)
      @raw = raw.to_s
      @extra = []
      @errors = []
      parse
    rescue => error
      @errors << error
    end

    def to_s
      raw
    end

    private
      def parse
        text = unfold(@raw)
        semicolon = last_top_level_semicolon(text)
        if semicolon
          parse_date(text[(semicolon + 1)..-1].to_s)
          info = text[0...semicolon]
        else
          info = text
        end
        parse_info(info)
      end

      def unfold(text)
        text.gsub(/\r?\n[ \t]+/, ' ')
      end

      def parse_date(text)
        cleaned = strip_comments(text).strip
        return if cleaned.empty?
        @date_time = ::DateTime.parse(cleaned)
      rescue ArgumentError, TypeError => error
        @errors << error
        @date_time = nil
      end

      def parse_info(info)
        clauses = {}
        current = nil
        top_level_tokens(info).each do |token|
          if (keyword = keyword_for(token))
            current = keyword
            clauses[keyword] ||= []
          elsif current
            clauses[current] << token
          else
            @extra << token
          end
        end
        clauses.each do |keyword, tokens|
          value = tokens.join(' ').strip
          assign_keyword(keyword, value) unless value.empty?
        end
      end

      def assign_keyword(keyword, value)
        case keyword
        when 'from' then @from = value
        when 'by'   then @by = value
        when 'with' then @with = value
        when 'id'   then @id = value
        when 'for'  then @for = value
        end
      end

      def keyword_for(token)
        downcased = token.downcase
        downcased if KEYWORDS.include?(downcased)
      end

      # Splits text on top-level whitespace. Parenthesized comments
      # (possibly nested) and quoted strings are kept intact, so keywords
      # and semicolons inside them are not treated as structure.
      def top_level_tokens(text)
        tokens = []
        current = +''
        depth = 0
        in_quote = false
        escaped = false
        text.each_char do |char|
          if escaped
            current << char
            escaped = false
            next
          end
          if char == '\\' && (in_quote || depth > 0)
            current << char
            escaped = true
            next
          end
          if in_quote
            current << char
            in_quote = false if char == '"'
            next
          end
          if depth.zero? && char =~ /\s/
            unless current.empty?
              tokens << current
              current = +''
            end
            next
          end
          current << char
          case char
          when '"' then in_quote = true if depth.zero?
          when '(' then depth += 1
          when ')' then depth -= 1 if depth > 0
          end
        end
        tokens << current unless current.empty?
        tokens
      end

      def last_top_level_semicolon(text)
        semicolon = nil
        depth = 0
        in_quote = false
        escaped = false
        text.each_char.with_index do |char, index|
          if escaped
            escaped = false
            next
          end
          if char == '\\' && (in_quote || depth > 0)
            escaped = true
            next
          end
          if in_quote
            in_quote = false if char == '"'
            next
          end
          case char
          when '"' then in_quote = true if depth.zero?
          when '(' then depth += 1
          when ')' then depth -= 1 if depth > 0
          when ';' then semicolon = index if depth.zero?
          end
        end
        semicolon
      end

      def strip_comments(text)
        result = +''
        depth = 0
        text.each_char do |char|
          case char
          when '(' then depth += 1
          when ')' then depth -= 1 if depth > 0
          else result << char if depth.zero?
          end
        end
        result
      end
  end
end
