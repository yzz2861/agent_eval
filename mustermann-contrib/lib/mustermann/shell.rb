# frozen_string_literal: true
require 'mustermann'
require 'mustermann/pattern'

module Mustermann
  # Matches strings that are identical to the pattern.
  #
  # @example
  #   Mustermann.new('/*.*', type: :shell) === '/bar' # => false
  #
  # @see Mustermann::Pattern
  # @see file:README.md#shell Syntax description in the README
  class Shell < Pattern
    include Concat::Native
    register :shell

    # @!visibility private
    # @return [#highlight, nil]
    #   highlighing logic for mustermann-visualizer,
    #   nil if mustermann-visualizer hasn't been loaded
    def highlighter
      return unless defined? Mustermann::Visualizer::Highlighter
      @@highlighter ||= Mustermann::Visualizer::Highlighter.create do
        on('\\') { |matched| escaped(matched, scanner.getch) }
        on(/[\*\[\]]/, :special)
        on("{") { nested(:union, ?{, ?}, ?,) }
      end
    end

    # @param (see Mustermann::Pattern#initialize)
    # @return (see Mustermann::Pattern#initialize)
    # @see (see Mustermann::Pattern#initialize)
    def initialize(string, **options)
      @flags = File::FNM_PATHNAME | File::FNM_DOTMATCH | File::FNM_EXTGLOB
      super(string, **options)
    end

    # @param (see Mustermann::Pattern#===)
    # @return (see Mustermann::Pattern#===)
    # @see (see Mustermann::Pattern#===)
    def ===(string)
      string = unescape(string)
      string = Mustermann::Unicode.normalize(string, @normalization) if normalize?
      pattern = normalize? ? Mustermann::Unicode.normalize(@string, @normalization) : @string
      File.fnmatch? pattern, string, @flags
    end

    # @param (see Mustermann::Pattern#peek_size)
    # @return (see Mustermann::Pattern#peek_size)
    # @see (see Mustermann::Pattern#peek_size)
    def peek_size(string)
      if normalize?
        check_encoding(string)
        normalized = Mustermann::Unicode.normalize(unescape(string), @normalization)
        normalized_pattern = Mustermann::Unicode.normalize(@string, @normalization)
        prefix = normalized_peek_length(normalized_pattern, normalized)
        return unless prefix
        return prefix unless string.include?('%')
        # Map the normalized length back to the (possibly percent-encoded) raw length.
        return raw_peek_length(string, prefix)
      end
      @peek_string ||= @string + "{**,/**,/**/*}"
      super if File.fnmatch? @peek_string, unescape(string), @flags
    end

    private

    # @return [Integer, nil] length (in normalized characters) that may match
    def normalized_peek_length(pattern, string)
      return string.size if File.fnmatch?(pattern, string, @flags)
      string.size.downto(0).detect { |size| File.fnmatch?(pattern, string[0, size], @flags) }
    end

    # Walks the raw and normalized strings in parallel to translate a normalized
    # prefix length into the corresponding raw string length.
    # @return [Integer]
    def raw_peek_length(raw, normalized_length)
      matched_normalized = 0
      position = 0
      while position < raw.size
        if raw[position] == ?% && raw[position, 3] =~ /\A%[0-9A-Fa-f]{2}\z/
          chunk = @@uri.unescape(raw[position, 3])
          position += 3
        else
          chunk = raw[position]
          position += 1
        end
        next unless chunk.valid_encoding?
        matched_normalized += Mustermann::Unicode.normalize(chunk, @normalization).size
        return position if matched_normalized >= normalized_length
      end
    end

    # Used by {Mustermann::FileUtils} to not use a generic glob pattern.
    alias_method :to_glob, :to_s
  end
end
