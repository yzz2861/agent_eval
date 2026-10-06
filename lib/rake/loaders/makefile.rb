# frozen_string_literal: true
require "strscan"

module Rake

  # Makefile loader to be used with the import file loader.  Use this to
  # import dependencies from make dependency tools:
  #
  #   require 'rake/loaders/makefile'
  #
  #   file ".depends.mf" => [SRC_LIST] do |t|
  #     sh "makedepend -f- -- #{CFLAGS} -- #{t.prerequisites} > #{t.name}"
  #   end
  #
  #   import ".depends.mf"
  #
  # The loader understands dependency rules using the subset of makefile
  # syntax emitted by compiler dependency generators: escaped spaces
  # (<tt>\\ </tt>), escaped number signs (<tt>\\#</tt>), escaped colons
  # (<tt>\\:</tt>), escaped backslashes (<tt>\\\\</tt>), literal dollar
  # signs (<tt>$$</tt>), backslash-newline line continuations, several
  # targets per rule and order-only prerequisites following a <tt>|</tt>.
  # Recipes are not executed and variables are not expanded; syntax outside
  # of this subset raises an +ArgumentError+ reporting the offending line.
  #
  # See {Importing Dependencies}[link:doc/rakefile_rdoc.html#label-Importing+Dependencies]
  # for further details.

  class MakefileLoader
    include Rake::DSL

    # Load the makefile dependencies in +fn+.
    def load(fn) # :nodoc:
      @load_file_name = fn
      each_logical_line(File.read(fn)) do |line_number, line|
        process_rule(line_number, line)
      end
    ensure
      @load_file_name = nil
    end

    private

    # Yield each logical line of +content+ as [first_physical_line_number,
    # text].  Joins backslash-newline continuations; blank and comment-only
    # physical lines are dropped (comment-only lines remain transparent to
    # a pending continuation).
    def each_logical_line(content)
      buffer = +""
      start_line = nil
      content.split("\n", -1).each_with_index do |physical_line, index|
        line_number = index + 1
        line = strip_comment(physical_line)
        if line.start_with?("\t") && !line.strip.empty?
          # A physical line beginning with a tab is a make recipe line,
          # even when it follows a continued prerequisite list.
          syntax_error(line_number,
            "recipe lines are not supported in dependency files")
        end

        if line.strip.empty? && physical_line =~ /(?<!\\)#/
          # A comment-only physical line is transparent: it neither ends
          # a pending continuation nor starts a rule.
          next
        end

        if line.strip.empty? && start_line.nil?
          # A truly blank line outside a continuation carries no data.
          next
        end

        continuation = (backslash_count =
          trailing_backslash_count(line)).odd?
        line = line[0, line.length - 1] if continuation

        if start_line
          buffer << " " << line
        else
          start_line = line_number
          buffer = +line
        end

        unless continuation
          # An even number of trailing backslashes ends the (possibly
          # continued) line; the backslashes are decoded later.
          yield start_line, buffer.dup unless buffer.strip.empty?
          start_line = nil
          buffer = +""
        end
      end

      if start_line
        syntax_error(start_line,
          "backslash-newline continuation is not followed by a line")
      end
    end

    # Remove the comment beginning at the first unescaped number sign.
    # A number sign escaped by an odd number of preceding backslashes is
    # preserved (and decoded later during tokenization).
    def strip_comment(line)
      index = 0
      while index < line.length
        if line[index] == "#"
          backslashes = 0
          position = index - 1
          while position >= 0 && line.getbyte(position) == 0x5c
            backslashes += 1
            position -= 1
          end
          return line[0, index] if backslashes.even?
        end
        index += 1
      end
      line
    end

    # Number of consecutive backslashes at the end of +line+.
    def trailing_backslash_count(line)
      count = 0
      index = line.length - 1
      while index >= 0 && line.getbyte(index) == 0x5c
        count += 1
        index -= 1
      end
      count
    end

    # Process one logical dependency rule.
    def process_rule(line_number, line) # :nodoc:
      colon = find_unescaped(line, ":", line_number)
      if colon.nil?
        if line =~ VARIABLE_ASSIGNMENT
          syntax_error(line_number,
            "variable assignments are not supported")
        end
        syntax_error(line_number,
          "expected a dependency rule but ':' was not found")
      end

      target_text = line[0, colon]
      prerequisites_text = line[colon + 1..-1]

      if prerequisites_text.start_with?(":")
        syntax_error(line_number, "double-colon rules are not supported")
      end
      if find_unescaped(prerequisites_text, ":", line_number)
        syntax_error(line_number,
          "unescaped ':' in prerequisites (escape it as '\\:')")
      end
      normal_text, order_only_text =
        split_order_only(prerequisites_text, line_number)

      targets = tokenize(target_text, line_number)
      if targets.empty?
        syntax_error(line_number, "a dependency rule needs a target")
      end
      prerequisites = tokenize(normal_text, line_number)
      order_only = order_only_text.nil? ? nil :
        tokenize(order_only_text, line_number)

      targets.each do |target|
        task = file(target => prerequisites)
        task | order_only unless order_only.nil? || order_only.empty?
      end
    end

    # Matches make variable assignments such as +NAME = value+,
    # +NAME := value+, +NAME += value+ and +NAME ?= value+.
    VARIABLE_ASSIGNMENT =
      /\A\s*\S[^:#=]*?\s*(?::=|\?=|\+=|=)/

    # Split prerequisites at the unescaped order-only separator.
    def split_order_only(text, line_number)
      pipe = find_unescaped(text, "|", line_number)
      return [text, nil] if pipe.nil?
      second = find_unescaped(text[pipe + 1..-1], "|", line_number)
      unless second.nil?
        syntax_error(line_number,
          "multiple order-only separators ('|') are not allowed")
      end
      [text[0, pipe], text[pipe + 1..-1]]
    end

    # Return the index of the first unescaped occurrence of +separator+
    # in +text+.
    def find_unescaped(text, separator, line_number)
      scanner = StringScanner.new(text)
      until scanner.eos?
        char = scanner.getch
        if char == "\\"
          following = scanner.getch
          if following.nil?
            syntax_error(line_number, "dangling escape ('\\')")
          end
        elsif char == "$"
          if scanner.scan(/\$/)
            # A doubled dollar sign is a literal dollar character.
          else
            syntax_error(line_number,
              "make variables are not supported; " \
                "use '$$' for a literal $")
          end
        elsif char == separator
          return scanner.pos - 1
        end
      end
      nil
    end

    # Split +text+ into whitespace separated, unescaped file names.
    def tokenize(text, line_number)
      tokens = []
      token = +""
      scanner = StringScanner.new(text)
      flush = -> do
        unless token.empty?
          tokens << token.dup
          token = +""
        end
      end
      until scanner.eos?
        if scanner.scan(/\s+/)
          flush.call
        elsif scanner.scan(/\\(.)/m)
          escaped = scanner[1]
          case escaped
          when " ", "#", ":", "|", "\\"
            token << escaped
          else
            syntax_error(line_number,
              "unsupported escape sequence ('\\#{escaped}')")
          end
        elsif scanner.scan(/\$\$/)
          token << "$"
        elsif scanner.scan(/\$/)
          syntax_error(line_number,
            "make variables are not supported; use '$$' for a literal $")
        else
          token << scanner.getch
        end
      end
      flush.call
      tokens
    end

    def syntax_error(line_number, message) # :nodoc:
      location = @load_file_name ?
        "#{@load_file_name}:#{line_number}" : line_number.to_s
      raise ArgumentError, "#{location}: #{message}"
    end
  end

  # Install the handler
  Rake.application.add_loader("mf", Rake::MakefileLoader.new)
end
