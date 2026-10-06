# frozen_string_literal: true
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
  # See {Importing Dependencies}[link:doc/rakefile_rdoc.html#label-Importing+Dependencies]
  # for further details.

  class MakefileLoader
    include Rake::DSL

    class ParseError < RuntimeError
    end

    # Load the makefile dependencies in +fn+.
    def load(fn) # :nodoc:
      rules = []
      each_logical_line(File.read(fn), fn) do |line, line_numbers,
        start_line, recipe|
        rule = parse_rule(line, line_numbers, fn, start_line, recipe)
        rules << rule unless rule[0].empty?
      end

      rules.each do |targets, prerequisites, order_only_prerequisites|
        targets.each do |target|
          task = file(target => prerequisites)
          unless order_only_prerequisites.empty?
            task | order_only_prerequisites
          end
        end
      end
    end

    private

    def each_logical_line(content, filename) # :nodoc:
      index = 0
      physical_line = 1
      logical_line = +""
      logical_line_numbers = []
      logical_line_number = physical_line
      recipe_line = nil
      physical_line_start = true

      while index < content.length
        character = content[index]

        if character == "\\"
          run = 1
          run += 1 while content[index + run] == "\\"
          following = content[index + run]

          if following == "\n"
            if run.even?
              logical_line << "\\" * (run / 2)
              logical_line_numbers.concat([physical_line] * (run / 2))
              physical_line_start = true
              yield logical_line, logical_line_numbers,
                logical_line_number, recipe_line
              logical_line = +""
              logical_line_numbers = []
              logical_line_number = physical_line + 1
              recipe_line = nil
              index += run + 1
              physical_line += 1
            else
              logical_line << " "
              logical_line_numbers << physical_line
              physical_line += 1
              index += run + 1
              physical_line_start = true
              next
            end
          elsif following.nil?
            parse_error filename, physical_line,
              "unexpected end of file in line continuation" if run.odd?
            logical_line << "\\" * (run / 2)
            logical_line_numbers.concat([physical_line] * (run / 2))
            index += run
          else
            logical_line << "\\" * run
            logical_line_numbers.concat([physical_line] * run)
            index += run
          end
        elsif character == "\n"
          yield logical_line, logical_line_numbers,
            logical_line_number, recipe_line
          logical_line = +""
          logical_line_numbers = []
          logical_line_number = physical_line + 1
          recipe_line = nil
          physical_line_start = true
          index += 1
          physical_line += 1
        else
          if character == "\t" && physical_line_start
            recipe_line = physical_line
          end
          logical_line << character
          logical_line_numbers << physical_line
          index += 1
          physical_line_start = false
        end
      end

      yield logical_line, logical_line_numbers,
        logical_line_number, recipe_line unless
        logical_line.empty?
    end

    def parse_rule(line, line_numbers, filename, start_line, recipe_line)
      # :nodoc:
      if recipe_line
        parse_error filename, recipe_line, "recipes are not supported"
      end
      line = strip_comment(line, line_numbers, filename, start_line)
      return [[], [], []] if line.strip.empty?

      tokens = {
        targets: [],
        prerequisites: [],
        order_only: []
      }
      section = :targets
      token = +""
      token_present = false
      separator_seen = false
      order_only_separator_seen = false
      index = 0

      append_token = lambda do
        tokens[section] << -token if token_present
        token = +""
        token_present = false
      end

      while index < line.length
        character = line[index]
        line_number = line_number_at(line_numbers, index, start_line)

        case character
        when /\s/
          append_token.call
          index += 1
        when "\\"
          value, size = read_escaped_character(line, index)
          parse_error filename, line_number,
            "unsupported escape sequence" if value.nil?
          token << value
          token_present = true
          index += size
        when "$"
          unless line[index + 1] == "$"
            parse_error filename, line_number, "variables are not supported"
          end
          token << "$"
          token_present = true
          index += 2
        when ":"
          if !separator_seen && line[index + 1] == "="
            parse_error filename, line_number,
              "variable assignments are not supported"
          end
          append_token.call
          parse_error filename, line_number,
            "multiple rule separators" if separator_seen
          separator_seen = true
          section = :prerequisites
          index += 1
        when "|"
          append_token.call
          unless separator_seen && !order_only_separator_seen
            parse_error filename, line_number, "unexpected '|'"
          end
          order_only_separator_seen = true
          section = :order_only
          index += 1
        when ";"
          parse_error filename, line_number, "recipes are not supported"
        else
          token << character
          token_present = true
          index += 1
        end
      end
      append_token.call

      parse_error filename, line_number_at(line_numbers, index - 1, start_line),
        "missing rule separator ':'" unless separator_seen
      parse_error filename, start_line, "missing rule target" if
        tokens[:targets].empty?
      parse_error filename, line_number_at(line_numbers, index - 1, start_line),
        "missing order-only prerequisite" if
          order_only_separator_seen && tokens[:order_only].empty?

      [tokens[:targets], tokens[:prerequisites], tokens[:order_only]]
    end

    def strip_comment(line, line_numbers, filename, start_line) # :nodoc:
      index = 0

      while index < line.length
        if line[index] == "\\"
          value, size = read_escaped_character(line, index)
          parse_error filename, line_number_at(line_numbers, index, start_line),
            "unsupported escape sequence" if value.nil?
          index += size
        elsif line[index] == "#"
          return line[0, index]
        else
          index += 1
        end
      end

      line
    end

    def read_escaped_character(line, index) # :nodoc:
      run = 1
      run += 1 while line[index + run] == "\\"
      following = line[index + run]
      prefix = "\\" * ((run - 1) / 2)

      return [prefix << "\\", run] if following.nil?

      case following
      when " ", "#", ":"
        [prefix << following, run + 1]
      when "\t", ";", "|"
        [nil, run + 1]
      else
        [prefix << "\\", run]
      end
    end

    def parse_error(filename, line_number, message) # :nodoc:
      raise ParseError, "#{filename}:#{line_number}: #{message}"
    end

    def line_number_at(line_numbers, index, start_line) # :nodoc:
      line_numbers[index] || line_numbers.last || start_line
    end
  end

  # Install the handler
  Rake.application.add_loader("mf", MakefileLoader.new)
end
