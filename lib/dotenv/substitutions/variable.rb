require "English"

module Dotenv
  module Substitutions
    # Substitute variables in a value, including shell-style parameter
    # expansion:
    #
    #   $VAR or ${VAR}            simple expansion
    #   ${VAR:-default}           default when unset or empty
    #   ${VAR-default}            default only when unset
    #   ${VAR:+alternate}         alternate when set and non-empty
    #   ${VAR+alternate}          alternate when set (even if empty)
    #   ${VAR:?error message}     fail when unset or empty
    #   ${VAR?error message}      fail only when unset
    #
    # Only the selected branch is expanded, so command substitutions and
    # variables in other branches are never evaluated.
    module Variable
      class << self
        def call(value, env, view: ENV, source: nil, base_offset: 0, depth: 0,
                 mode: :normal, root_offset: base_offset)
          Expander.new(value, env, view, source || value, base_offset, depth, mode,
                       root_offset).expand
        end
      end

      # Performs a single left-to-right scan of a value so that command
      # substitutions are executed only when they appear in selected text.
      class Expander
        MAX_DEPTH = 10

        VARIABLE_NAME = /[A-Z0-9_]+/i
        ESCAPABLE = /[{}$()]/

        def initialize(value, hash, view, source, base_offset, depth, mode, root_offset)
          @value = value
          @hash = hash
          @view = view
          @source = source
          @base_offset = base_offset
          @depth = depth
          @mode = mode
          @root_offset = root_offset
          @output = String.new
          @pos = 0
        end

        def expand
          if @depth > MAX_DEPTH
            raise FormatError,
              root_error("parameter expansion exceeds maximum depth of #{MAX_DEPTH}")
          end
          while @pos < @value.length
            char = @value[@pos]

            if char == "\\" && @value[@pos + 1] == "$"
              @output << "$"
              @pos += 2
            elsif char == "$"
              expand_dollar
            else
              @output << char
              @pos += 1
            end
          end

          @output
        end

        private

        def expand_dollar
          next_char = @value[@pos + 1]

          if next_char == "{"
            expand_braced
          elsif (name = variable_name_at(@pos + 1))
            @pos += 1 + name.length
            @output << lookup(name)
          elsif next_char == "(" && @mode == :normal
            expand_command
          else
            @output << "$"
            @pos += 1
          end
        end

        def expand_braced
          name = variable_name_at(@pos + 2)
          if name.nil?
            raise FormatError, error_message(@pos, "missing variable name in parameter expansion")
          end

          operator_pos = @pos + 2 + name.length
          operator =
            if [":-", ":+", ":?"].include?(@value[operator_pos, 2])
              @value[operator_pos, 2]
            elsif ["-", "+", "?"].include?(@value[operator_pos, 1])
              @value[operator_pos, 1]
            end

          case operator
          when nil
            if @value[operator_pos] != "}"
              raise FormatError, error_message(@pos, "unclosed parameter expansion #{brace_preview}")
            end
            @pos = operator_pos + 1
            @output << lookup(name)
          when "-", ":-", "+", ":+", "?", ":?"
            word_start = operator_pos + operator.length
            word_end = find_word_end(word_start)
            word = @value[word_start...word_end]
            expansion_start = @pos
            @pos = word_end + 1
            @output << select_branch(name, operator, word, word_start, expansion_start)
          else
            raise FormatError,
              error_message(@pos, "unsupported parameter expansion operator #{operator.inspect}")
          end
        end

        # Find the matching closing brace, accounting for nested braces and
        # command substitutions. Escaped and quoted delimiters are ignored.
        def find_word_end(start)
          delimiter = balanced_end(start, "}", %w[brace paren])
          delimiter ||
            raise(FormatError, error_message(@pos, "unclosed parameter expansion #{brace_preview}"))
        end

        def select_branch(name, operator, word, word_start, expansion_start)
          set = variable_set?(name)
          value = set ? lookup(name) : nil
          use_word =
            case operator
            when "-" then !set
            when ":-" then !set || value.empty?
            when "+" then set
            when ":+" then set && !value.empty?
            when "?" then !set
            when ":?" then !set || value.empty?
            end

          if operator.include?("?")
            required_branch(name, value, word, word_start, expansion_start) if use_word
            value.to_s
          elsif use_word
            nested(word, word_start)
          else
            value.to_s
          end
        end

        def required_branch(name, value, word, word_start, expansion_start)
          message = if word.empty?
                      "#{name} is a required parameter but is #{value.nil? ? "not set" : "empty"}"
                    else
                      nested(word, word_start)
                    end
          raise FormatError, error_message(expansion_start, message)
        end

        def expand_command
          end_pos = find_command_end(@pos + 2)
          command = @value[@pos + 2...end_pos]
          command_start = @pos + 2
          @pos = end_pos + 1
          @output << run_command(command, command_start)
        end

        # Match the closing parenthesis while respecting nested braces and
        # command substitutions. The final command text (including any inner
        # $(...)) is handed to the shell unchanged.
        def find_command_end(start)
          delimiter = balanced_end(start, ")", %w[paren brace])
          delimiter || raise(FormatError, error_message(@pos, "unclosed command substitution"))
        end

        # Scan for the close delimiter using a nesting stack. `order` gives
        # the opener kind of the current nesting level and the other kind
        # allowed inside it.
        def balanced_end(start, close, order)
          stack = [order.first]
          index = start
          quote = nil

          while index < @value.length
            char = @value[index]

            if char == "\\"
              index += 2
              next
            end

            if quote
              quote = nil if char == quote
              index += 1
              next
            end

            if char == "'" || char == '"'
              quote = char
            elsif char == "$" && @value[index + 1] == "{"
              stack << "brace"
              index += 2
              next
            elsif char == "$" && @value[index + 1] == "("
              stack << "paren"
              index += 2
              next
            elsif (char == "}" && stack.last == "brace") ||
                  (char == ")" && stack.last == "paren")
              stack.pop
              return index if stack.empty? && char == close
            end

            index += 1
          end

          nil
        end

        def run_command(command, command_start)
          expanded = Variable.call(
            command,
            @hash,
            view: @view,
            source: @source,
            base_offset: absolute_offset(command_start),
            depth: @depth + 1,
            mode: :command,
            root_offset: @root_offset
          )
          `#{expanded}`.chomp
        end

        def nested(word, word_start)
          Variable.call(
            word,
            @hash,
            view: @view,
            source: @source,
            base_offset: absolute_offset(word_start),
            depth: @depth + 1,
            mode: @mode,
            root_offset: @root_offset
          )
        end

        def variable_name_at(index)
          match = @value.match(VARIABLE_NAME, index)
          return nil if match.nil? || match.begin(0) != index
          match[0]
        end

        def variable_set?(name)
          @hash.key?(name) || @view.key?(name)
        end

        def lookup(name)
          return @hash[name] if @hash.key?(name)
          @view.key?(name) ? @view[name] : ""
        end

        def absolute_offset(local)
          @base_offset + local
        end

        def error_message(offset, message)
          line, column = location(offset)
          "#{message} (line #{line}, column #{column})"
        end

        def root_error(message)
          line, column = root_location
          "#{message} (line #{line}, column #{column})"
        end

        def root_location
          prefix = @source[0, @root_offset]
          line = prefix.count("\n") + 1
          line_start = prefix.rindex("\n")&.+(1) || 0
          [line, @root_offset - line_start + 1]
        end

        def location(offset)
          absolute = absolute_offset(offset)
          prefix = @source[0, absolute]
          line = prefix.count("\n") + 1
          line_start = prefix.rindex("\n")&.+(1) || 0
          column = absolute - line_start + 1
          [line, column]
        end

        def brace_preview
          @value[@pos, [32, @value.length - @pos].min].inspect
        end
      end
    end
  end
end
