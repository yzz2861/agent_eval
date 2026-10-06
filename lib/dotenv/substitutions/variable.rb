module Dotenv
  module Substitutions
    # Substitute variables in a value.
    #
    #   HOST=example.com
    #   URL="https://$HOST"
    #
    # Shell-style parameter expansion is supported inside braces:
    #
    #   ${VAR:-default}  # default when VAR is unset or empty
    #   ${VAR-default}   # default only when VAR is unset (empty string is kept)
    #   ${VAR:+alt}      # alt when VAR is set and not empty
    #   ${VAR+alt}       # alt when VAR is set (even when empty)
    #   ${VAR:?message}  # raise when VAR is unset or empty
    #   ${VAR?message}   # raise when VAR is unset
    #
    # Defaults and alternates may reference other variables and are only
    # expanded (including any command substitutions) when their branch is
    # actually selected.
    #
    module Variable
      # Raised when a required variable (${VAR?message} or ${VAR:?message})
      # is missing.
      class MissingVariableError < StandardError; end

      # Raised when nested parameter expansion exceeds MAX_DEPTH.
      class ExpansionDepthError < StandardError; end

      # Maximum nesting depth for parameter expansions like ${A:-${B:-...}}.
      MAX_DEPTH = 10

      VARIABLE_NAME = /[A-Za-z0-9_]/

      EXPRESSION = /
        \A
        (?<name>[A-Za-z0-9_]+)
        (?:(?<colon>:)?(?<operator>[-+?])(?<word>.*))?
        \z
      /mx

      class << self
        def call(value, env)
          expand(value, env, 0, 0, value)
        end

        # Index of the ")" closing the "(" at +open_index+, or nil when the
        # parentheses are unbalanced.
        def closing_paren(value, open_index)
          depth = 0
          (open_index...value.length).each do |index|
            case value[index]
            when "(" then depth += 1
            when ")"
              depth -= 1
              return index if depth.zero?
            end
          end
          nil
        end

        # Index of the "}" closing the "${" at +open_index+, or nil when the
        # braces are unbalanced. Nested expansions and command substitutions
        # are skipped over so their braces are not miscounted.
        def closing_brace(value, open_index)
          depth = 1
          index = open_index + 1
          while index < value.length
            if value[index] == "\\" && value[index + 1] == "$"
              index += 2
            elsif value[index] == "$" && value[index + 1] == "{"
              depth += 1
              index += 2
            elsif value[index] == "$" && value[index + 1] == "("
              close = closing_paren(value, index + 1)
              return nil unless close

              index = close + 1
            elsif value[index] == "}"
              depth -= 1
              return index if depth.zero?

              index += 1
            else
              index += 1
            end
          end
          nil
        end

        private

        def expand(value, env, depth, offset, source)
          if depth > MAX_DEPTH
            raise ExpansionDepthError,
              "variable expansion is nested deeper than #{MAX_DEPTH} levels " \
              "at offset #{offset} of #{source.inspect}"
          end

          output = +""
          index = 0
          while index < value.length
            if value[index] == "\\" && value[index + 1] == "$" && value[index + 2] != "("
              # Escaped variable, keep it literal (Command handles "\$(").
              output << "$"
              index += 2
            elsif value[index] == "$" && value[index + 1] == "{"
              close = closing_brace(value, index + 1)
              if close
                output << evaluate(value[(index + 2)...close], env, depth, offset + index, source)
                index = close + 1
              else
                index = expand_unclosed_brace(value, index, output, env)
              end
            elsif value[index] == "$" && value[index + 1] == "("
              # Command substitution, left for Substitutions::Command.
              close = closing_paren(value, index + 1)
              if close
                output << value[index..close]
                index = close + 1
              else
                output << value[index]
                index += 1
              end
            elsif value[index] == "$" && VARIABLE_NAME.match?(value[index + 1].to_s)
              name = value[(index + 1)..][/\A[A-Za-z0-9_]+/]
              output << lookup(name, env).last.to_s
              index += 1 + name.length
            else
              output << value[index]
              index += 1
            end
          end
          output
        end

        # Preserve the historical behavior of expanding an unclosed "${NAME"
        # like "$NAME".
        def expand_unclosed_brace(value, index, output, env)
          name = value[(index + 2)..][/\A[A-Za-z0-9_]+/]
          if name
            output << lookup(name, env).last.to_s
            index + 2 + name.length
          else
            output << "${"
            index + 2
          end
        end

        def evaluate(expression, env, depth, position, source)
          match = EXPRESSION.match(expression)
          return legacy_expression(expression, env) unless match

          operator = match[:operator]
          word = match[:word]
          defined, value = lookup(match[:name], env)
          applicable = match[:colon] ? defined && !value.to_s.empty? : defined
          word_offset = position + 2 + (expression.length - word.to_s.length)

          case operator
          when nil
            value.to_s
          when "-"
            applicable ? value.to_s : expand_word(word, env, depth, word_offset, source)
          when "+"
            applicable ? expand_word(word, env, depth, word_offset, source) : ""
          when "?"
            unless applicable
              raise MissingVariableError,
                missing_message(match[:name], match[:colon], word, env, depth, word_offset, source)
            end
            value.to_s
          end
        end

        # Expand the selected branch of a parameter expansion. Command
        # substitutions run only now, so commands in branches that were not
        # selected are never executed.
        def expand_word(word, env, depth, offset, source)
          expanded = expand(word, env, depth + 1, offset, source)
          defined?(Command) ? Command.call(expanded, env) : expanded
        end

        def missing_message(name, colon, word, env, depth, offset, source)
          if word.nil? || word.empty?
            colon ? "#{name}: parameter not set or empty" : "#{name}: parameter not set"
          else
            "#{name}: #{expand_word(word, env, depth, offset, source)}"
          end
        end

        # Not a parameter expression. Preserve the historical behavior of
        # expanding a leading name and leaving the remainder untouched.
        def legacy_expression(expression, env)
          if (name = expression[/\A[A-Za-z0-9_]+/])
            "#{lookup(name, env).last}#{expression[name.length..]}}"
          else
            "${#{expression}}"
          end
        end

        # Returns [defined, value] for a variable in the given environment
        # view, falling back to the process environment.
        def lookup(name, env)
          if env.key?(name)
            [true, env[name]]
          elsif ENV.key?(name)
            [true, ENV[name]]
          else
            [false, nil]
          end
        end
      end
    end
  end
end
