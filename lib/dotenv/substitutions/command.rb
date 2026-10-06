module Dotenv
  module Substitutions
    # Substitute shell commands in a value.
    #
    #   SHA=$(git rev-parse HEAD)
    #
    # Commands inside ${...} parameter expansions are left for
    # Substitutions::Variable, which only runs the branch it selects.
    module Command
      class << self
        def call(value, env)
          output = +""
          index = 0
          while index < value.length
            if escaped_command?(value, index)
              close = Variable.closing_paren(value, index + 2)
              if close && close > index + 3
                # Command is escaped, do not execute it, just drop the backslash.
                output << value[(index + 1)..close]
                index = close + 1
              else
                output << value[index]
                index += 1
              end
            elsif value[index] == "$" && value[index + 1] == "("
              close = Variable.closing_paren(value, index + 1)
              if close && close > index + 2
                command = value[(index + 2)...close]
                output << `#{Variable.call(command, env)}`.chomp
                index = close + 1
              else
                output << value[index]
                index += 1
              end
            elsif value[index] == "$" && value[index + 1] == "{"
              # Parameter expansion, handled by Substitutions::Variable.
              close = Variable.closing_brace(value, index + 1)
              if close
                output << value[index..close]
                index = close + 1
              else
                output << value[index]
                index += 1
              end
            else
              output << value[index]
              index += 1
            end
          end
          output
        end

        private

        def escaped_command?(value, index)
          value[index] == "\\" && value[index + 1] == "$" && value[index + 2] == "("
        end
      end
    end
  end
end
