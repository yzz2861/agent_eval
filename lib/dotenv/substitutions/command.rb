require "English"

module Dotenv
  module Substitutions
    # Substitute shell commands in a value.
    #
    #   SHA=$(git rev-parse HEAD)
    #
    module Command
      class << self
        INTERPOLATED_SHELL_COMMAND = /
          (?<backslash>\\)?   # is it escaped with a backslash?
          \$                  # literal $
          (?<cmd>             # collect command content for eval
            \(                # require opening paren
            (?:[^()]|\g<cmd>)+  # allow any number of non-parens, or balanced
                              # parens (by nesting the <cmd> expression
                              # recursively)
            \)                # require closing paren
          )
        /x

        def call(value, env, parent_env = ENV)
          # Process interpolated shell commands
          value.gsub(INTERPOLATED_SHELL_COMMAND) do |*|
            # Eliminate opening and closing parentheses
            command = $LAST_MATCH_INFO[:cmd][1..-2]

            if $LAST_MATCH_INFO[:backslash]
              # Command is escaped, don't replace it.
              $LAST_MATCH_INFO[0][1..]
            else
              # Execute the command with the same restricted environment view used by variable
              # substitution.
              command_env = parent_env.nil? ? env : parent_env.merge(env)
              expanded_command = Variable.call(command, command_env)
              IO.popen(command_env, expanded_command, unsetenv_others: true, &:read).chomp
            end
          end
        end
      end
    end
  end
end
