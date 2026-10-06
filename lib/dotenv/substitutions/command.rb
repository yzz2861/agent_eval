require "English"

module Dotenv
  module Substitutions
    # Substitute commands in a value, e.g. `SHA=$(git rev-parse HEAD)`.
    #
    # The per-load `policy` decides what happens to every substitution:
    #
    #   * +:shell+    - run through the system shell (historical behavior)
    #   * +:disabled+ - raise {Dotenv::CommandExecutionError}
    #   * +:literal+   - leave the +$(...)+ text untouched
    #   * any object responding to +call(command, env, source)+ - invoke it
    #
    # The same policy is applied at every nesting level, so a disabled or
    # literal substitution is never evaluated, not even to resolve a nested or
    # surrounding command. No policy ever falls back to the system shell.
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

        def call(value, env, policy: :shell, source: nil)
          value.gsub(INTERPOLATED_SHELL_COMMAND) do
            match = $LAST_MATCH_INFO
            command = match[:cmd][1..-2]

            if match[:backslash]
              # Escaped substitution: drop the backslash and leave the whole
              # expression, including nested commands, as a literal.
              match[0][1..]
            else
              evaluate(command, env, policy, source)
            end
          end
        end

        def evaluate(command, env, policy, source)
          case policy
          when :literal
            "$(#{command})"
          when :disabled
            error = CommandExecutionError.new("Command substitution is disabled")
            raise error.with_source(command, source)
          when :shell
            execute(CommandExecutors::Shell.new, command, env, policy, source)
          else
            unless policy.respond_to?(:call)
              raise ArgumentError,
                "Invalid value for command_substitution: #{policy.inspect}"
            end

            execute(policy, command, env, policy, source)
          end
        end

        # Resolve nested substitutions with the same policy before running the
        # command, then expand variables in the resulting command text.
        def execute(executor, command, env, policy, source)
          resolved = call(command, env, policy: policy, source: source)
          expanded = Variable.call(resolved, env)
          result = executor.call(expanded, env.dup.freeze, source)

          unless result.is_a?(String)
            raise CommandExecutionError.new(
              "Command executor must return a String, got #{result.class}"
            )
          end

          result
        rescue StandardError => e
          raise wrap_error(e, expanded || command, source)
        end

        def wrap_error(error, command, source)
          # Keep the innermost command/location that already has context.
          return error if error.is_a?(CommandExecutionError) && error.source

          message =
            if error.is_a?(CommandExecutionError)
              error.message
            else
              "Command executor failed: #{error.message}"
            end

          wrapped = CommandExecutionError.new(message).with_source(command, source)
          wrapped.set_backtrace(error.backtrace)
          wrapped
        end

        private :wrap_error, :evaluate, :execute
      end
    end
  end
end
