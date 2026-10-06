require "English"

module Dotenv
  module Substitutions
    # Substitute shell commands in a value.
    #
    #   SHA=$(git rev-parse HEAD)
    #
    module Command
      class << self
        # Sentinel placeholders for escaped parens, so they do not affect
        # balanced-paren matching while resolving nested commands.
        OPEN_PAREN = "\u0000DOTENV_LPAREN\u0000"
        CLOSE_PAREN = "\u0000DOTENV_RPAREN\u0000"

        INTERPOLATED_SHELL_COMMAND = /
          (?<backslash>\\)?                    # is it escaped with a backslash?
          \$                                   # literal $
          (?<cmd>                              # collect command content
            \(                                 # require opening paren
            (?:                               # non-parens, sentinel parens,
              [^()]                            # or balanced parens (nesting
              |#{Regexp.escape(OPEN_PAREN)}   # the <cmd> expression
              |#{Regexp.escape(CLOSE_PAREN)}  # recursively)
              |\g<cmd>
            )+
            \)                                 # require closing paren
          )
        /x

        # Protect `\(` and `\)` from backslash unescaping and paren matching.
        # Called by the parser before generic character unescaping.
        def protect_escaped_parens(value)
          value.gsub("\\(", OPEN_PAREN).gsub("\\)", CLOSE_PAREN)
        end

        # Restore parens protected by {.protect_escaped_parens}.
        def restore_parens(value)
          value.gsub(OPEN_PAREN, "(").gsub(CLOSE_PAREN, ")")
        end

        # Substitute commands in +value+ according to the per-load +policy+.
        #
        # @param value [String] value being expanded (escaped parens are sentinels)
        # @param env [Hash] variables parsed from the current file so far
        # @param policy [CommandPolicy] policy in effect for this load
        # @param location [CommandLocation] source location of the current line
        # @param view [Hash] read-only variables passed to caller executors
        def call(value, env, policy: CommandPolicy.default, location: nil, view: nil)
          # Historical behavior, retained for the :shell policy:
          # the system shell resolves nesting and escapes itself.
          return restore_parens(shell_substitute(value, env)) if policy.shell?

          restore_parens(substitute(value, policy, location, view || env))
        end

        private

        def shell_substitute(value, env)
          value.gsub(INTERPOLATED_SHELL_COMMAND) do |*|
            match = $LAST_MATCH_INFO

            if match[:backslash]
              # Command is escaped, don't replace it.
              match[0][1..]
            else
              # Eliminate opening and closing parentheses
              command = restore_parens(match[:cmd][1..-2])
              # Execute the command and return the value
              `#{Variable.call(command, env)}`.chomp
            end
          end
        end

        def substitute(value, policy, location, view)
          value.gsub(INTERPOLATED_SHELL_COMMAND) do |*|
            match = $LAST_MATCH_INFO

            if match[:backslash]
              # Command is escaped, don't replace it.
              match[0][1..]
            else
              # Eliminate opening and closing parentheses and resolve the
              # contents first so nested commands run inner-most first.
              command = restore_parens(substitute(match[:cmd][1..-2], policy, location, view))

              if policy.literal?
                "$(#{command})"
              elsif policy.disabled?
                raise CommandNotAllowedError,
                  "Command substitution is disabled#{location ? " at #{location}" : ""}: $(#{command})"
              else
                policy.execute(command, view, location)
              end
            end
          end
        end
      end
    end
  end
end
