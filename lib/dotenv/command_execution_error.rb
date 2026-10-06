module Dotenv
  # Raised when a command substitution is disallowed or an executor fails.
  #
  # Parsing a file always fails atomically: when this error is raised, no key
  # from the file (or the current load) is written to `ENV`.
  class CommandExecutionError < StandardError
    attr_reader :command, :source

    def initialize(message = nil, command: nil, source: nil)
      super(message)
      @command = command
      @source = source
    end

    # Return a copy annotated with the failing command and its source location.
    # The first (innermost) location wins so nested failures stay actionable.
    def with_source(command, source)
      return self if @annotated
      annotated = exception(
        "#{message} (for command #{command.inspect} at #{source || "<unknown source>"})"
      )
      annotated.set_command_and_source(@command || command, @source || source)
      annotated
    end

    def set_command_and_source(command, source)
      @command = command
      @source = source
      @annotated = true
    end
  end
end
