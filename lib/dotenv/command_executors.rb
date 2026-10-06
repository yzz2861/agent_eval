require "open3"

module Dotenv
  module CommandExecutors
    # Default executor: runs the command through the system shell.
    #
    # This preserves dotenv's historical `$(...)` behavior. It is only used
    # when a caller explicitly leaves the default untouched; no other policy
    # ever falls back to it.
    class Shell
      def call(command, _env, _source)
        stdout, status = Open3.capture2(command)

        unless status.success?
          raise Dotenv::CommandExecutionError.new(
            "Command failed with exit status #{status.exitstatus}",
            command: command
          )
        end

        stdout.chomp
      end
    end
  end
end
