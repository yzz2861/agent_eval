module Net
  module SSH
    module Connection
      # The structured result of a command executed remotely via
      # Net::SSH::Connection::Session#exec_capture. Unlike Session#exec!,
      # which concatenates all output into a single string, an ExecResult
      # keeps stdout and stderr separate and records exactly how the remote
      # command terminated, so callers can distinguish between:
      #
      # * the server refusing to run the command at all (#rejected?)
      # * the command exiting with a non-zero exit status
      # * the command being terminated by a signal (#signaled?)
      # * the channel closing before any exit information arrived
      #   (in which case the exit state is explicitly unknown)
      #
      #   result = ssh.exec_capture("make test")
      #   case result.status
      #   when :success  then puts result.stdout
      #   when :failed   then warn "exited with #{result.exit_status}"
      #   when :signaled then warn "killed by SIG#{result.exit_signal}"
      #   when :rejected then warn "server refused to run the command"
      #   else                warn "exit state unknown"
      #   end
      class ExecResult
        # The default maximum number of bytes collected per stream (stdout
        # and stderr are capped independently) when the caller does not
        # provide their own output sink. Output beyond the limit is
        # discarded and the result is flagged with #truncated?.
        DEFAULT_OUTPUT_LIMIT = 1024 * 1024

        # The command that was executed.
        attr_reader :command

        # Everything received on stdout (up to the output limit, unless a
        # custom sink was given).
        attr_reader :stdout

        # Everything received on stderr (up to the output limit, unless a
        # custom sink was given).
        attr_reader :stderr

        # The command's exit status (an Integer), or nil if the server did
        # not report one.
        attr_reader :exit_status

        # The name of the signal that terminated the command (e.g. "TERM",
        # without the "SIG" prefix), or nil if the command was not reported
        # as terminated by a signal.
        attr_reader :exit_signal

        def initialize(command) # :nodoc:
          @command = command
          @stdout = String.new
          @stderr = String.new
          @exit_status = nil
          @exit_signal = nil
          @rejected = false
          @truncated = false
        end

        # True if the server refused to execute the command (the channel
        # could not be opened, or the "exec" request itself failed). In
        # that case no exit information can ever exist.
        def rejected?
          @rejected
        end

        # True if the remote side reported how the command terminated
        # (via either an exit status or an exit signal) before the channel
        # was closed. When this is false, the command may or may not have
        # finished; treat the exit state as unknown rather than assuming
        # success or failure.
        def exit_known?
          !@exit_status.nil? || !@exit_signal.nil?
        end

        # True if the command was terminated by a signal.
        def signaled?
          !@exit_signal.nil?
        end

        # True if collected output was discarded because the output limit
        # was reached.
        def truncated?
          @truncated
        end

        # A symbolic summary of how the command ended:
        #
        # * :success  -- exit status 0
        # * :failed   -- non-zero exit status
        # * :signaled -- terminated by a signal (#exit_signal)
        # * :rejected -- the server refused to execute the command
        # * :unknown  -- the channel closed without any exit information
        def status
          return :rejected if rejected?
          return :unknown unless exit_known?
          return :signaled if signaled?

          @exit_status.zero? ? :success : :failed
        end

        # True only if the command ran and exited with status 0.
        def success?
          status == :success
        end

        # @private
        def reject!
          @rejected = true
        end

        # @private
        def record_exit_status(status)
          @exit_status = status
        end

        # @private
        def record_exit_signal(signal)
          @exit_signal = signal
        end

        # @private
        # Appends +data+ to the default buffer for +stream+ (:stdout or
        # :stderr), keeping at most +limit+ bytes per stream. Excess data
        # is dropped and the result is flagged as truncated.
        def append_output(stream, data, limit)
          buffer = (stream == :stderr ? @stderr : @stdout)
          remaining = limit - buffer.bytesize
          if remaining <= 0
            @truncated = true
          elsif data.bytesize > remaining
            buffer << data.byteslice(0, remaining)
            @truncated = true
          else
            buffer << data
          end
        end
      end
    end
  end
end
