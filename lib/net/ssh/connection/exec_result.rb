module Net
  module SSH
    module Connection
      # The default output sink used by Session#exec_capture. It collects
      # command output into an in-memory string, retaining at most +limit+
      # bytes. Once the limit has been reached, any additional data is
      # discarded (but counted, see #dropped_bytes) and the collector is
      # marked as truncated. This keeps automated tasks from buffering
      # unbounded amounts of remote output.
      class OutputCollector
        # The default maximum number of bytes retained per stream (1 MiB).
        DEFAULT_LIMIT = 1024 * 1024

        # The maximum number of bytes this collector retains.
        attr_reader :limit

        # The number of bytes that had to be discarded because the limit
        # had already been reached.
        attr_reader :dropped_bytes

        def initialize(limit = DEFAULT_LIMIT)
          unless limit.is_a?(Integer) && limit >= 0
            raise ArgumentError, "limit must be a non-negative integer"
          end

          @limit = limit
          @buffer = String.new
          @dropped_bytes = 0
        end

        # Appends +data+ to the collected output, retaining at most #limit
        # bytes in total. Aliased as #<< and #call so a collector can be used
        # directly as an output sink. Returns self.
        def append(data)
          data = data.to_s
          remaining = @limit - @buffer.bytesize

          if data.bytesize <= remaining
            @buffer << data
          else
            @buffer << data.byteslice(0, remaining) if remaining > 0
            @dropped_bytes += data.bytesize - remaining
          end

          self
        end
        alias << append
        alias call append

        # The collected output, as a (possibly truncated) string.
        def to_s
          @buffer
        end

        def bytesize
          @buffer.bytesize
        end

        def empty?
          @buffer.empty?
        end

        # True when data had to be discarded because #limit was reached.
        def truncated?
          @dropped_bytes > 0
        end
      end

      # The structured outcome of a command executed via
      # Session#exec_capture. Unlike Session#exec!, which concatenates
      # everything into a single string, an ExecResult keeps stdout and
      # stderr separate and exposes the full exit information of the remote
      # process: its exit status, the signal that terminated it (if any), or
      # an explicit "unknown" state when the server closed the channel
      # without reporting either.
      #
      # Instances are filled in as protocol events arrive. A result is only
      # #complete? once the channel has been fully closed; the arrival of
      # EOF, exit-status, or exit-signal (in any order) is not, by itself,
      # enough to consider the command finished.
      class ExecResult
        # The command that was executed.
        attr_reader :command

        # The exit status reported by the remote process, or nil if none
        # was received (see #exit_known?).
        attr_reader :exit_status

        # The name of the signal that terminated the remote process
        # (e.g. "TERM"), or nil if none was received.
        attr_reader :exit_signal

        # The sinks receiving stdout and stderr data. These are
        # OutputCollector instances unless custom sinks were passed to
        # Session#exec_capture.
        attr_reader :stdout_sink, :stderr_sink

        def initialize(command, stdout_sink, stderr_sink)
          @command = command
          @stdout_sink = stdout_sink
          @stderr_sink = stderr_sink
          @exit_status = nil
          @exit_signal = nil
          @exit_known = false
          @exec_rejected = false
          @eof = false
          @closed = false
        end

        # The captured stdout, as a string, when the default collecting
        # sink is used. Returns nil when a custom sink was given to
        # Session#exec_capture (the output went to that sink instead).
        def stdout
          @stdout_sink.is_a?(OutputCollector) ? @stdout_sink.to_s : nil
        end

        # The captured stderr, as a string, when the default collecting
        # sink is used. Returns nil when a custom sink was given to
        # Session#exec_capture (the output went to that sink instead).
        def stderr
          @stderr_sink.is_a?(OutputCollector) ? @stderr_sink.to_s : nil
        end

        # True when stdout had to be truncated because the capture limit
        # was reached. Always false for custom sinks.
        def stdout_truncated?
          @stdout_sink.respond_to?(:truncated?) && @stdout_sink.truncated?
        end

        # True when stderr had to be truncated because the capture limit
        # was reached. Always false for custom sinks.
        def stderr_truncated?
          @stderr_sink.respond_to?(:truncated?) && @stderr_sink.truncated?
        end

        # True when the server refused to execute the command (the "exec"
        # channel request failed or the channel could not be opened).
        def exec_rejected?
          @exec_rejected
        end

        # True once the remote end has sent EOF, meaning no more output
        # will arrive. Note that EOF does not complete the command: exit
        # information and further channel traffic may still follow.
        def eof?
          @eof
        end

        # True only once the channel has been fully closed. This is the
        # sole completion signal; EOF or exit information arriving earlier
        # (in any order) does not mark the result complete.
        def complete?
          @closed
        end

        # True when the server reported how the remote process terminated,
        # either via an exit status or via an exit signal. When this is
        # false, both #exit_status and #exit_signal are nil and the fate of
        # the remote process is explicitly unknown.
        def exit_known?
          @exit_known
        end

        # True when the command was accepted by the server, ran to
        # completion, and reported a zero exit status.
        def success?
          !@exec_rejected && @exit_known && @exit_signal.nil? && @exit_status == 0
        end

        # The following methods are invoked by Session#exec_capture as the
        # corresponding protocol events arrive; they are part of the
        # internal wiring rather than the public reporting interface.

        def receive_stdout(data) # :nodoc:
          deliver(@stdout_sink, data)
        end

        def receive_stderr(data) # :nodoc:
          deliver(@stderr_sink, data)
        end

        def receive_exit_status(status) # :nodoc:
          @exit_status = status
          @exit_known = true
        end

        def receive_exit_signal(signal) # :nodoc:
          @exit_signal = signal
          @exit_known = true
        end

        def receive_eof # :nodoc:
          @eof = true
        end

        def receive_close # :nodoc:
          @closed = true
        end

        def exec_rejected! # :nodoc:
          @exec_rejected = true
        end

        private

        def deliver(sink, data)
          if sink.respond_to?(:call)
            sink.call(data)
          else
            sink << data
          end
        end
      end
    end
  end
end
